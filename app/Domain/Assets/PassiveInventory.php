<?php

namespace App\Domain\Assets;

use DateTimeInterface;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Support\Collection;
use Illuminate\Support\Str;

final class PassiveInventory
{
    /** @param list<array{record_type: string, value: string, source: string}> $observations */
    public function syncSnapshot(MonitoredDomain $domain, string $source, array $observations): void
    {
        $timestamp = now();
        $known = $domain->assets()->where('source', $source)
            ->where(fn (Builder $query) => $query->whereNull('retired_at')->orWhereIn('value', array_column($observations, 'value')))
            ->get()
            ->keyBy(fn (DiscoveredAsset $asset) => $this->key($asset->record_type, $asset->value));

        $this->save($domain, $observations, $known, $timestamp);

        $seen = array_fill_keys(array_map(
            fn (array $observation): string => $this->key($observation['record_type'], $observation['value']),
            $observations,
        ), true);

        $missing = $known->filter(fn (DiscoveredAsset $asset, string $key): bool => $asset->retired_at === null && ! isset($seen[$key]));
        foreach ($missing->chunk(100) as $batch) {
            $domain->assets()->whereKey($batch->pluck('id')->all())->update(['retired_at' => $timestamp]);

            AssetObservationChange::insert($batch->map(fn (DiscoveredAsset $asset): array => [
                'discovered_asset_id' => $asset->id, 'event' => 'removed', 'occurred_at' => $timestamp,
            ])->values()->all());
        }
    }

    /** @param list<string> $hostnames */
    public function recordHostnames(MonitoredDomain $domain, array $hostnames, string $source, bool $complete = false): void
    {
        $observations = array_map(fn (string $hostname): array => [
            'record_type' => 'SUBDOMAIN', 'value' => $hostname, 'source' => $source,
        ], $hostnames);
        if ($complete) {
            $this->syncSnapshot($domain, $source, $observations);

            return;
        }

        $timestamp = now();

        foreach (array_chunk($observations, 100) as $batch) {
            $known = $domain->assets()->where('source', $source)
                ->where('record_type', 'SUBDOMAIN')->whereIn('value', array_column($batch, 'value'))->get()
                ->keyBy(fn (DiscoveredAsset $asset) => $this->key($asset->record_type, $asset->value));

            $this->save($domain, $batch, $known, $timestamp);
        }
    }

    /**
     * The caller holds the monitored-domain lock until observations and changes commit.
     *
     * @param  list<array{record_type: string, value: string, source: string}>  $observations
     * @param  Collection<string, DiscoveredAsset>  $known
     */
    private function save(MonitoredDomain $domain, array $observations, Collection $known, DateTimeInterface $timestamp): void
    {
        foreach (array_chunk($observations, 100) as $batch) {
            $rows = [];
            $changes = [];
            $subdomainAdded = false;

            foreach ($batch as $observation) {
                $previous = $known->get($this->key($observation['record_type'], $observation['value']));
                $id = $previous?->id ?? (string) Str::uuid();

                $rows[] = $observation + [
                    'id' => $id,
                    'monitored_domain_id' => $domain->id,
                    'first_seen_at' => $timestamp,
                    'last_seen_at' => $timestamp,
                    'retired_at' => null,
                ];

                if ($previous === null || $previous->retired_at !== null) {
                    $subdomainAdded = $subdomainAdded || ($observation['record_type'] === 'SUBDOMAIN' && $previous?->hidden_at === null);
                    $changes[] = [
                        'discovered_asset_id' => $id,
                        'event' => $previous === null ? 'added' : 'returned',
                        'occurred_at' => $timestamp,
                    ];
                }
            }

            DiscoveredAsset::upsert($rows, ['monitored_domain_id', 'record_type', 'value', 'source'], ['last_seen_at', 'retired_at']);

            if ($changes !== []) {
                AssetObservationChange::insert($changes);
            }
            if ($subdomainAdded && $domain->web_authorization_id !== null && $domain->web_next_run_at?->gt($timestamp)) {
                $domain->forceFill(['web_next_run_at' => $timestamp])->save();
            }
        }
    }

    private function key(string $type, string $value): string
    {
        return $type.':'.$value;
    }
}
