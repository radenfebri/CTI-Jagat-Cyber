<?php

namespace App\Jobs;

use App\Domain\Assets\DiscoveredAsset;
use App\Domain\Scanning\PythonScannerClient;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Collection;

class EnrichAssetWithPython implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

    public int $timeout = 90;

    public int $tries = 3;

    public int $uniqueFor = 3600;

    public function __construct(public string $assetId)
    {
        $this->onQueue('cti');
    }

    public function uniqueId(): string
    {
        return $this->assetId;
    }

    public function backoff(): array
    {
        return [30, 120];
    }

    public function handle(PythonScannerClient $scanner): void
    {
        if (! $scanner->enabled()) {
            return;
        }

        $asset = DiscoveredAsset::query()->with('monitoredDomain')->find($this->assetId);
        $domain = $asset?->monitoredDomain;
        if ($asset === null || $domain === null || $asset->record_type !== 'SUBDOMAIN'
            || $asset->retired_at !== null || $asset->hidden_at !== null || $domain->verified_at === null) {
            return;
        }

        $observation = $domain->webObservations()->where('hostname', $asset->value)->first();
        if ($observation === null) {
            return;
        }

        try {
            $payload = $scanner->fingerprint($asset->value, $domain->hostname);
        } catch (ConnectionException) {
            if ((bool) config('cve.enabled')) {
                MapAssetCves::dispatch($observation->id)->afterCommit();
            }

            return;
        }
        $technologies = $this->mergeTechnologies($observation->technologies ?? [], $payload['technologies'] ?? []);

        $observation->forceFill([
            'scheme' => $payload['scheme'] ?? $observation->scheme,
            'status_code' => $payload['status_code'] ?? $observation->status_code,
            'server_header' => $payload['server_header'] ?? $observation->server_header,
            'technologies' => $technologies,
        ])->save();

        if ((bool) config('cve.enabled')) {
            MapAssetCves::dispatch($observation->id)->afterCommit();
        }
    }

    /** @param array<int, mixed> $existing @param array<int, mixed> $incoming @return array<int, array<string, mixed>> */
    private function mergeTechnologies(array $existing, mixed $incoming): array
    {
        $incomingFacts = collect(is_array($incoming) ? $incoming : []);
        $incomingNames = $incomingFacts->filter(fn (mixed $technology): bool => is_array($technology))
            ->pluck('name')->filter()->map(fn (mixed $name): string => mb_strtolower((string) $name));
        $legacyFrameworks = ['react', 'vue', 'vue.js', 'angular'];
        $existingFacts = collect($existing)->reject(function (mixed $technology) use ($incomingNames, $legacyFrameworks): bool {
            if (! is_array($technology)) {
                return false;
            }
            $category = mb_strtolower((string) ($technology['category'] ?? ''));
            if (filled($technology['version'] ?? null) || ($category !== '' && $category !== 'other')) {
                return false;
            }

            $name = mb_strtolower((string) ($technology['name'] ?? ''));

            return in_array($name, $legacyFrameworks, true) && ! $incomingNames->contains($name);
        });

        $facts = $existingFacts->merge($incomingFacts)->values()
            ->filter(fn (mixed $technology): bool => is_array($technology) && filled($technology['name'] ?? null))
            ->map(function (array $technology, int $index): array {
                $version = filled($technology['version'] ?? null) ? mb_substr(trim((string) $technology['version']), 0, 80) : null;
                $category = filled($technology['category'] ?? null) ? mb_substr(trim((string) $technology['category']), 0, 80) : 'Other';

                return [
                    'name' => mb_substr(trim((string) $technology['name']), 0, 120),
                    'version' => $version,
                    'source' => mb_substr(trim((string) ($technology['source'] ?? 'fingerprint')), 0, 40),
                    'category' => $category,
                    '_score' => ($version ? 4 : 0) + ($category !== 'Other' ? 2 : 0) + ($index / 10000),
                ];
            });

        return $facts->groupBy(fn (array $technology): string => mb_strtolower($technology['name']))
            ->map(fn (Collection $versions): array => $versions->sortByDesc('_score')->first())
            ->map(function (array $technology): array {
                unset($technology['_score']);

                return $technology;
            })->values()->all();
    }
}
