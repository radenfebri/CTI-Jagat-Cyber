<?php

namespace App\Jobs;

use App\Domain\Assets\DiscoveredAsset;
use App\Domain\Scanning\PythonScannerClient;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Http\Client\ConnectionException;

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
        $facts = collect($existing)->merge(is_array($incoming) ? $incoming : [])->filter(
            fn (mixed $technology): bool => is_array($technology) && filled($technology['name'] ?? null),
        );

        return $facts->unique(fn (array $technology): string => mb_strtolower(
            (string) ($technology['name'] ?? '').'|'.(string) ($technology['version'] ?? ''),
        ))->values()->all();
    }
}
