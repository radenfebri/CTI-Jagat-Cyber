<?php

namespace App\Jobs;

use App\Domain\Assets\DomainName;
use App\Domain\Assets\DomainProof;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\PublicTlsEndpoint;
use App\Domain\Assets\WebProbe;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\DB;
use RuntimeException;

class ProbeWebInventory implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

    public int $timeout = 45;

    public int $tries = 1;

    public int $uniqueFor = 600;

    public function __construct(public string $domainId, public string $authorizationId)
    {
        $this->onQueue('cti');
    }

    public function uniqueId(): string
    {
        return $this->domainId;
    }

    public function handle(DomainProof $proof, PublicTlsEndpoint $dns, WebProbe $probe): void
    {
        $domain = $this->scope()->first();
        if ($domain === null) {
            return;
        }

        $hostname = $this->nextHostname($domain);
        if ($hostname === null) {
            $this->scope()->update(['web_next_run_at' => now()->addHour()]);

            return;
        }

        try {
            $verified = $proof->matches($domain);
        } catch (RuntimeException) {
            $verified = false;
        }
        if (! $verified) {
            $this->scope()->update(['web_next_run_at' => now()->addMinutes(10)]);

            return;
        }

        $ip = null;
        $result = null;
        if (DomainName::normalize($hostname) === $hostname
            && ($hostname === $domain->hostname || str_ends_with($hostname, '.'.$domain->hostname))) {
            try {
                $ip = $dns->resolve($hostname);
            } catch (RuntimeException) {
                // Record that the endpoint could not be resolved on this pass.
            }
            if ($ip !== null && $this->scope()->exists()) {
                $result = $probe->inspect($hostname, $ip);
            }
        }

        $stored = DB::transaction(function () use ($hostname, $ip, $result): ?array {
            $current = $this->scope()->lockForUpdate()->first();
            if ($current === null) {
                return null;
            }

            $current->webObservations()->updateOrCreate(['hostname' => $hostname], [
                'authorization_id' => $this->authorizationId,
                'public_ip' => $ip,
                'scheme' => $result['scheme'] ?? null,
                'status_code' => $result['status_code'] ?? null,
                'server_header' => $result['server_header'] ?? null,
                'technologies' => $result['technologies'] ?? null,
                'checked_at' => now(),
            ]);
            $current->forceFill(['web_next_run_at' => now()])->save();

            return [
                'asset_id' => $current->assets()->where('record_type', 'SUBDOMAIN')->where('value', $hostname)->value('id'),
                'observation_id' => $current->webObservations()->where('hostname', $hostname)->value('id'),
            ];
        });

        if ($stored !== null && $stored['asset_id'] !== null && (bool) config('cti.python_worker.enabled')) {
            EnrichAssetWithPython::dispatch($stored['asset_id'])->afterCommit();
        } elseif ($stored !== null && $stored['observation_id'] !== null && (bool) config('cve.enabled')) {
            MapAssetCves::dispatch($stored['observation_id'])->afterCommit();
        }
    }

    private function scope(): Builder
    {
        return MonitoredDomain::eligible()->whereKey($this->domainId)->whereNotNull('verified_at')
            ->where('web_authorization_id', $this->authorizationId);
    }

    private function nextHostname(MonitoredDomain $domain): ?string
    {
        $cutoff = now()->subDay();
        if (! $domain->webObservations()->where('hostname', $domain->hostname)
            ->where('authorization_id', $this->authorizationId)->where('checked_at', '>', $cutoff)->exists()) {
            return $domain->hostname;
        }

        return $domain->assets()->where('record_type', 'SUBDOMAIN')->whereNull('hidden_at')->whereNull('retired_at')
            ->leftJoin('web_observations', function ($join): void {
                $join->on('web_observations.monitored_domain_id', '=', 'discovered_assets.monitored_domain_id')
                    ->on('web_observations.hostname', '=', 'discovered_assets.value')
                    ->where('web_observations.authorization_id', $this->authorizationId);
            })
            ->where(function (Builder $query) use ($cutoff): void {
                $query->whereNull('web_observations.checked_at')->orWhere('web_observations.checked_at', '<=', $cutoff);
            })
            ->orderByRaw('CASE WHEN web_observations.checked_at IS NULL THEN 0 ELSE 1 END')
            ->orderBy('web_observations.checked_at')->orderBy('discovered_assets.value')
            ->value('discovered_assets.value');
    }
}
