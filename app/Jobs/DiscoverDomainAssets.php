<?php

namespace App\Jobs;

use App\Domain\Assets\CertificateTransparency;
use App\Domain\Assets\CloudflareZoneInventory;
use App\Domain\Assets\DomainProof;
use App\Domain\Assets\DomainScanPolicy;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\PassiveDnsDiscovery;
use App\Domain\Assets\PassiveInventory;
use App\Domain\Tenancy\Organization;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Http\Client\ConnectionException;
use Illuminate\Queue\Middleware\WithoutOverlapping;
use Illuminate\Support\Facades\DB;
use JsonException;
use RuntimeException;

class DiscoverDomainAssets implements ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public int $timeout = 45;

    public array $backoff = [30, 120];

    public bool $forceZone = false;

    public function __construct(
        public string $organizationId,
        public string $domainId,
        public string $authorizationId,
        public string $runId,
        bool $forceZone = false,
    ) {
        $this->forceZone = $forceZone;
        $this->onQueue('cti');
    }

    public function middleware(): array
    {
        return [(new WithoutOverlapping($this->domainId))->releaseAfter(30)->expireAfter(180)];
    }

    public function handle(DomainProof $proof, PassiveDnsDiscovery $discovery, CertificateTransparency $ct, PassiveInventory $inventory, CloudflareZoneInventory $zone): void
    {
        $domain = MonitoredDomain::eligible()->whereKey($this->domainId)
            ->where('organization_id', $this->organizationId)->whereNotNull('verified_at')->first();

        if ($domain === null || ! $this->activeRun()->exists()) {
            $this->finish('skipped');

            return;
        }

        $this->activeRun()->update(['last_status' => 'running']);
        $matched = $proof->matches($domain);
        $observations = $matched ? $discovery->observe($domain->hostname) : [];
        $ctPage = null;
        $ctAttempted = $matched && $domain->ct_authorization_id !== null
            && MonitoredDomain::eligible()->whereKey($domain->id)->where('ct_authorization_id', $domain->ct_authorization_id)->exists()
            && $this->activeRun()->exists();

        if ($ctAttempted) {
            try {
                $ctPage = $ct->nextPage($domain->hostname, $domain->ct_cursor);
            } catch (ConnectionException|JsonException|RuntimeException) {
                // CT failure must not discard a successful DNS observation.
            }
        }

        $zoneNames = null;
        $zoneAttempted = $matched && $zone->configuredFor($domain) && $this->activeRun()->exists()
            && ($this->forceZone || $domain->zone_checked_at === null
                || $domain->zone_checked_at->lte(now()->subHours(config('cti.passive_interval_hours'))));
        if ($zoneAttempted) {
            try {
                $zoneNames = $zone->read($domain);
            } catch (ConnectionException|RuntimeException) {
                // An incomplete list must not retire existing zone observations.
            }
        }

        DB::transaction(function () use ($domain, $matched, $observations, $ctAttempted, $ctPage, $inventory, $zoneAttempted, $zoneNames): void {
            $organization = Organization::query()->lockForUpdate()->find($this->organizationId);
            $current = MonitoredDomain::query()->where('organization_id', $this->organizationId)
                ->lockForUpdate()->find($this->domainId);
            $run = $this->activeRun()->lockForUpdate()->first();

            if ($run === null) {
                return;
            }

            if (! $organization?->allowsDiscovery() || $current?->verified_at === null
                || ! hash_equals($current->verification_token, $domain->verification_token)) {
                $this->finish('skipped');

                return;
            }

            if (! $matched) {
                $current->invalidateOwnership();

                return;
            }

            $inventory->syncSnapshot($current, PassiveDnsDiscovery::SOURCE, $observations);

            if ($zoneAttempted) {
                $current->forceFill(['zone_checked_at' => now(), 'zone_status' => $zoneNames === null ? 'unavailable' : 'complete'])->save();
                if ($zoneNames !== null) {
                    $inventory->recordHostnames($current, $zoneNames, CloudflareZoneInventory::SOURCE, complete: true);
                }
            }

            if ($ctAttempted && $current->ct_authorization_id === $domain->ct_authorization_id) {
                $hasMore = $ctPage !== null && $ctPage['cursor'] !== $domain->ct_cursor;
                $current->forceFill([
                    'ct_checked_at' => now(),
                    'ct_status' => $ctPage === null ? 'unavailable' : ($hasMore ? 'page_saved' : 'complete'),
                    'ct_cursor' => $ctPage['cursor'] ?? $current->ct_cursor,
                ])->save();

                $inventory->recordHostnames($current, $ctPage['hosts'] ?? [], CertificateTransparency::SOURCE);
                $continuation = now()->addMinutes(config('cti.ct_page_interval_minutes'));
                if ($hasMore && ($run->next_run_at === null || $run->next_run_at->gt($continuation))) {
                    $run->next_run_at = $continuation;
                }
            }
            $run->update(['last_status' => 'completed', 'last_finished_at' => now(), 'last_success_at' => now()]);
        });
    }

    public function failed(): void
    {
        $this->finish('failed');
    }

    private function activeRun(): Builder
    {
        return DomainScanPolicy::query()->whereKey($this->domainId)
            ->where('authorization_id', $this->authorizationId)
            ->where('run_id', $this->runId)
            ->whereNull('revoked_at')
            ->whereNotNull('approved_by')
            ->whereIn('last_status', ['queued', 'running'])
            ->whereHas('monitoredDomain', fn (Builder $domain) => $domain->where('organization_id', $this->organizationId));
    }

    private function finish(string $status): void
    {
        $this->activeRun()->update(['last_status' => $status, 'last_finished_at' => now()]);
    }
}
