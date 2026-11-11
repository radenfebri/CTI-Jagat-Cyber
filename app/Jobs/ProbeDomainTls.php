<?php

namespace App\Jobs;

use App\Domain\Assets\DomainProof;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\ObservedNetwork;
use App\Domain\Assets\PassiveDnsDiscovery;
use App\Domain\Assets\PublicTlsEndpoint;
use App\Domain\Assets\TlsCheck;
use App\Domain\Assets\TlsProbe;
use App\Domain\Identity\Membership;
use App\Domain\Tenancy\Organization;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Support\Facades\DB;
use RuntimeException;

class ProbeDomainTls implements ShouldQueue
{
    use Queueable;

    public int $tries = 1;

    public int $timeout = 45;

    public function __construct(public string $organizationId, public string $domainId, public string $checkId)
    {
        $this->onQueue('cti');
    }

    public function handle(DomainProof $proof, PassiveDnsDiscovery $dns, PublicTlsEndpoint $endpoint, TlsProbe $probe): void
    {
        $check = $this->checkQuery()->where('status', 'queued')->first();
        if ($check === null) {
            return;
        }

        $domain = $this->eligibleDomain($check);
        if ($domain === null || $check->created_at->lte(now()->subMinutes(10))) {
            $this->finish('skipped', 'scope_or_queue_expired');

            return;
        }

        if ($this->checkQuery()->where('status', 'queued')->update(['status' => 'running', 'started_at' => now()]) !== 1) {
            return;
        }

        if (! $proof->matches($domain)) {
            DB::transaction(function () use ($domain): void {
                $current = MonitoredDomain::query()->where('organization_id', $this->organizationId)
                    ->lockForUpdate()->find($this->domainId);
                if ($current?->verified_at !== null && hash_equals($current->verification_token, $domain->verification_token)) {
                    $current->invalidateOwnership();
                }
                $this->finish('skipped', 'dns_proof_missing');
            });

            return;
        }

        try {
            $address = $check->scope === TlsCheck::PUBLIC_ENDPOINT
                ? $endpoint->resolve($domain->hostname)
                : $this->resolveDirectAddress($dns, $domain, $check);
        } catch (RuntimeException) {
            $this->finish('failed', 'dns_lookup_failed');

            return;
        }

        if ($address === null) {
            $this->finish('skipped', $check->scope === TlsCheck::PUBLIC_ENDPOINT ? 'dns_public_endpoint_missing' : 'dns_ip_mismatch');

            return;
        }

        if ($this->eligibleDomain($check) === null || ! $this->checkQuery()->where('status', 'running')->exists()) {
            $this->finish('skipped', 'scope_or_queue_expired');

            return;
        }

        if ($check->scope === TlsCheck::PUBLIC_ENDPOINT
            && $this->checkQuery()->where('status', 'running')->update(['ip_address' => $address]) !== 1) {
            return;
        }

        try {
            $result = $probe->inspect($domain->hostname, $address);
        } catch (RuntimeException) {
            $this->finish('failed', 'tls_handshake_failed');

            return;
        }

        DB::transaction(function () use ($check, $result): void {
            $workspace = Organization::query()->lockForUpdate()->find($this->organizationId);
            $current = $workspace?->monitoredDomains()->lockForUpdate()->find($this->domainId);
            $record = $this->checkQuery()->where('status', 'running')->lockForUpdate()->first();

            if ($record === null) {
                return;
            }

            if (! $workspace?->allowsDiscovery() || ! $this->scopeMatches($current, $check)) {
                $this->finish('skipped', 'scope_or_queue_expired');

                return;
            }

            $record->forceFill(['status' => 'completed', 'result' => $result, 'finished_at' => now()])->save();
        });
    }

    public function failed(): void
    {
        $this->finish('failed', 'worker_error');
    }

    private function checkQuery(): Builder
    {
        return TlsCheck::query()->whereKey($this->checkId)->where('monitored_domain_id', $this->domainId)
            ->whereHas('monitoredDomain', fn (Builder $domain) => $domain->where('organization_id', $this->organizationId));
    }

    private function eligibleDomain(TlsCheck $check): ?MonitoredDomain
    {
        $domain = MonitoredDomain::eligible()->where('organization_id', $this->organizationId)->find($this->domainId);

        return $this->scopeMatches($domain, $check) ? $domain : null;
    }

    private function resolveDirectAddress(PassiveDnsDiscovery $dns, MonitoredDomain $domain, TlsCheck $check): ?string
    {
        $records = collect($dns->observe($domain->hostname));

        return ! $records->contains('record_type', 'CNAME')
            && $records->contains(fn (array $record): bool => in_array($record['record_type'], ['A', 'AAAA'], true) && $record['value'] === $check->ip_address)
            ? $check->ip_address
            : null;
    }

    private function scopeMatches(?MonitoredDomain $domain, TlsCheck $check): bool
    {
        if (! $domain?->hasTlsScope() || $domain->tls_authorization_id !== $check->authorization_id
            || $domain->tls_scope !== $check->scope) {
            return false;
        }

        if ($check->scope === TlsCheck::DIRECT
            && ($domain->tls_approved_ip !== $check->ip_address || ObservedNetwork::classify($check->ip_address) !== 'public_unknown')) {
            return false;
        }

        $authorized = Membership::query()->where('organization_id', $this->organizationId)
            ->whereIn('user_id', [$domain->tls_approved_by, $check->requested_by])
            ->whereIn('role', [Membership::OWNER, Membership::ADMIN])->pluck('user_id');

        return $authorized->contains($domain->tls_approved_by) && $authorized->contains($check->requested_by);
    }

    private function finish(string $status, string $reason): void
    {
        $this->checkQuery()->whereIn('status', ['queued', 'running'])
            ->update(['status' => $status, 'reason' => $reason, 'finished_at' => now()]);
    }
}
