<?php

namespace App\Domain\Assets;

use App\Domain\Identity\Membership;
use App\Domain\Tenancy\Organization;
use App\Jobs\DiscoverDomainAssets;
use App\Jobs\ProbeDomainTls;
use App\Jobs\VerifyDomainOwnership;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

final class DomainJobDispatcher
{
    public function verify(MonitoredDomain $domain): void
    {
        VerifyDomainOwnership::dispatch(
            $domain->organization_id, $domain->id, hash('sha256', $domain->verification_token),
        )->afterCommit();
    }

    public function discover(MonitoredDomain $domain, bool $manual = false): bool
    {
        return DB::transaction(function () use ($domain, $manual): bool {
            $organization = Organization::query()->lockForUpdate()->find($domain->organization_id);
            $current = $organization?->monitoredDomains()->lockForUpdate()->find($domain->id);
            $policy = $current?->scanPolicy()->lockForUpdate()->first();
            $now = now();

            if (! $organization?->allowsDiscovery() || $current?->verified_at === null || ! $policy?->isAuthorized()) {
                return false;
            }

            if (in_array($policy->last_status, ['queued', 'running'], true) && $policy->last_queued_at?->gt($now->copy()->subHours(2))) {
                return false;
            }

            if ($manual ? $policy->last_queued_at?->gt($now->copy()->subMinutes(10)) : $policy->next_run_at?->gt($now)) {
                return false;
            }

            $runId = (string) Str::uuid();
            $policy->update([
                'run_id' => $runId,
                'last_status' => 'queued',
                'last_queued_at' => $now,
                'last_finished_at' => null,
                'next_run_at' => $now->copy()->addHours(config('cti.passive_interval_hours')),
            ]);

            $this->dispatchInTransaction(new DiscoverDomainAssets($organization->id, $current->id, $policy->authorization_id, $runId, forceZone: $manual));

            return true;
        });
    }

    /**
     * Enable the default passive coverage after TXT ownership has been verified.
     * The scheduler calls this for verified domains, so no manual approval click is
     * required while the ownership proof remains valid.
     */
    public function ensureAutomaticCoverage(MonitoredDomain $domain): bool
    {
        return DB::transaction(function () use ($domain): bool {
            $organization = Organization::query()->lockForUpdate()->find($domain->organization_id);
            $current = $organization?->monitoredDomains()->lockForUpdate()->find($domain->id);

            if (! $organization?->allowsDiscovery() || $current?->verified_at === null) {
                return false;
            }

            $approver = Membership::query()->where('organization_id', $organization->id)
                ->where('role', Membership::OWNER)->value('user_id')
                ?? Membership::query()->where('organization_id', $organization->id)
                    ->where('role', Membership::ADMIN)->value('user_id');

            if ($approver === null) {
                return false;
            }

            $policy = $current->scanPolicy()->lockForUpdate()->first();
            if (! $policy?->isAuthorized()) {
                $current->scanPolicy()->updateOrCreate([], [
                    'authorization_id' => (string) Str::uuid(),
                    'approved_by' => $approver,
                    'approved_at' => now(),
                    'revoked_at' => null,
                    'next_run_at' => now(),
                    'run_id' => null,
                    'last_status' => null,
                    'last_queued_at' => null,
                    'last_finished_at' => null,
                    'last_success_at' => null,
                ]);
            } elseif ($policy->next_run_at === null) {
                $policy->update(['next_run_at' => now()]);
            }

            if ($current->ct_authorization_id === null) {
                $current->forceFill(['ct_authorization_id' => (string) Str::uuid(), 'ct_status' => 'pending'])->save();
            }

            $webChanges = [];
            if ($current->web_authorization_id === null) {
                $webChanges['web_authorization_id'] = (string) Str::uuid();
            }
            if ($current->web_next_run_at === null) {
                $webChanges['web_next_run_at'] = now();
            }

            $tlsChanges = [];
            if ($current->tls_authorization_id === null) {
                $tlsChanges = [
                    'tls_authorization_id' => (string) Str::uuid(),
                    'tls_approved_ip' => null,
                    'tls_scope' => TlsCheck::PUBLIC_ENDPOINT,
                    'tls_approved_by' => $approver,
                    'tls_approved_at' => now(),
                ];
            }

            if ($webChanges !== [] || $tlsChanges !== []) {
                $current->forceFill($webChanges + $tlsChanges)->save();
            }

            return true;
        });
    }

    public function queueAutomaticTls(MonitoredDomain $domain): bool
    {
        return DB::transaction(function () use ($domain): bool {
            $organization = Organization::query()->lockForUpdate()->find($domain->organization_id);
            $current = $organization?->monitoredDomains()->lockForUpdate()->find($domain->id);

            if (! $organization?->allowsDiscovery() || ! $current?->hasTlsScope()) {
                return false;
            }

            if ($current->tlsChecks()->where('created_at', '>', now()->subHours(config('cti.passive_interval_hours')))->exists()) {
                return false;
            }

            $check = $current->tlsChecks()->create([
                'requested_by' => $current->tls_approved_by,
                'authorization_id' => $current->tls_authorization_id,
                'ip_address' => null,
                'scope' => TlsCheck::PUBLIC_ENDPOINT,
                'status' => 'queued',
            ]);

            $this->dispatchInTransaction(new ProbeDomainTls($current->organization_id, $current->id, $check->id));

            return true;
        });
    }

    public function dispatchInTransaction(DiscoverDomainAssets|ProbeDomainTls $job): void
    {
        $connection = config('queue.default');
        $queue = config('queue.connections.'.$connection);
        $transactional = ($queue['driver'] ?? null) === 'database'
            && (($queue['connection'] ?? null) === null || $queue['connection'] === DB::getDefaultConnection());

        dispatch($transactional ? $job->beforeCommit() : $job->afterCommit());
    }
}
