<?php

namespace App\Console\Commands;

use App\Domain\Assets\DomainJobDispatcher;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\PortScanDispatcher;
use App\Jobs\ProbeWebInventory;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;

#[Signature('cti:dispatch-domain-jobs {--limit=50 : Maximum number of domains to select per job type}')]
#[Description('Queue due ownership, passive discovery, web inventory and TLS checks')]
class DispatchDomainJobs extends Command
{
    public function handle(DomainJobDispatcher $dispatcher, PortScanDispatcher $portScans): int
    {
        $limit = min(50, max(1, (int) $this->option('limit')));

        MonitoredDomain::eligible()->whereNull('verified_at')
            ->where('verification_expires_at', '>', now())
            ->where(function (Builder $domains): void {
                $domains->whereNull('verification_checked_at')
                    ->orWhere('verification_checked_at', '<=', now()->subMinutes(config('cti.verification_interval_minutes')));
            })
            ->orderBy('verification_checked_at')->orderBy('id')->limit($limit)->get()
            ->each(fn (MonitoredDomain $domain) => $dispatcher->verify($domain));

        MonitoredDomain::eligible()->whereNotNull('verified_at')
            ->where(function (Builder $domains): void {
                $domains->whereDoesntHave('scanPolicy')
                    ->orWhereHas('scanPolicy', fn (Builder $policies) => $policies
                        ->whereNull('revoked_at')->whereNotNull('approved_by')->where('next_run_at', '<=', now()))
                    ->orWhereHas('scanPolicy', fn (Builder $policies) => $policies->whereNotNull('revoked_at'))
                    ->orWhereNull('ct_authorization_id');
            })
            ->orderBy('id')->limit($limit)->get()
            ->each(function (MonitoredDomain $domain) use ($dispatcher): void {
                if ($dispatcher->ensureAutomaticCoverage($domain)) {
                    $dispatcher->discover($domain);
                }
            });

        MonitoredDomain::eligible()->whereNotNull('verified_at')->whereNotNull('tls_authorization_id')
            ->whereDoesntHave('tlsChecks', fn (Builder $checks) => $checks->where('created_at', '>', now()->subHours(config('cti.passive_interval_hours'))))
            ->orderBy('id')->limit($limit)->get()
            ->each(fn (MonitoredDomain $domain) => $dispatcher->queueAutomaticTls($domain));

        MonitoredDomain::eligible()->whereNotNull('verified_at')->orderBy('id')->limit($limit)->get()
            ->each(fn (MonitoredDomain $domain) => $portScans->queueAutomatic($domain));

        MonitoredDomain::eligible()->whereNotNull('verified_at')->whereNotNull('web_authorization_id')
            ->where('web_next_run_at', '<=', now())->orderBy('web_next_run_at')->orderBy('id')->limit($limit)->get()
            ->each(fn (MonitoredDomain $domain) => ProbeWebInventory::dispatch($domain->id, $domain->web_authorization_id));

        return self::SUCCESS;
    }
}
