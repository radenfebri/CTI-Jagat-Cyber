<?php

namespace App\Console\Commands;

use App\Domain\Assets\WebObservation;
use App\Jobs\MapAssetCves;
use Illuminate\Console\Attributes\Description;
use Illuminate\Console\Attributes\Signature;
use Illuminate\Console\Command;
use Illuminate\Database\Eloquent\Builder;

#[Signature('cti:dispatch-cve-mapping {--limit=1000 : Maximum observations to enqueue}')]
#[Description('Enqueue CVE correlation jobs for recent web observations')]
class DispatchCveMapping extends Command
{
    public function handle(): int
    {
        if (! (bool) config('cve.enabled')) {
            $this->warn('CVE mapping is disabled. Set CTI_CVE_ENABLED=true first.');

            return self::SUCCESS;
        }

        $limit = max(1, min(10000, (int) $this->option('limit')));
        $ids = WebObservation::query()
            ->whereHas('monitoredDomain', fn (Builder $query): Builder => $query->whereNotNull('verified_at'))
            ->whereNotNull('checked_at')
            ->orderBy('id')
            ->limit($limit)
            ->pluck('id');

        foreach ($ids as $id) {
            MapAssetCves::dispatch((int) $id);
        }

        $this->info("Enqueued {$ids->count()} CVE mapping job(s).");

        return self::SUCCESS;
    }
}
