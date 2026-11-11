<?php

namespace App\Jobs;

use App\Domain\Assets\WebObservation;
use App\Domain\Vulnerabilities\CveMatcher;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

class MapAssetCves implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

    public int $timeout = 90;

    public int $tries = 3;

    public int $uniqueFor = 3600;

    public function __construct(public int $observationId)
    {
        $this->onQueue('cti');
    }

    public function uniqueId(): string
    {
        return (string) $this->observationId;
    }

    public function backoff(): array
    {
        return [60, 300];
    }

    public function handle(CveMatcher $matcher): void
    {
        if (! (bool) config('cve.enabled')) {
            return;
        }

        $observation = WebObservation::query()->with('monitoredDomain')->find($this->observationId);
        if ($observation?->monitoredDomain === null || $observation->checked_at === null) {
            return;
        }

        $matcher->map($observation, $observation->monitoredDomain);
    }
}
