<?php

namespace App\Jobs;

use App\Domain\Assets\PortScanResult;
use App\Domain\Vulnerabilities\CveMatcher;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Queue\Queueable;

class MapPortCves implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

    public int $timeout = 90;

    public int $tries = 6;

    public int $uniqueFor = 3600;

    public function __construct(public string $resultId)
    {
        $this->onQueue('cti');
    }

    public function uniqueId(): string
    {
        return $this->resultId;
    }

    public function backoff(): array
    {
        return [60, 300, 900, 1800, 3600];
    }

    public function handle(CveMatcher $matcher): void
    {
        if (! (bool) config('cve.enabled')) {
            return;
        }

        $result = PortScanResult::query()->with('run.monitoredDomain')->find($this->resultId);
        $domain = $result?->run?->monitoredDomain;
        if ($result === null || $domain === null || $domain->verified_at === null) {
            return;
        }

        $matcher->mapPort($result, $domain);
    }
}
