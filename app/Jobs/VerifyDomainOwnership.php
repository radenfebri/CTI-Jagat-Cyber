<?php

namespace App\Jobs;

use App\Domain\Assets\DomainProof;
use App\Domain\Assets\MonitoredDomain;
use Illuminate\Contracts\Queue\ShouldBeUnique;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Foundation\Queue\Queueable;

class VerifyDomainOwnership implements ShouldBeUnique, ShouldQueue
{
    use Queueable;

    public int $tries = 3;

    public int $timeout = 30;

    public int $uniqueFor = 600;

    public array $backoff = [30, 120];

    public function __construct(public string $organizationId, public string $domainId, public string $tokenFingerprint)
    {
        $this->onQueue('cti');
    }

    public function uniqueId(): string
    {
        return $this->domainId.':'.$this->tokenFingerprint;
    }

    public function handle(DomainProof $proof): void
    {
        $domain = $this->pendingDomain()->first();

        if ($domain === null || ! hash_equals($this->tokenFingerprint, hash('sha256', $domain->verification_token))) {
            return;
        }

        $matched = $proof->matches($domain);

        $this->pendingDomain()->where('verification_token', $domain->verification_token)->update([
            'verification_checked_at' => now(),
            'verification_status' => $matched ? 'verified' : 'not_found',
            'verified_at' => $matched ? now() : null,
        ]);
    }

    public function failed(): void
    {
        $domain = $this->pendingDomain()->first();

        if ($domain && hash_equals($this->tokenFingerprint, hash('sha256', $domain->verification_token))) {
            $this->pendingDomain()->where('verification_token', $domain->verification_token)->update([
                'verification_checked_at' => now(),
                'verification_status' => 'error',
            ]);
        }
    }

    private function pendingDomain(): Builder
    {
        return MonitoredDomain::eligible()->whereKey($this->domainId)
            ->where('organization_id', $this->organizationId)
            ->whereNull('verified_at')
            ->where('verification_expires_at', '>', now());
    }
}
