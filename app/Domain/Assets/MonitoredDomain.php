<?php

namespace App\Domain\Assets;

use App\Domain\Tenancy\Organization;
use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;

class MonitoredDomain extends Model
{
    use HasUuids;

    public const TXT_PREFIX = '_cti-jagat-cyber.';

    protected $fillable = ['organization_id', 'hostname', 'verification_token', 'verification_expires_at'];

    protected $hidden = ['verification_token', 'cloudflare_api_token'];

    protected function casts(): array
    {
        return [
            'verification_expires_at' => 'immutable_datetime',
            'verification_checked_at' => 'immutable_datetime',
            'verified_at' => 'immutable_datetime',
            'zone_checked_at' => 'immutable_datetime',
            'ct_checked_at' => 'immutable_datetime',
            'tls_approved_at' => 'immutable_datetime',
            'web_next_run_at' => 'immutable_datetime',
            'cloudflare_api_token' => 'encrypted',
        ];
    }

    public function organization(): BelongsTo
    {
        return $this->belongsTo(Organization::class);
    }

    public function scanPolicy(): HasOne
    {
        return $this->hasOne(DomainScanPolicy::class);
    }

    public function assets(): HasMany
    {
        return $this->hasMany(DiscoveredAsset::class);
    }

    public function tlsChecks(): HasMany
    {
        return $this->hasMany(TlsCheck::class);
    }

    public function webObservations(): HasMany
    {
        return $this->hasMany(WebObservation::class);
    }

    public function vulnerabilityFindings(): HasMany
    {
        return $this->hasMany(VulnerabilityFinding::class);
    }

    public function portScanRuns(): HasMany
    {
        return $this->hasMany(PortScanRun::class);
    }

    public function hasTlsScope(): bool
    {
        return $this->tls_authorization_id !== null && $this->tls_approved_by !== null
            && $this->verified_at !== null
            && match ($this->tls_scope) {
                TlsCheck::DIRECT => $this->tls_approved_ip !== null,
                TlsCheck::PUBLIC_ENDPOINT => $this->tls_approved_ip === null,
                default => false,
            };
    }

    public function invalidateOwnership(): void
    {
        $this->forceFill([
            'verified_at' => null,
            'verification_checked_at' => now(),
            'verification_status' => 'not_found',
            'verification_expires_at' => now()->addDays(config('cti.verification_token_days')),
            'ct_authorization_id' => null,
            'tls_authorization_id' => null,
            'tls_approved_ip' => null,
            'tls_scope' => TlsCheck::DIRECT,
            'tls_approved_by' => null,
            'tls_approved_at' => null,
            'web_authorization_id' => null,
            'web_next_run_at' => null,
        ])->save();

        $this->scanPolicy()->whereNull('revoked_at')->update([
            'last_status' => 'skipped',
            'revoked_at' => now(),
            'next_run_at' => null,
            'last_finished_at' => now(),
        ]);
    }

    public function txtName(): string
    {
        return self::TXT_PREFIX.$this->hostname;
    }

    public function txtValue(): string
    {
        return 'cti-jagat-cyber='.$this->verification_token;
    }

    #[Scope]
    protected function eligible(Builder $query): void
    {
        $query->whereHas('organization', fn (Builder $organizations) => $organizations
            ->whereIn('subscription_status', Organization::DISCOVERY_SUBSCRIPTIONS));
    }
}
