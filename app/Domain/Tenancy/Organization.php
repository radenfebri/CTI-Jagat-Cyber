<?php

namespace App\Domain\Tenancy;

use App\Domain\Assets\MonitoredDomain;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Organization extends Model
{
    use HasUuids;

    public const DISCOVERY_SUBSCRIPTIONS = ['trial', 'active'];

    protected $fillable = ['name', 'slug', 'subscription_status'];

    public function monitoredDomains(): HasMany
    {
        return $this->hasMany(MonitoredDomain::class);
    }

    public function allowsDiscovery(): bool
    {
        return in_array($this->subscription_status, self::DISCOVERY_SUBSCRIPTIONS, true);
    }
}
