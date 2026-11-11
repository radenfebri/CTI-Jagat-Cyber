<?php

namespace App\Domain\Assets;

use Illuminate\Database\Eloquent\Attributes\Scope;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Query\Builder as QueryBuilder;

class WebObservation extends Model
{
    public $timestamps = false;

    protected $fillable = ['hostname', 'authorization_id', 'public_ip', 'scheme', 'status_code', 'server_header', 'technologies', 'checked_at'];

    public function monitoredDomain(): BelongsTo
    {
        return $this->belongsTo(MonitoredDomain::class);
    }

    protected function casts(): array
    {
        return ['checked_at' => 'immutable_datetime', 'status_code' => 'integer', 'technologies' => 'array'];
    }

    #[Scope]
    protected function successful(Builder $query): void
    {
        $query->where('status_code', 200)->where('checked_at', '>=', now()->subHours(48));
    }

    #[Scope]
    protected function responded(Builder $query): void
    {
        $query->whereBetween('status_code', [100, 599])->where('checked_at', '>=', now()->subHours(48));
    }

    #[Scope]
    protected function listedSubdomains(Builder $query, bool $hidden = false): void
    {
        $query->whereExists(function (QueryBuilder $assets) use ($hidden): void {
            $assets->selectRaw('1')->from('discovered_assets')
                ->whereColumn('discovered_assets.monitored_domain_id', 'web_observations.monitored_domain_id')
                ->whereColumn('discovered_assets.value', 'web_observations.hostname')
                ->where('discovered_assets.record_type', 'SUBDOMAIN')->whereNull('discovered_assets.retired_at');
            $hidden ? $assets->whereNotNull('discovered_assets.hidden_at') : $assets->whereNull('discovered_assets.hidden_at');
        });
    }
}
