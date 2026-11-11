<?php

namespace App\Domain\Assets;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class PortScanRun extends Model
{
    use HasUuids;

    protected $fillable = [
        'monitored_domain_id',
        'requested_by',
        'target_ip',
        'range_start',
        'range_end',
        'total_ports',
        'completed_ports',
        'open_ports',
        'status',
        'last_error',
        'started_at',
        'finished_at',
    ];

    public function monitoredDomain(): BelongsTo
    {
        return $this->belongsTo(MonitoredDomain::class);
    }

    public function results(): HasMany
    {
        return $this->hasMany(PortScanResult::class);
    }

    protected function casts(): array
    {
        return [
            'started_at' => 'immutable_datetime',
            'finished_at' => 'immutable_datetime',
        ];
    }
}
