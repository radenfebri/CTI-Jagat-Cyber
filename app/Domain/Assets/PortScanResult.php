<?php

namespace App\Domain\Assets;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class PortScanResult extends Model
{
    use HasUuids;

    protected $fillable = [
        'port_scan_run_id', 'port', 'protocol', 'state', 'latency_ms', 'service', 'product',
        'service_version', 'cpe', 'banner', 'fingerprint_source', 'observed_at',
    ];

    public function run(): BelongsTo
    {
        return $this->belongsTo(PortScanRun::class, 'port_scan_run_id');
    }

    protected function casts(): array
    {
        return [
            'port' => 'integer',
            'latency_ms' => 'integer',
            'observed_at' => 'immutable_datetime',
        ];
    }
}
