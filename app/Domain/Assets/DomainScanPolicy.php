<?php

namespace App\Domain\Assets;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class DomainScanPolicy extends Model
{
    protected $primaryKey = 'monitored_domain_id';

    protected $keyType = 'string';

    public $incrementing = false;

    protected $fillable = ['authorization_id', 'approved_by', 'approved_at', 'revoked_at', 'next_run_at', 'run_id', 'last_status', 'last_queued_at', 'last_finished_at', 'last_success_at'];

    protected function casts(): array
    {
        return [
            'approved_at' => 'immutable_datetime',
            'revoked_at' => 'immutable_datetime',
            'next_run_at' => 'immutable_datetime',
            'last_queued_at' => 'immutable_datetime',
            'last_finished_at' => 'immutable_datetime',
            'last_success_at' => 'immutable_datetime',
        ];
    }

    public function monitoredDomain(): BelongsTo
    {
        return $this->belongsTo(MonitoredDomain::class);
    }

    public function isAuthorized(): bool
    {
        return $this->revoked_at === null && $this->approved_by !== null;
    }
}
