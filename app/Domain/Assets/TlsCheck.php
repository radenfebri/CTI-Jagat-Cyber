<?php

namespace App\Domain\Assets;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class TlsCheck extends Model
{
    use HasUuids;

    public const DIRECT = 'direct';

    public const PUBLIC_ENDPOINT = 'public_endpoint';

    protected $fillable = ['requested_by', 'authorization_id', 'ip_address', 'scope', 'status'];

    public function scopeLabel(): string
    {
        return $this->scope === self::PUBLIC_ENDPOINT ? 'Endpoint publik' : 'IP langsung';
    }

    protected function casts(): array
    {
        return ['result' => 'array', 'started_at' => 'immutable_datetime', 'finished_at' => 'immutable_datetime'];
    }

    public function monitoredDomain(): BelongsTo
    {
        return $this->belongsTo(MonitoredDomain::class);
    }
}
