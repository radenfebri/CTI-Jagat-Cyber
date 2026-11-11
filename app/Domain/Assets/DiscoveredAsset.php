<?php

namespace App\Domain\Assets;

use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class DiscoveredAsset extends Model
{
    use HasUuids;

    public $timestamps = false;

    public function isImported(): bool
    {
        return in_array($this->source, ['manual', 'zone_file'], true);
    }

    public function subdomainSourceLabel(): string
    {
        return match ($this->source) {
            'cloudflare_zone' => 'Zona DNS Cloudflare',
            'zone_file' => 'Impor zona BIND',
            'manual' => 'Impor hostname',
            default => 'Certificate Transparency',
        };
    }

    public function observationStatusLabel(): string
    {
        if ($this->hidden_at !== null) {
            return 'Disembunyikan';
        }

        if ($this->retired_at !== null) {
            return 'Tidak terlihat lagi';
        }

        return match ($this->source) {
            'certspotter' => 'Tercatat di sertifikat',
            'cloudflare_zone' => 'Tercatat di zona',
            'zone_file' => 'Tercatat di ekspor zona',
            'manual' => 'Dilaporkan operator',
            default => 'Teramati',
        };
    }

    public function monitoredDomain(): BelongsTo
    {
        return $this->belongsTo(MonitoredDomain::class);
    }

    public function vulnerabilityFindings(): HasMany
    {
        return $this->hasMany(VulnerabilityFinding::class);
    }

    protected function casts(): array
    {
        return [
            'first_seen_at' => 'immutable_datetime',
            'last_seen_at' => 'immutable_datetime',
            'retired_at' => 'immutable_datetime',
            'hidden_at' => 'immutable_datetime',
        ];
    }
}
