<?php

namespace App\Domain\Assets;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AssetObservationChange extends Model
{
    public $timestamps = false;

    protected function casts(): array
    {
        return ['occurred_at' => 'immutable_datetime'];
    }

    public function asset(): BelongsTo
    {
        return $this->belongsTo(DiscoveredAsset::class, 'discovered_asset_id');
    }
}
