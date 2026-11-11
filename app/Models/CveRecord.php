<?php

namespace App\Models;

use Database\Factories\CveRecordFactory;
use Illuminate\Database\Eloquent\Concerns\HasUuids;
use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;

class CveRecord extends Model
{
    /** @use HasFactory<CveRecordFactory> */
    use HasFactory, HasUuids;

    protected $fillable = [
        'cve_id', 'source', 'title', 'description', 'severity', 'cvss_score',
        'cvss_vector', 'cisa_kev', 'affected_cpes', 'references', 'published_at',
        'last_modified_at',
    ];

    protected function casts(): array
    {
        return [
            'cvss_score' => 'decimal:1',
            'cisa_kev' => 'boolean',
            'affected_cpes' => 'array',
            'references' => 'array',
            'published_at' => 'immutable_datetime',
            'last_modified_at' => 'immutable_datetime',
        ];
    }
}
