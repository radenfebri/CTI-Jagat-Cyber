<?php

namespace Database\Factories;

use App\Models\CveRecord;
use Illuminate\Database\Eloquent\Factories\Factory;

/**
 * @extends Factory<CveRecord>
 */
class CveRecordFactory extends Factory
{
    /**
     * Define the model's default state.
     *
     * @return array<string, mixed>
     */
    public function definition(): array
    {
        return [
            'cve_id' => 'CVE-2026-'.fake()->numerify('####'),
            'source' => 'nvd',
            'title' => fake()->sentence(4),
            'description' => fake()->paragraph(),
            'severity' => 'high',
            'cvss_score' => 8.1,
            'cvss_vector' => null,
            'cisa_kev' => false,
            'affected_cpes' => [],
            'references' => [],
            'published_at' => now(),
            'last_modified_at' => now(),
        ];
    }
}
