<?php

namespace Tests\Unit;

use App\Domain\Vulnerabilities\CvssSeverity;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

class CvssSeverityTest extends TestCase
{
    #[DataProvider('scoreBoundaries')]
    public function test_it_maps_cvss_scores_to_the_first_qualitative_scale(float $score, CvssSeverity $expected): void
    {
        $this->assertSame($expected, CvssSeverity::fromScore($score));
    }

    public static function scoreBoundaries(): array
    {
        return [
            'maximum critical' => [10.0, CvssSeverity::Critical],
            'minimum critical' => [9.0, CvssSeverity::Critical],
            'maximum high' => [8.9, CvssSeverity::High],
            'minimum high' => [7.0, CvssSeverity::High],
            'maximum medium' => [6.9, CvssSeverity::Medium],
            'minimum medium' => [4.0, CvssSeverity::Medium],
            'maximum low' => [3.9, CvssSeverity::Low],
            'minimum low' => [0.1, CvssSeverity::Low],
            'none' => [0.0, CvssSeverity::None],
        ];
    }
}
