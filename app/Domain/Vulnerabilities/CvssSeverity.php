<?php

namespace App\Domain\Vulnerabilities;

enum CvssSeverity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case None = 'none';
    case Unrated = 'unrated';

    public static function fromScore(float|int|string|null $score, ?string $fallback = null): self
    {
        if ($score === null || $score === '' || ! is_numeric($score)) {
            return self::fromStoredValue($fallback);
        }

        $numericScore = (float) $score;
        if ($numericScore < 0 || $numericScore > 10) {
            return self::Unrated;
        }

        return match (true) {
            $numericScore >= 9.0 => self::Critical,
            $numericScore >= 7.0 => self::High,
            $numericScore >= 4.0 => self::Medium,
            $numericScore > 0.0 => self::Low,
            default => self::None,
        };
    }

    public function label(): string
    {
        return match ($this) {
            self::Critical => 'Critical',
            self::High => 'High',
            self::Medium => 'Medium',
            self::Low => 'Low',
            self::None => 'None',
            self::Unrated => 'Unrated',
        };
    }

    public function rank(): int
    {
        return match ($this) {
            self::Critical => 5,
            self::High => 4,
            self::Medium => 3,
            self::Low => 2,
            self::None => 1,
            self::Unrated => 0,
        };
    }

    private static function fromStoredValue(?string $severity): self
    {
        $normalized = mb_strtolower(trim((string) $severity));

        return self::tryFrom($normalized) ?? self::Unrated;
    }
}
