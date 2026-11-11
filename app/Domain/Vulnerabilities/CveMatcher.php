<?php

namespace App\Domain\Vulnerabilities;

use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\VulnerabilityFinding;
use App\Domain\Assets\WebObservation;
use App\Models\CveRecord;
use Illuminate\Support\Str;

final class CveMatcher
{
    public function __construct(private NvdClient $nvd) {}

    public function map(WebObservation $observation, MonitoredDomain $domain): int
    {
        if (! (bool) config('cve.enabled')) {
            return 0;
        }

        $asset = $domain->assets()->where('record_type', 'SUBDOMAIN')->where('value', $observation->hostname)->first();
        $mapped = 0;
        $seenCpes = [];
        foreach ($observation->technologies ?? [] as $technology) {
            if (! is_array($technology) || blank($technology['name'] ?? null) || blank($technology['version'] ?? null)) {
                continue;
            }

            $cpe = $this->cpeFor($technology['name'], $technology['version']);
            if ($cpe === null) {
                continue;
            }
            if (isset($seenCpes[$cpe])) {
                continue;
            }
            $seenCpes[$cpe] = true;

            foreach ($this->nvd->vulnerabilitiesForCpe($cpe) as $recordData) {
                $match = collect($recordData['affected_cpes'] ?? [])->first(
                    fn (mixed $criteria): bool => is_array($criteria) && $this->matches($criteria, $cpe, $technology['version']),
                );
                if (! is_array($match)) {
                    continue;
                }

                $record = CveRecord::updateOrCreate(['cve_id' => $recordData['cve_id']], [
                    ...$recordData,
                    'source' => 'nvd',
                ]);
                $finding = VulnerabilityFinding::firstOrNew([
                    'monitored_domain_id' => $domain->id,
                    'hostname' => $observation->hostname,
                    'cve_id' => $record->cve_id,
                ]);
                $finding->fill([
                    'discovered_asset_id' => $asset?->id,
                    'severity' => $record->severity ?: 'info',
                    'status' => $finding->exists ? $finding->status : 'open',
                    'title' => $record->title ?: $record->cve_id,
                    'cpe' => $cpe,
                    'confidence' => 'probable',
                    'source' => 'nvd',
                    'cvss_score' => $record->cvss_score,
                    'cisa_kev' => $record->cisa_kev,
                    'matched_version_range' => $this->rangeLabel($match),
                    'fixed_version' => $match['version_end_excluding'] ?? $match['version_end_including'] ?? null,
                    'description' => $record->description,
                    'evidence' => [
                        'technology' => $technology,
                        'cpe' => $cpe,
                        'source' => 'http_fingerprint',
                        'references' => $record->references ?? [],
                    ],
                    'detected_at' => $finding->detected_at ?: now(),
                    'first_seen_at' => $finding->first_seen_at ?: now(),
                    'last_seen_at' => now(),
                ]);
                $finding->save();
                $mapped++;
            }
        }

        return $mapped;
    }

    private function cpeFor(mixed $name, mixed $version): ?string
    {
        $key = Str::lower(trim((string) $name));
        $mapping = config('cve.technology_cpe.'.$key);
        if (! is_array($mapping) || blank($version)) {
            return null;
        }

        return sprintf(
            'cpe:2.3:%s:%s:%s:%s:*:*:*:*:*:*:*',
            $mapping['part'], $mapping['vendor'], $mapping['product'], trim((string) $version),
        );
    }

    /** @param array<string, mixed> $criteria */
    private function matches(array $criteria, string $cpe, string $version): bool
    {
        if (($criteria['vulnerable'] ?? true) !== true || ! str_starts_with((string) ($criteria['criteria'] ?? ''), 'cpe:2.3:')) {
            return false;
        }

        $expected = explode(':', (string) $criteria['criteria']);
        $actual = explode(':', $cpe);
        if (($expected[2] ?? null) !== ($actual[2] ?? null) || ($expected[3] ?? null) !== ($actual[3] ?? null)
            || ($expected[4] ?? null) !== ($actual[4] ?? null)) {
            return false;
        }

        $criteriaVersion = $expected[5] ?? '*';
        if ($criteriaVersion !== '*' && $criteriaVersion !== $version) {
            return false;
        }
        if (filled($criteria['version_start_including'] ?? null) && version_compare($version, $criteria['version_start_including'], '<')) {
            return false;
        }
        if (filled($criteria['version_start_excluding'] ?? null) && version_compare($version, $criteria['version_start_excluding'], '<=')) {
            return false;
        }
        if (filled($criteria['version_end_including'] ?? null) && version_compare($version, $criteria['version_end_including'], '>')) {
            return false;
        }
        if (filled($criteria['version_end_excluding'] ?? null) && version_compare($version, $criteria['version_end_excluding'], '>=')) {
            return false;
        }

        return true;
    }

    /** @param array<string, mixed> $criteria */
    private function rangeLabel(array $criteria): ?string
    {
        $start = $criteria['version_start_including'] ?? $criteria['version_start_excluding'] ?? null;
        $end = $criteria['version_end_including'] ?? $criteria['version_end_excluding'] ?? null;
        if (! $start && ! $end) {
            return null;
        }

        return ($start ? '>= '.$start : '').($start && $end ? ' ' : '').($end ? '<= '.$end : '');
    }
}
