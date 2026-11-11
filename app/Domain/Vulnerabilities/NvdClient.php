<?php

namespace App\Domain\Vulnerabilities;

use Illuminate\Http\Client\ConnectionException;
use Illuminate\Support\Facades\Http;

final class NvdClient
{
    /** @return list<array<string, mixed>> */
    public function vulnerabilitiesForCpe(string $cpe): array
    {
        $request = Http::acceptJson()
            ->connectTimeout((int) config('cve.connect_timeout'))
            ->timeout((int) config('cve.timeout'))
            ->retry([500, 1500], 2, fn (\Throwable $exception): bool => $exception instanceof ConnectionException);

        if (filled(config('cve.nvd_api_key'))) {
            $request = $request->withHeaders(['apiKey' => (string) config('cve.nvd_api_key')]);
        }

        $response = $request->get(rtrim((string) config('cve.nvd_url'), '/').'/cves/2.0', [
            'cpeName' => $cpe,
            'resultsPerPage' => 200,
        ])->throw();

        $items = $response->json('vulnerabilities', []);
        if (! is_array($items)) {
            return [];
        }

        return collect($items)
            ->map(fn (mixed $item): ?array => is_array($item) ? $this->normalize($item['cve'] ?? []) : null)
            ->filter()
            ->values()
            ->all();
    }

    /** @return array<string, mixed>|null */
    private function normalize(mixed $cve): ?array
    {
        if (! is_array($cve) || ! is_string($cve['id'] ?? null)) {
            return null;
        }

        $description = collect($cve['descriptions'] ?? [])->first(fn (mixed $item): bool => is_array($item) && ($item['lang'] ?? null) === 'en');
        $metric = $this->metric($cve['metrics'] ?? []);

        return [
            'cve_id' => $cve['id'],
            'title' => is_array($description) ? ($description['value'] ?? null) : null,
            'description' => is_array($description) ? ($description['value'] ?? null) : null,
            'severity' => $metric['severity'],
            'cvss_score' => $metric['score'],
            'cvss_vector' => $metric['vector'],
            'cisa_kev' => filled($cve['cisaExploitAdd'] ?? null),
            'affected_cpes' => $this->affectedCpes($cve['configurations'] ?? []),
            'references' => collect($cve['references'] ?? [])->pluck('url')->filter()->values()->all(),
            'published_at' => $cve['published'] ?? null,
            'last_modified_at' => $cve['lastModified'] ?? null,
        ];
    }

    /** @return array{severity: ?string, score: ?float, vector: ?string} */
    private function metric(mixed $metrics): array
    {
        if (! is_array($metrics)) {
            return ['severity' => null, 'score' => null, 'vector' => null];
        }

        foreach (['cvssMetricV40', 'cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'] as $key) {
            $entry = $metrics[$key][0] ?? null;
            $data = is_array($entry) ? ($entry['cvssData'] ?? $entry) : null;
            if (! is_array($data)) {
                continue;
            }

            return [
                'severity' => isset($data['baseSeverity']) ? strtolower((string) $data['baseSeverity']) : null,
                'score' => isset($data['baseScore']) ? (float) $data['baseScore'] : null,
                'vector' => $data['vectorString'] ?? null,
            ];
        }

        return ['severity' => null, 'score' => null, 'vector' => null];
    }

    /** @return list<array<string, mixed>> */
    private function affectedCpes(mixed $configurations): array
    {
        $matches = [];
        foreach (is_array($configurations) ? $configurations : [] as $configuration) {
            $this->collectMatches($configuration, $matches);
        }

        return $matches;
    }

    /** @param array<int, array<string, mixed>> $matches */
    private function collectMatches(mixed $node, array &$matches): void
    {
        if (! is_array($node)) {
            return;
        }
        foreach ($node['cpeMatch'] ?? [] as $match) {
            if (! is_array($match) || ! is_string($match['criteria'] ?? null)) {
                continue;
            }
            $matches[] = [
                'criteria' => $match['criteria'],
                'vulnerable' => $match['vulnerable'] ?? true,
                'version_start_including' => $match['versionStartIncluding'] ?? null,
                'version_start_excluding' => $match['versionStartExcluding'] ?? null,
                'version_end_including' => $match['versionEndIncluding'] ?? null,
                'version_end_excluding' => $match['versionEndExcluding'] ?? null,
            ];
        }
        foreach ($node['nodes'] ?? [] as $child) {
            $this->collectMatches($child, $matches);
        }
        foreach ($node['children'] ?? [] as $child) {
            $this->collectMatches($child, $matches);
        }
    }
}
