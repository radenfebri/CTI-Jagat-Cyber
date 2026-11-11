<?php

namespace Tests\Feature;

use App\Domain\Tenancy\CreateOrganization;
use App\Domain\Vulnerabilities\CveMatcher;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

class CveMappingTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_exact_version_evidence_creates_a_cve_finding(): void
    {
        Config::set([
            'cve.enabled' => true,
            'cve.nvd_url' => 'https://services.nvd.nist.gov/rest/json',
            'cve.nvd_api_key' => null,
        ]);
        Http::preventStrayRequests();
        Http::fake([
            'https://services.nvd.nist.gov/rest/json/cves/2.0*' => Http::response([
                'vulnerabilities' => [[
                    'cve' => [
                        'id' => 'CVE-2026-1234',
                        'descriptions' => [['lang' => 'en', 'value' => 'PHP vulnerability']],
                        'metrics' => ['cvssMetricV31' => [['cvssData' => [
                            'baseScore' => 8.1,
                            'baseSeverity' => 'HIGH',
                            'vectorString' => 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                        ]]]],
                        'configurations' => [[
                            'nodes' => [[
                                'cpeMatch' => [[
                                    'vulnerable' => true,
                                    'criteria' => 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*:*',
                                    'versionEndExcluding' => '8.2.13',
                                ]],
                            ]],
                        ]],
                        'references' => [['url' => 'https://example.test/CVE-2026-1234']],
                        'published' => '2026-01-01T00:00:00.000',
                        'lastModified' => '2026-01-02T00:00:00.000',
                    ],
                ]],
            ]),
        ]);

        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $domain = $workspace->monitoredDomains()->create([
            'hostname' => 'example.com',
            'verification_token' => 'fixture-token',
            'verification_expires_at' => now()->addDay(),
        ]);
        $domain->forceFill(['verified_at' => now()])->save();
        $asset = $domain->assets()->forceCreate([
            'record_type' => 'SUBDOMAIN',
            'value' => 'api.example.com',
            'source' => 'manual',
            'first_seen_at' => now(),
            'last_seen_at' => now(),
        ]);
        $observation = $domain->webObservations()->create([
            'hostname' => $asset->value,
            'authorization_id' => (string) Str::uuid(),
            'public_ip' => '93.184.216.34',
            'scheme' => 'https',
            'status_code' => 200,
            'technologies' => [['name' => 'PHP', 'version' => '8.2.12', 'source' => 'header']],
            'checked_at' => now(),
        ]);

        $mapped = app(CveMatcher::class)->map($observation, $domain);

        $this->assertSame(1, $mapped);
        $this->assertDatabaseHas('cve_records', ['cve_id' => 'CVE-2026-1234', 'severity' => 'high']);
        $this->assertDatabaseHas('vulnerability_findings', [
            'hostname' => 'api.example.com',
            'cve_id' => 'CVE-2026-1234',
            'confidence' => 'probable',
            'cisa_kev' => false,
        ]);
        Http::assertSent(fn ($request): bool => str_starts_with($request->url(), 'https://services.nvd.nist.gov/rest/json/cves/2.0')
            && str_contains(urldecode($request->url()), 'cpeName=cpe:2.3:a:php:php:8.2.12:*:*:*:*:*:*:*'));
    }
}
