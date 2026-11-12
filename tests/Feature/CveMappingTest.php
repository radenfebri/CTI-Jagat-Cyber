<?php

namespace Tests\Feature;

use App\Domain\Tenancy\CreateOrganization;
use App\Domain\Vulnerabilities\CveMatcher;
use App\Models\CveRecord;
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
                'vulnerabilities' => [
                    ['cve' => [
                        'id' => 'CVE-2026-1234',
                        'descriptions' => [['lang' => 'en', 'value' => 'PHP '.str_repeat('vulnerability ', 30)]],
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
                    ]],
                    ['cve' => [
                        'id' => 'CVE-2007-0001',
                        'descriptions' => [['lang' => 'en', 'value' => 'An unbounded historical product match']],
                        'configurations' => [['nodes' => [['cpeMatch' => [[
                            'vulnerable' => true,
                            'criteria' => 'cpe:2.3:a:php:php:*:*:*:*:*:*:*:*:*',
                        ]]]]]],
                        'references' => [],
                    ]],
                ],
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
        $cached = app(CveMatcher::class)->map($observation, $domain);

        $this->assertSame(1, $mapped);
        $this->assertSame(1, $cached);
        $this->assertDatabaseHas('cve_records', ['cve_id' => 'CVE-2026-1234', 'severity' => 'high']);
        $this->assertLessThanOrEqual(190, mb_strlen((string) CveRecord::where('cve_id', 'CVE-2026-1234')->value('title')));
        $this->assertDatabaseHas('vulnerability_findings', [
            'hostname' => 'api.example.com',
            'cve_id' => 'CVE-2026-1234',
            'severity' => 'high',
            'cvss_score' => 8.1,
            'confidence' => 'probable',
            'cisa_kev' => false,
        ]);
        $this->assertDatabaseMissing('vulnerability_findings', ['cve_id' => 'CVE-2007-0001']);
        Http::assertSent(fn ($request): bool => str_starts_with($request->url(), 'https://services.nvd.nist.gov/rest/json/cves/2.0')
            && str_contains(urldecode($request->url()), 'cpeName=cpe:2.3:a:php:php:8.2.12:*:*:*:*:*:*:*'));
        Http::assertSentCount(1);
    }

    public function test_port_banner_version_creates_a_cve_finding(): void
    {
        Config::set(['cve.enabled' => true, 'cve.nvd_url' => 'https://services.nvd.nist.gov/rest/json', 'cve.nvd_api_key' => null]);
        Http::preventStrayRequests();
        Http::fake(['https://services.nvd.nist.gov/rest/json/cves/2.0*' => Http::response([
            'vulnerabilities' => [[
                'cve' => [
                    'id' => 'CVE-2026-5678',
                    'descriptions' => [['lang' => 'en', 'value' => 'Exim vulnerability']],
                    'configurations' => [['nodes' => [['cpeMatch' => [[
                        'vulnerable' => true,
                        'criteria' => 'cpe:2.3:a:exim:exim:*:*:*:*:*:*:*:*:*',
                        'versionEndExcluding' => '4.100.2',
                    ]]]]]],
                    'references' => [],
                ],
            ]],
        ])]);

        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $domain = $workspace->monitoredDomains()->create([
            'hostname' => 'example.com', 'verification_token' => 'fixture-token', 'verification_expires_at' => now()->addDay(),
        ]);
        $domain->forceFill(['verified_at' => now()])->save();
        $run = $domain->portScanRuns()->create([
            'target_ip' => '93.184.216.34', 'range_start' => 1, 'range_end' => 65535,
            'total_ports' => 65535, 'completed_ports' => 65535, 'open_ports' => 1, 'status' => 'completed',
            'finished_at' => now(),
        ]);
        $result = $run->results()->create([
            'port' => 587, 'protocol' => 'tcp', 'state' => 'open', 'service' => 'SMTP', 'product' => 'Exim',
            'service_version' => '4.100.1', 'cpe' => 'cpe:2.3:a:exim:exim:4.100.1:*:*:*:*:*:*:*',
            'banner' => '220 ESMTP Exim 4.100.1', 'fingerprint_source' => 'tcp_banner', 'observed_at' => now(),
        ]);

        $mapped = app(CveMatcher::class)->mapPort($result->load('run'), $domain);

        $this->assertSame(1, $mapped);
        $this->assertDatabaseHas('vulnerability_findings', [
            'hostname' => 'example.com', 'cve_id' => 'CVE-2026-5678', 'confidence' => 'confirmed', 'source' => 'tcp_banner',
        ]);
    }
}
