<?php

namespace Tests\Feature;

use App\Domain\Scanning\PythonScannerClient;
use App\Domain\Tenancy\CreateOrganization;
use App\Jobs\EnrichAssetWithPython;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Str;
use Tests\TestCase;

class PythonScannerIntegrationTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_python_fingerprint_enrichment_updates_the_existing_web_observation(): void
    {
        Config::set([
            'cti.python_worker.enabled' => true,
            'cti.python_worker.url' => 'http://127.0.0.1:9100',
            'cti.python_worker.token' => 'worker-token',
            'cve.enabled' => false,
        ]);
        Http::preventStrayRequests();
        Http::fake([
            'http://127.0.0.1:9100/v1/fingerprint' => Http::response([
                'hostname' => 'api.example.com',
                'server_header' => 'nginx/1.24.0',
                'technologies' => [
                    ['name' => 'PHP', 'version' => '8.3.0', 'source' => 'header'],
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
        $domain->webObservations()->create([
            'hostname' => $asset->value,
            'authorization_id' => (string) Str::uuid(),
            'public_ip' => '93.184.216.34',
            'scheme' => 'https',
            'status_code' => 200,
            'technologies' => [['name' => 'Bootstrap', 'version' => '5.3.3', 'source' => 'body']],
            'checked_at' => now(),
        ]);

        (new EnrichAssetWithPython($asset->id))->handle(app(PythonScannerClient::class));

        $observation = $domain->webObservations()->where('hostname', $asset->value)->firstOrFail();
        $this->assertSame('nginx/1.24.0', $observation->server_header);
        $this->assertCount(2, $observation->technologies);
        $this->assertTrue(collect($observation->technologies)->contains('name', 'PHP'));
        Http::assertSent(fn ($request): bool => $request->hasHeader('Authorization', 'Bearer worker-token')
            && $request->data()['hostname'] === 'api.example.com'
            && $request->data()['base_domain'] === 'example.com');
    }

    public function test_python_enrichment_is_a_no_op_when_the_worker_is_disabled(): void
    {
        Config::set('cti.python_worker.enabled', false);
        $client = app(PythonScannerClient::class);

        $this->assertFalse($client->enabled());
        $this->assertSame([], $client->fingerprint('api.example.com', 'example.com'));
    }
}
