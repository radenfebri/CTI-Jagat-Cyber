<?php

namespace Tests\Feature\Domain;

use App\Domain\Assets\DnsResolver;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\TlsProbe;
use App\Domain\Tenancy\CreateOrganization;
use App\Domain\Tenancy\Organization;
use App\Jobs\DiscoverDomainAssets;
use App\Jobs\ProbeDomainTls;
use App\Jobs\ScanPortChunk;
use App\Models\User;
use Closure;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Http\Client\Request;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class DomainMonitoringTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_approving_a_direct_ip_scope_queues_the_full_port_scan(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->verifiedDomain();

        $this->actingAs($owner)->post(route('domains.tls.approve', [$workspace, $domain]), [
            'scope' => 'direct',
            'ip_address' => '93.184.216.34',
            'consent' => '1',
        ])->assertRedirect()->assertSessionHas('status', 'Direct IP scope saved. The TCP 1–65535 scan was queued automatically.');

        Queue::assertPushed(ScanPortChunk::class, 256);
        $this->assertDatabaseHas('port_scan_runs', [
            'monitored_domain_id' => $domain->id,
            'target_ip' => '93.184.216.34',
            'total_ports' => 65535,
            'status' => 'queued',
        ]);
    }

    public function test_scheduler_queues_a_port_scan_for_a_verified_direct_dns_ip(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->verifiedDomain();

        $this->artisan('cti:dispatch-domain-jobs')->assertSuccessful();

        Queue::assertPushed(ScanPortChunk::class, 256);
        $this->assertDatabaseHas('port_scan_runs', [
            'monitored_domain_id' => $domain->id,
            'target_ip' => '93.184.216.34',
            'total_ports' => 65535,
            'status' => 'queued',
        ]);
    }

    public function test_scheduler_waits_for_the_passive_port_scan_interval_but_manual_scope_can_run_again(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->verifiedDomain();
        $domain->portScanRuns()->create([
            'target_ip' => '93.184.216.34', 'range_start' => 1, 'range_end' => 65535,
            'total_ports' => 65535, 'completed_ports' => 65535, 'open_ports' => 2, 'status' => 'completed',
            'finished_at' => now(),
        ]);

        $this->artisan('cti:dispatch-domain-jobs')->assertSuccessful();
        Queue::assertNotPushed(ScanPortChunk::class);

        $this->actingAs($owner)->post(route('domains.tls.approve', [$workspace, $domain]), [
            'scope' => 'direct', 'ip_address' => '93.184.216.34', 'consent' => '1',
        ])->assertRedirect();
        Queue::assertPushed(ScanPortChunk::class, 256);
    }

    public function test_scheduler_collects_certificate_pages_then_returns_to_the_regular_interval(): void
    {
        Queue::fake();
        Http::preventStrayRequests();
        Http::fake(['api.certspotter.com/*' => Http::sequence()
            ->push([['id' => '1210', 'dns_names' => ['api.example.com']]])
            ->push([])]);
        [$owner, $workspace, $domain] = $this->verifiedDomain();
        $this->dns($domain, '93.184.216.34');
        $this->actingAs($owner)->post(route('domains.approve', [$workspace, $domain]), ['consent' => '1'])->assertRedirect();
        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->sole(), 'handle']);
        Http::assertNothingSent();

        $this->post(route('domains.certificates', [$workspace, $domain]), ['enabled' => '1'])->assertRedirect();
        $this->artisan('cti:dispatch-domain-jobs')->assertSuccessful();
        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->last(), 'handle']);
        $this->assertSame('page_saved', $domain->refresh()->ct_status);

        $this->travel(14)->minutes();
        $this->artisan('cti:dispatch-domain-jobs')->assertSuccessful();
        Queue::assertPushed(DiscoverDomainAssets::class, 2);
        $this->travel(1)->minutes();
        $this->artisan('cti:dispatch-domain-jobs')->assertSuccessful();
        Queue::assertPushed(DiscoverDomainAssets::class, 3);
        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->last(), 'handle']);

        $this->assertSame('complete', $domain->refresh()->ct_status);
        $this->assertTrue($domain->scanPolicy->next_run_at->gt(now()->addHours(23)));
        $this->assertDatabaseHas('discovered_assets', ['monitored_domain_id' => $domain->id, 'value' => 'api.example.com', 'source' => 'certspotter']);
    }

    public function test_opted_in_discovery_saves_only_in_scope_subdomains_and_paginates(): void
    {
        Queue::fake();
        Http::preventStrayRequests();
        Http::fake(['api.certspotter.com/*' => Http::sequence()->push([
            ['id' => '9100', 'dns_names' => ['Api.Example.com', '*.example.com', 'example.com', 'badexample.com', 'example.com.attacker.net']],
        ])->push([['id' => '9101', 'dns_names' => ['admin.example.com']]])]);
        [$owner, $workspace, $domain] = $this->verifiedDomain('172.66.40.184');
        $this->dns($domain, '172.66.40.184');
        $this->actingAs($owner)->post(route('domains.approve', [$workspace, $domain]), ['consent' => '1'])->assertRedirect();
        $this->post(route('domains.certificates', [$workspace, $domain]), ['enabled' => '1'])->assertRedirect();

        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->sole(), 'handle']);
        $this->assertSame(['api.example.com'], $domain->assets()->where('record_type', 'SUBDOMAIN')->pluck('value')->all());
        $this->assertSame('9100', $domain->refresh()->ct_cursor);

        $this->travel(11)->minutes();
        $this->post(route('domains.discover', [$workspace, $domain]))->assertRedirect();
        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->last(), 'handle']);

        Http::assertSent(fn (Request $request) => str_contains($request->url(), 'after=9100'));
        $this->assertSame(['admin.example.com', 'api.example.com'], $domain->assets()->where('record_type', 'SUBDOMAIN')->orderBy('value')->pluck('value')->all());
        $this->get(route('domains.show', [$workspace, $domain]))->assertOk()
            ->assertSee('api.example.com')->assertDontSee('admin.example.com');
    }

    public function test_ct_outage_does_not_discard_dns_observations(): void
    {
        Queue::fake();
        Http::preventStrayRequests();
        Http::fake(['api.certspotter.com/*' => Http::response(['error' => 'rate_limited'], 429)]);
        [$owner, $workspace, $domain] = $this->verifiedDomain();
        $this->dns($domain, '93.184.216.34');
        $this->actingAs($owner)->post(route('domains.approve', [$workspace, $domain]), ['consent' => '1'])->assertRedirect();
        $this->post(route('domains.certificates', [$workspace, $domain]), ['enabled' => '1'])->assertRedirect();

        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->sole(), 'handle']);

        $this->assertSame('unavailable', $domain->refresh()->ct_status);
        $this->assertSame('completed', $domain->scanPolicy->last_status);
        $this->assertDatabaseHas('discovered_assets', ['monitored_domain_id' => $domain->id, 'record_type' => 'A', 'retired_at' => null]);
    }

    public function test_tls_permission_rejects_cloudflare_nonpublic_ips_and_other_tenants(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->verifiedDomain('172.66.40.184');

        foreach (['172.66.40.184', '2606:4700:3108::ac42:28b8', '169.254.169.254', '100.100.100.200', '::ffff:127.0.0.1'] as $address) {
            $this->actingAs($owner)->post(route('domains.tls.approve', [$workspace, $domain]), ['ip_address' => $address, 'consent' => '1'])
                ->assertSessionHasErrors('ip_address');
        }

        $this->actingAs(User::factory()->create())->post(route('domains.tls.queue', [$workspace, $domain]))->assertNotFound();
        Queue::assertNothingPushed();
        $this->assertNull($domain->refresh()->tls_authorization_id);
    }

    public function test_tls_runs_once_against_the_approved_address_and_keeps_history(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->verifiedDomain();
        $this->dns($domain, '93.184.216.34');
        $this->mock(TlsProbe::class, fn ($probe) => $probe->shouldReceive('inspect')->once()
            ->with('example.com', '93.184.216.34')->andReturn([
                'protocol' => 'TLSv1.3', 'issuer' => 'QA CA',
                'expires_at' => now()->addMonth()->timestamp, 'fingerprint_sha256' => str_repeat('a', 64),
            ]));
        $this->actingAs($owner)->post(route('domains.tls.queue', [$workspace, $domain]))->assertConflict();
        $this->post(route('domains.tls.approve', [$workspace, $domain]), ['ip_address' => '93.184.216.34', 'consent' => '1'])
            ->assertRedirect(route('domains.show', [$workspace, $domain]).'#tls');
        $this->post(route('domains.tls.queue', [$workspace, $domain]))->assertRedirect();
        $this->post(route('domains.tls.queue', [$workspace, $domain]))->assertRedirect();

        $job = Queue::pushed(ProbeDomainTls::class)->sole();
        $this->app->call([$job, 'handle']);
        $this->app->call([$job, 'handle']);

        $check = $domain->tlsChecks()->sole();
        $this->assertSame('completed', $check->status);
        $this->assertSame('TLSv1.3', $check->result['protocol']);
        $this->get(route('attack-surface.tls', [$workspace, $domain]))->assertOk()->assertSee('QA CA');
    }

    public function test_tls_skips_when_dns_changes_before_the_worker_runs(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->verifiedDomain();
        $this->dns($domain, '93.184.216.35');
        $this->mock(TlsProbe::class, fn ($probe) => $probe->shouldNotReceive('inspect'));
        $this->actingAs($owner)->post(route('domains.tls.approve', [$workspace, $domain]), ['ip_address' => '93.184.216.34', 'consent' => '1'])->assertRedirect();
        $this->post(route('domains.tls.queue', [$workspace, $domain]))->assertRedirect();

        $this->app->call([Queue::pushed(ProbeDomainTls::class)->sole(), 'handle']);

        $this->assertDatabaseHas('tls_checks', ['monitored_domain_id' => $domain->id, 'status' => 'skipped', 'reason' => 'dns_ip_mismatch']);
    }

    public function test_public_tls_uses_live_dns_and_keeps_the_verified_hostname_through_a_waf_alias(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->verifiedDomain('172.66.40.184');
        $dns = $this->mock(DnsResolver::class);
        $dns->shouldReceive('records')->with($domain->txtName(), DNS_TXT)->once()->andReturn([
            ['type' => 'TXT', 'host' => $domain->txtName(), 'txt' => $domain->txtValue()],
        ]);
        $dns->shouldReceive('records')->with('example.com', DNS_A | DNS_AAAA | DNS_CNAME)->once()->andReturn([
            ['type' => 'CNAME', 'host' => 'example.com', 'target' => 'edge.example.net.'],
        ]);
        $dns->shouldReceive('records')->with('edge.example.net', DNS_A | DNS_AAAA | DNS_CNAME)->once()->andReturn([
            ['type' => 'A', 'host' => 'edge.example.net', 'ip' => '172.66.43.72'],
        ]);
        $this->mock(TlsProbe::class, fn ($probe) => $probe->shouldReceive('inspect')->once()
            ->with('example.com', '172.66.43.72')->andReturn([
                'protocol' => 'TLSv1.3', 'issuer' => 'Edge CA',
                'expires_at' => now()->addMonth()->timestamp, 'fingerprint_sha256' => str_repeat('a', 64),
            ]));

        $this->actingAs($owner)->get(route('attack-surface.tls', [$workspace, $domain]))->assertOk()
            ->assertSee('Public endpoint TLS checks will be enabled automatically')->assertDontSee('Approve IP');
        $scope = ['scope' => 'public_endpoint', 'consent' => '1'];
        $approveUrl = route('domains.tls.approve', [$workspace, $domain]);
        $this->post($approveUrl, $scope + ['ip_address' => '172.66.40.184'])->assertSessionHasErrors('ip_address');
        $this->post($approveUrl, $scope)->assertRedirect(route('domains.show', [$workspace, $domain]).'#tls');
        $this->post(route('domains.tls.queue', [$workspace, $domain]))->assertRedirect();
        $check = $domain->tlsChecks()->sole();
        $this->assertNull($check->ip_address);
        $this->get(route('attack-surface', $workspace))->assertOk();

        $this->app->call([Queue::pushed(ProbeDomainTls::class)->sole(), 'handle']);

        $this->assertDatabaseHas('tls_checks', ['id' => $check->id, 'scope' => 'public_endpoint', 'ip_address' => '172.66.43.72', 'status' => 'completed']);
        $this->get(route('attack-surface', $workspace))->assertOk()
            ->assertSee('Edge CA')->assertSee('172.66.43.72:443')->assertSee('Public endpoint');
    }

    public function test_public_tls_cannot_connect_to_a_non_public_dns_answer(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->verifiedDomain();
        $this->dns($domain, '169.254.169.254');
        $this->mock(TlsProbe::class, fn ($probe) => $probe->shouldNotReceive('inspect'));
        $this->actingAs($owner)->post(route('domains.tls.approve', [$workspace, $domain]), [
            'scope' => 'public_endpoint', 'consent' => '1',
        ])->assertRedirect();
        $this->post(route('domains.tls.queue', [$workspace, $domain]))->assertRedirect();

        $this->app->call([Queue::pushed(ProbeDomainTls::class)->sole(), 'handle']);

        $this->assertDatabaseHas('tls_checks', [
            'monitored_domain_id' => $domain->id, 'status' => 'skipped',
            'reason' => 'dns_public_endpoint_missing', 'ip_address' => null,
        ]);
    }

    public function test_revoked_tls_check_cannot_open_a_socket(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->verifiedDomain();
        $this->mock(TlsProbe::class, fn ($probe) => $probe->shouldNotReceive('inspect'));
        $this->actingAs($owner)->post(route('domains.tls.approve', [$workspace, $domain]), ['ip_address' => '93.184.216.34', 'consent' => '1'])->assertRedirect();
        $this->post(route('domains.tls.queue', [$workspace, $domain]))->assertRedirect();
        $this->delete(route('domains.tls.revoke', [$workspace, $domain]))->assertRedirect();

        $this->app->call([Queue::pushed(ProbeDomainTls::class)->sole(), 'handle']);

        $this->assertDatabaseHas('tls_checks', ['monitored_domain_id' => $domain->id, 'status' => 'cancelled']);
        $this->assertNull($domain->refresh()->tls_authorization_id);
    }

    /** @return array{User, Organization, MonitoredDomain} */
    private function verifiedDomain(string $address = '93.184.216.34'): array
    {
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $domain = $workspace->monitoredDomains()->create([
            'hostname' => 'example.com',
            'verification_token' => 'test-challenge',
            'verification_expires_at' => now()->addDay(),
        ]);
        $domain->forceFill(['verified_at' => now(), 'verification_status' => 'verified'])->save();
        $domain->assets()->forceCreate([
            'record_type' => 'A', 'value' => $address, 'source' => 'dns',
            'first_seen_at' => now(), 'last_seen_at' => now(),
        ]);

        return [$owner, $workspace, $domain];
    }

    private function dns(MonitoredDomain $domain, string $address): void
    {
        $this->app->instance(DnsResolver::class, new class(fn ($host, $type) => $type === DNS_TXT ? [['type' => 'TXT', 'host' => $domain->txtName(), 'txt' => $domain->txtValue()]] : [['type' => 'A', 'host' => $host, 'ip' => $address]]) implements DnsResolver
        {
            public function __construct(private Closure $resolve) {}

            public function records(string $hostname, int $type): array
            {
                return ($this->resolve)($hostname, $type);
            }
        });
    }
}
