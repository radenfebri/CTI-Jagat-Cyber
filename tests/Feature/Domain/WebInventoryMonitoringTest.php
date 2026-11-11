<?php

namespace Tests\Feature\Domain;

use App\Domain\Assets\DnsResolver;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\WebProbe;
use App\Domain\Identity\Membership;
use App\Domain\Tenancy\CreateOrganization;
use App\Jobs\ProbeWebInventory;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class WebInventoryMonitoringTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_authorized_checks_store_the_response_and_include_non_200_subdomains(): void
    {
        Queue::fake();
        [$owner, $domain] = $this->registeredDomain();
        $domain->assets()->forceCreate([
            'record_type' => 'SUBDOMAIN', 'value' => 'app.example.com', 'source' => 'manual',
            'first_seen_at' => now(), 'last_seen_at' => now(),
        ]);
        $dns = $this->mock(DnsResolver::class);
        $dns->shouldReceive('records')->with($domain->txtName(), DNS_TXT)->twice()
            ->andReturn([['host' => $domain->txtName(), 'type' => 'TXT', 'txt' => $domain->txtValue()]]);
        foreach (['example.com', 'app.example.com'] as $hostname) {
            $dns->shouldReceive('records')->with($hostname, DNS_A | DNS_AAAA | DNS_CNAME)->once()
                ->andReturn([['host' => $hostname, 'type' => 'A', 'ip' => '93.184.216.34']]);
        }
        $probe = $this->mock(WebProbe::class);
        $probe->shouldReceive('inspect')->with('example.com', '93.184.216.34')->once()
            ->andReturn(['scheme' => 'https', 'status_code' => 200]);
        $probe->shouldReceive('inspect')->with('app.example.com', '93.184.216.34')->once()
            ->andReturn(['scheme' => 'https', 'status_code' => 403]);
        $endpoint = route('domains.web.update', [$domain->organization_id, $domain]);

        $this->actingAs($owner)->patchJson($endpoint, ['enabled' => true])->assertUnprocessable();
        $this->patch($endpoint, ['enabled' => '1', 'consent' => '1'])->assertRedirect();
        $this->artisan('cti:dispatch-domain-jobs', ['--limit' => 1])->assertSuccessful();
        $job = Queue::pushed(ProbeWebInventory::class)->sole();
        $this->app->call([$job, 'handle']);
        $this->app->call([$job, 'handle']);

        $this->assertDatabaseHas('web_observations', ['hostname' => 'example.com', 'status_code' => 200, 'public_ip' => '93.184.216.34']);
        $this->assertDatabaseHas('web_observations', ['hostname' => 'app.example.com', 'status_code' => 403, 'public_ip' => '93.184.216.34']);
        $this->get(route('assets.inventory', $domain->organization_id))->assertOk()->assertSee('app.example.com')->assertSee('HTTPS 403');
        $this->get(route('domains.index', $domain->organization_id))->assertOk()->assertSee('93.184.216.34');
        $this->get(route('domains.show', [$domain->organization_id, $domain]))->assertOk()
            ->assertDontSee('HTTPS 200')->assertSee('HTTPS 403')->assertSee('app.example.com');
    }

    public function test_private_addresses_and_revoked_scopes_do_not_trigger_http_requests(): void
    {
        [$owner, $domain] = $this->registeredDomain();
        $viewer = User::factory()->create();
        Membership::create(['organization_id' => $domain->organization_id, 'user_id' => $viewer->id, 'role' => 'viewer']);
        $endpoint = route('domains.web.update', [$domain->organization_id, $domain]);
        $enable = ['enabled' => '1', 'consent' => '1'];
        $this->actingAs($viewer)->patch($endpoint, $enable)->assertForbidden();
        $this->actingAs($owner)->patch($endpoint, $enable)->assertRedirect();

        $dns = $this->mock(DnsResolver::class);
        $dns->shouldReceive('records')->with($domain->txtName(), DNS_TXT)->once()
            ->andReturn([['host' => $domain->txtName(), 'type' => 'TXT', 'txt' => $domain->txtValue()]]);
        $dns->shouldReceive('records')->with($domain->hostname, DNS_A | DNS_AAAA | DNS_CNAME)->once()
            ->andReturn([['host' => $domain->hostname, 'type' => 'A', 'ip' => '192.168.1.2']]);
        $this->mock(WebProbe::class)->shouldNotReceive('inspect');

        $job = new ProbeWebInventory($domain->id, $domain->fresh()->web_authorization_id);
        $this->app->call([$job, 'handle']);
        $this->assertDatabaseHas('web_observations', ['hostname' => $domain->hostname, 'status_code' => null, 'public_ip' => null]);

        $this->patch($endpoint, ['enabled' => '0'])->assertRedirect();
        $this->app->call([$job, 'handle']);
    }

    /** @return array{User, MonitoredDomain} */
    private function registeredDomain(): array
    {
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $domain = $workspace->monitoredDomains()->create([
            'hostname' => 'example.com', 'verification_token' => 'fixture-token',
            'verification_expires_at' => now()->addDay(),
        ]);
        $domain->forceFill(['verified_at' => now()])->save();

        return [$owner, $domain];
    }
}
