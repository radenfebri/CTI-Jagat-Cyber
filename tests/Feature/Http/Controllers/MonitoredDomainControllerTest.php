<?php

namespace Tests\Feature\Http\Controllers;

use App\Domain\Assets\AssetObservationChange;
use App\Domain\Assets\DnsResolver;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Identity\Membership;
use App\Domain\Tenancy\CreateOrganization;
use App\Jobs\DiscoverDomainAssets;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class MonitoredDomainControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_owner_registers_a_normalized_domain_and_starts_automatic_discovery(): void
    {
        Queue::fake();
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);

        $response = $this->actingAs($owner)->post(route('domains.store', $workspace), ['hostname' => 'Example.COM.']);

        $domain = $workspace->monitoredDomains()->firstOrFail();
        $response->assertRedirectToRoute('domains.show', [$workspace, $domain]);
        $this->assertSame('example.com', $domain->hostname);
        $this->assertSame('auto_registered', $domain->verification_status);
        $this->assertNotNull($domain->verified_at);
        $this->assertDatabaseHas('audit_logs', ['organization_id' => $workspace->id, 'event' => 'domain.registered']);
        $this->get(route('domains.show', [$workspace, $domain]))->assertOk()
            ->assertSee('Automatic discovery is active')->assertDontSee('Verify TXT');
    }

    public function test_registration_rejects_urls_and_duplicate_normalized_hostnames(): void
    {
        Queue::fake();
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $this->actingAs($owner)->post(route('domains.store', $workspace), ['hostname' => 'example.com'])->assertRedirect();

        $this->post(route('domains.store', $workspace), ['hostname' => 'https://example.com/'])->assertSessionHasErrors('hostname');
        $this->post(route('domains.store', $workspace), ['hostname' => 'EXAMPLE.COM.'])->assertSessionHasErrors('hostname');

        $this->assertDatabaseCount('monitored_domains', 1);
    }

    public function test_domain_list_shows_the_number_of_discovered_subdomains(): void
    {
        Queue::fake();
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $this->actingAs($owner)->post(route('domains.store', $workspace), ['hostname' => 'example.com'])->assertRedirect();
        $domain = $workspace->monitoredDomains()->firstOrFail();

        $domain->assets()->forceCreate([
            'record_type' => 'SUBDOMAIN',
            'value' => 'app.example.com',
            'source' => 'manual',
            'first_seen_at' => now(),
            'last_seen_at' => now(),
        ]);

        $this->get(route('domains.index', $workspace))
            ->assertOk()
            ->assertSee('1 discovered')
            ->assertSee('0 responsive');
    }

    public function test_domain_detail_groups_the_same_subdomain_across_discovery_sources(): void
    {
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $domain = $workspace->monitoredDomains()->create([
            'hostname' => 'example.com',
            'verification_token' => 'fixture-token',
            'verification_expires_at' => now()->addDay(),
            'verified_at' => now(),
        ]);
        $domain->forceFill(['web_authorization_id' => fake()->uuid()])->save();

        foreach (['cloudflare_zone', 'manual'] as $source) {
            $domain->assets()->forceCreate([
                'record_type' => 'SUBDOMAIN',
                'value' => 'app.example.com',
                'source' => $source,
                'first_seen_at' => now(),
                'last_seen_at' => now(),
            ]);
        }

        $domain->webObservations()->create([
            'hostname' => 'app.example.com',
            'public_ip' => '93.184.216.34',
            'scheme' => 'https',
            'status_code' => 200,
            'authorization_id' => $domain->web_authorization_id,
            'checked_at' => now(),
        ]);

        $response = $this->actingAs($owner)->get(route('domains.show', [$workspace, $domain]));

        $response->assertOk()->assertViewHas('assets', function ($assets): bool {
            if ($assets->total() !== 1) {
                return false;
            }

            $labels = $assets->first()->source_labels;

            return str_contains($labels, 'Cloudflare DNS Zone') && str_contains($labels, 'Hostname Import');
        })->assertSee('Delete app.example.com')->assertDontSee('Manage subdomain')->assertDontSee('Hidden');

        $this->actingAs($owner)->get(route('domains.show', [$workspace, $domain]).'?q=app')
            ->assertOk()
            ->assertViewHas('assets', fn ($assets) => $assets->total() === 1);

        $this->actingAs($owner)->get(route('domains.show', [$workspace, $domain]).'?q=missing')
            ->assertOk()
            ->assertViewHas('assets', fn ($assets) => $assets->isEmpty());
    }

    public function test_viewer_cannot_manage_domains_and_another_tenant_gets_404(): void
    {
        Queue::fake();
        $owner = User::factory()->create();
        $viewer = User::factory()->create();
        $outsider = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $unrelated = app(CreateOrganization::class)->handle($outsider, 'Other Security', 'other-security', null);
        Membership::create(['organization_id' => $workspace->id, 'user_id' => $viewer->id, 'role' => 'viewer']);
        $this->actingAs($owner)->post(route('domains.store', $workspace), ['hostname' => 'example.com'])->assertRedirect();
        $domain = $workspace->monitoredDomains()->firstOrFail();

        $this->actingAs($viewer)->get(route('domains.show', [$workspace, $domain]))->assertOk()->assertDontSee($domain->txtValue());
        $this->post(route('domains.verify', [$workspace, $domain]))->assertForbidden();
        $this->delete(route('domains.destroy', [$workspace, $domain]), ['delete_confirmation' => $domain->hostname])->assertForbidden();
        $this->actingAs($outsider)->get(route('domains.index', $workspace))->assertNotFound();
        $this->post(route('domains.verify', [$unrelated, $domain]))->assertNotFound();
        $this->delete(route('domains.destroy', [$unrelated, $domain]), ['delete_confirmation' => $domain->hostname])->assertNotFound();
    }

    public function test_registration_starts_passive_coverage_without_txt_verification(): void
    {
        Queue::fake();
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $this->actingAs($owner)->post(route('domains.store', $workspace), ['hostname' => 'example.com'])->assertRedirect();
        $domain = MonitoredDomain::firstOrFail();

        $this->assertDatabaseHas('domain_scan_policies', ['monitored_domain_id' => $domain->id, 'revoked_at' => null]);
        Queue::assertPushed(DiscoverDomainAssets::class);
    }

    public function test_domain_deletion_requires_its_name_and_prevents_queued_discovery_from_running(): void
    {
        Queue::fake();
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $this->actingAs($owner)->post(route('domains.store', $workspace), ['hostname' => 'example.com'])->assertRedirect();
        $domain = $workspace->monitoredDomains()->firstOrFail();
        $domain->forceFill(['verified_at' => now()])->save();
        $asset = $domain->assets()->forceCreate([
            'record_type' => 'A', 'value' => '93.184.216.34', 'source' => 'dns',
            'first_seen_at' => now(), 'last_seen_at' => now(),
        ]);
        AssetObservationChange::insert(['discovered_asset_id' => $asset->id, 'event' => 'added', 'occurred_at' => now()]);
        $domain->tlsChecks()->create([
            'requested_by' => $owner->id, 'authorization_id' => fake()->uuid(),
            'ip_address' => '93.184.216.34', 'status' => 'completed',
        ]);
        $this->post(route('domains.approve', [$workspace, $domain]), ['consent' => '1'])->assertRedirect();
        $this->mock(DnsResolver::class, fn ($dns) => $dns->shouldNotReceive('records'));
        $url = route('domains.destroy', [$workspace, $domain]);

        $this->get(route('domains.show', [$workspace, $domain]))->assertOk()->assertSee('Delete Domain');
        $this->delete($url, ['delete_confirmation' => 'another.example.com'])->assertSessionHasErrors('delete_confirmation');
        $this->assertDatabaseHas('monitored_domains', ['id' => $domain->id]);
        $this->delete($url, ['delete_confirmation' => $domain->hostname])->assertRedirectToRoute('domains.index', $workspace);
        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->sole(), 'handle']);

        $this->assertDatabaseMissing('monitored_domains', ['id' => $domain->id]);
        $this->assertDatabaseMissing('domain_scan_policies', ['monitored_domain_id' => $domain->id]);
        $this->assertDatabaseMissing('discovered_assets', ['id' => $asset->id]);
        $this->assertDatabaseMissing('asset_observation_changes', ['discovered_asset_id' => $asset->id]);
        $this->assertDatabaseMissing('tls_checks', ['monitored_domain_id' => $domain->id]);
        $this->assertDatabaseHas('audit_logs', ['organization_id' => $workspace->id, 'event' => 'domain.deleted']);
    }
}
