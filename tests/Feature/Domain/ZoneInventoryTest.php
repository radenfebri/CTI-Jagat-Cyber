<?php

namespace Tests\Feature\Domain;

use App\Domain\Assets\CloudflareZoneInventory;
use App\Domain\Assets\DnsResolver;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Tenancy\CreateOrganization;
use App\Jobs\DiscoverDomainAssets;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Http\UploadedFile;
use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class ZoneInventoryTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_owner_can_import_unique_subdomains_without_accepting_other_zones(): void
    {
        [$owner, $domain] = $this->domain();
        $url = route('domains.hostnames.store', [$domain->organization_id, $domain]);

        $this->actingAs($owner)->post($url, ['hostnames' => "api\nother.example.net"])->assertSessionHasErrors('hostnames');
        $this->assertDatabaseCount('discovered_assets', 0);

        $this->post($url, ['hostnames' => "api\nAPI.example.com.\nadmin.example.com"])->assertRedirect();

        $this->assertSame(['admin.example.com', 'api.example.com'], $domain->assets()->where('source', 'manual')->orderBy('value')->pluck('value')->all());
        $this->get(route('domains.show', [$domain->organization_id, $domain]))->assertOk()->assertDontSee('admin.example.com');
        $this->actingAs(User::factory()->create())->post($url, ['hostnames' => 'private'])->assertNotFound();
    }

    public function test_cloudflare_connection_is_stored_per_domain_with_an_encrypted_token(): void
    {
        [$owner, $domain] = $this->domain();
        $zoneId = str_repeat('b', 32);

        $this->actingAs($owner)->patch(route('domains.cloudflare.update', [$domain->organization_id, $domain]), [
            'enabled' => '1',
            'zone_id' => $zoneId,
            'api_token' => 'test-token',
        ])->assertRedirectToRoute('domains.show', [$domain->organization_id, $domain]);

        $domain->refresh();
        $this->assertSame($zoneId, $domain->cloudflare_zone_id);
        $this->assertSame('test-token', $domain->cloudflare_api_token);
        $this->assertDatabaseMissing('monitored_domains', ['id' => $domain->id, 'cloudflare_api_token' => 'test-token']);
        $this->assertTrue(app(CloudflareZoneInventory::class)->configuredFor($domain));

        $otherOwner = User::factory()->create();
        app(CreateOrganization::class)->handle($otherOwner, 'Other Security', 'other-security', null);
        $this->actingAs($otherOwner)->patch(route('domains.cloudflare.update', [$domain->organization_id, $domain]), [
            'enabled' => '1',
            'zone_id' => $zoneId,
            'api_token' => 'other-token',
        ])->assertNotFound();
    }

    public function test_zone_reader_paginates_and_excludes_foreign_wildcard_and_private_names(): void
    {
        [, $domain] = $this->domain();
        $domain->forceFill(['cloudflare_zone_id' => str_repeat('a', 32), 'cloudflare_api_token' => 'test-token'])->save();
        Http::preventStrayRequests();
        Http::fake(['api.cloudflare.com/*' => Http::sequence()
            ->push(['success' => true, 'result_info' => ['page' => 1, 'total_pages' => 2],
                'result' => [['name' => 'example.com'], ['name' => '*.example.com'], ['name' => 'api.example.com']]])
            ->push(['success' => true, 'result_info' => ['page' => 2, 'total_pages' => 2],
                'result' => [['name' => 'admin.example.com'], ['name' => 'outside.net'], ['name' => 'internal.example.com', 'private_routing' => true]]])]);

        $this->assertSame(['api.example.com', 'admin.example.com'], app(CloudflareZoneInventory::class)->read($domain));
        Http::assertSentCount(2);
    }

    public function test_verified_domain_accepts_a_bind_export_without_a_cloudflare_connector(): void
    {
        [$owner, $domain] = $this->domain();
        Queue::fake();
        Http::preventStrayRequests();
        $url = route('domains.zone-file.store', [$domain->organization_id, $domain]);
        $contents = <<<'ZONE'
            $ORIGIN example.com.
            $TTL 1h
            @ IN SOA ns.example.com. admin.example.com. (
                2026110801 1h 1h 1w 1h ) ; zone metadata
            api 300 IN A 192.0.2.5
                IN AAAA 2001:db8::5
            API.example.com. IN TXT "record; content (do not store)"
            *.example.com. IN CNAME api
            _acme-challenge IN TXT "fixture-secret"
            outside.net. IN A 192.0.2.6
            $ORIGIN staging.example.com.
            dashboard IN 1h CNAME api.example.com.
            ZONE;

        $this->actingAs($owner)->post($url, ['zone_file' => UploadedFile::fake()->createWithContent('zone.txt', $contents)])
            ->assertRedirectToRoute('domains.show', [$domain->organization_id, $domain, 'assets' => 'subdomains']);
        $this->post($url, ['zone_file' => UploadedFile::fake()->createWithContent('partial.txt', 'api IN A 192.0.2.7')])
            ->assertSessionHasNoErrors();

        $this->assertSame(
            ['api.example.com', 'dashboard.staging.example.com'],
            $domain->assets()->where('source', 'zone_file')->whereNull('retired_at')->orderBy('value')->pluck('value')->all(),
        );
        $this->assertDatabaseCount('discovered_assets', 2);
        $this->get(route('domains.show', [$domain->organization_id, $domain]))->assertOk()->assertSee('Import BIND zone');
        Queue::assertNothingPushed();
    }

    public function test_zone_file_import_requires_membership_verification_and_supported_records(): void
    {
        [$owner, $domain] = $this->domain();
        $url = route('domains.zone-file.store', [$domain->organization_id, $domain]);
        $this->actingAs(User::factory()->create())->post($url, [
            'zone_file' => UploadedFile::fake()->createWithContent('zone.txt', 'api IN A 192.0.2.5'),
        ])->assertNotFound();
        $this->actingAs($owner)->post($url, [
            'zone_file' => UploadedFile::fake()->createWithContent('zone.txt', "api IN A 192.0.2.5\n".'$INCLUDE another.zone'),
        ])->assertSessionHasErrors('zone_file');
        $domain->forceFill(['verified_at' => null])->save();
        $this->post($url, ['zone_file' => UploadedFile::fake()->createWithContent('zone.txt', 'api IN A 192.0.2.5')])
            ->assertConflict();

        $this->assertDatabaseCount('discovered_assets', 0);
    }

    public function test_worker_saves_zone_names_and_preserves_them_when_a_manual_refresh_fails(): void
    {
        [$owner, $domain] = $this->domain();
        $domain->forceFill(['cloudflare_zone_id' => str_repeat('a', 32), 'cloudflare_api_token' => 'test-token'])->save();
        Queue::fake();
        Http::preventStrayRequests();
        Http::fake(['api.cloudflare.com/*' => Http::sequence()
            ->push(['success' => true, 'result_info' => ['page' => 1, 'total_pages' => 1],
                'result' => [['name' => 'example.com'], ['name' => 'api.example.com']]])
            ->push(['success' => false], 429)]);
        $this->mock(DnsResolver::class, function ($dns) use ($domain): void {
            $dns->shouldReceive('records')->with($domain->txtName(), DNS_TXT)
                ->andReturn([['host' => $domain->txtName(), 'type' => 'TXT', 'txt' => $domain->txtValue()]]);
            $dns->shouldReceive('records')->with($domain->hostname, DNS_A | DNS_AAAA | DNS_CNAME)->andReturn([]);
        });

        $this->actingAs($owner)->post(route('domains.approve', [$domain->organization_id, $domain]), ['consent' => '1'])->assertRedirect();
        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->sole(), 'handle']);
        $this->assertSame('complete', $domain->refresh()->zone_status);

        $this->travel(11)->minutes();
        $this->post(route('domains.discover', [$domain->organization_id, $domain]))->assertRedirect();
        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->last(), 'handle']);

        $this->assertSame('unavailable', $domain->refresh()->zone_status);
        $this->assertDatabaseHas('discovered_assets', ['monitored_domain_id' => $domain->id, 'source' => 'cloudflare_zone', 'value' => 'api.example.com', 'retired_at' => null]);
        Http::assertSentCount(2);
    }

    /** @return array{User, MonitoredDomain} */
    private function domain(): array
    {
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $domain = $workspace->monitoredDomains()->create([
            'hostname' => 'example.com', 'verification_token' => 'fixture-token', 'verification_expires_at' => now()->addDay(),
        ]);
        $domain->forceFill(['verified_at' => now()])->save();

        return [$owner, $domain];
    }
}
