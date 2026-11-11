<?php

namespace Tests\Feature\Http\Controllers;

use App\Domain\Assets\AssetObservationChange;
use App\Domain\Assets\DiscoveredAsset;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\PassiveInventory;
use App\Domain\Assets\TlsCheck;
use App\Domain\Assets\WebObservation;
use App\Domain\Identity\Membership;
use App\Domain\Tenancy\CreateOrganization;
use App\Domain\Tenancy\Organization;
use App\Jobs\ScanPortChunk;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class AttackSurfaceControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_inventory_filters_and_history_are_limited_to_the_selected_organization(): void
    {
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'First Security', 'first-security', null);
        $otherOwner = User::factory()->create();
        $otherWorkspace = app(CreateOrganization::class)->handle($otherOwner, 'Other Security', 'other-security', null);
        $ownDomain = $this->domain($workspace, 'first-example.com');
        $otherDomain = $this->domain($otherWorkspace, 'other-example.com');
        $this->observation($ownDomain, 'A', '172.66.40.184', change: true);
        $this->observation($ownDomain, 'SUBDOMAIN', 'api.first-example.com');
        $this->observation($ownDomain, 'SUBDOMAIN', 'blocked.first-example.com');
        $this->observation($ownDomain, 'SUBDOMAIN', 'unchecked.first-example.com');
        $this->observation($ownDomain, 'SUBDOMAIN', 'stale.first-example.com');
        $this->observation($otherDomain, 'SUBDOMAIN', 'private.other-example.com', change: true);
        $this->webResult($ownDomain, 'api.first-example.com', '93.184.216.34');
        $this->webResult($ownDomain, 'blocked.first-example.com', '93.184.216.35', 403);
        $this->webResult($ownDomain, 'stale.first-example.com', '93.184.216.36')
            ->update(['checked_at' => now()->subDays(3)]);
        $this->webResult($otherDomain, 'private.other-example.com', '93.184.216.37');

        $this->actingAs($owner)->get(route('assets.inventory', ['organization' => $workspace, 'type' => 'SUBDOMAIN', 'q' => 'example.com']))
            ->assertOk()
            ->assertViewHas('assets', fn ($assets) => $assets->pluck('hostname')->all() === ['api.first-example.com', 'blocked.first-example.com'])
            ->assertViewHas('summary', ['domains' => 1, 'subdomains' => 2, 'addresses' => 2])
            ->assertSee('93.184.216.34')
            ->assertDontSee('172.66.40.184')
            ->assertDontSee('private.other-example.com');

        $this->get(route('assets.inventory', $otherWorkspace))->assertNotFound();
    }

    public function test_attack_surface_shows_organization_tls_evidence_instead_of_dns_observations(): void
    {
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'First Security', 'first-security', null);
        $otherOwner = User::factory()->create();
        $otherWorkspace = app(CreateOrganization::class)->handle($otherOwner, 'Other Security', 'other-security', null);
        $ownDomain = $this->domain($workspace, 'first-example.com');
        $otherDomain = $this->domain($otherWorkspace, 'other-example.com');
        $this->observation($ownDomain, 'SUBDOMAIN', 'inventory-only.first-example.com');
        $this->tlsEvidence($otherDomain, 'Private issuer');
        $surface = route('attack-surface', $workspace);

        $this->actingAs($owner)->get($surface)->assertOk()->assertSee('Belum ada pemeriksaan TLS')
            ->assertDontSee('inventory-only.first-example.com');
        $check = $this->tlsEvidence($ownDomain, 'Example issuer');

        $this->get($surface)->assertOk()
            ->assertViewHas('summary', ['completed' => 1, 'failed' => 0, 'pending' => 0])
            ->assertViewHas('checks', fn ($checks) => $checks->pluck('id')->all() === [$check->id])
            ->assertSee('Example issuer')->assertSee('93.184.216.34:443')->assertDontSee('Private issuer');
        $this->get(route('attack-surface.tls', [$workspace, $ownDomain]))->assertOk()->assertSee('Example issuer');
        $this->get(route('domains.show', [$workspace, $ownDomain]))->assertOk()->assertDontSee('Example issuer');
        $this->get(route('attack-surface', $otherWorkspace))->assertNotFound();
        $this->get(route('attack-surface.tls', [$workspace, $otherDomain]))->assertNotFound();
    }

    public function test_vulnerability_surface_previews_assets_and_scopes_detail_to_the_organization(): void
    {
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'First Security', 'first-security', null);
        $otherOwner = User::factory()->create();
        $otherWorkspace = app(CreateOrganization::class)->handle($otherOwner, 'Other Security', 'other-security', null);
        $ownDomain = $this->domain($workspace, 'first-example.com');
        $otherDomain = $this->domain($otherWorkspace, 'other-example.com');
        $asset = $this->observation($ownDomain, 'SUBDOMAIN', 'api.first-example.com');
        $web = $this->webResult($ownDomain, $asset->value, '93.184.216.34');
        $web->update([
            'server_header' => 'nginx/1.24.0',
            'technologies' => [
                ['name' => 'PHP', 'version' => '8.2.12', 'source' => 'header'],
                ['name' => 'Bootstrap', 'version' => '5.3.3', 'source' => 'body'],
            ],
        ]);
        $this->tlsEvidence($ownDomain, 'Example issuer');
        $ownDomain->vulnerabilityFindings()->create([
            'discovered_asset_id' => $asset->id,
            'hostname' => $asset->value,
            'severity' => 'high',
            'status' => 'open',
            'title' => 'Outdated web framework',
            'cve_id' => 'CVE-2026-1234',
            'threat_actor' => 'Example Actor',
            'detected_at' => now(),
        ]);
        $this->observation($otherDomain, 'SUBDOMAIN', 'private.other-example.com');

        $surface = route('attack-surface.vulnerabilities', ['organization' => $workspace, 'domain' => $ownDomain->id]);
        $this->actingAs($owner)->get($surface)->assertOk()
            ->assertViewHas('preview', fn (array $preview): bool => $preview['findings']->contains('cve_id', 'CVE-2026-1234')
                && $preview['ports']->contains('port', 443)
                && $preview['technologies']->contains('TLS certificate')
                && $preview['technologies']->contains('PHP 8.2.12')
                && $preview['technologies']->contains('Bootstrap 5.3.3'))
            ->assertSee('Kerentanan aset')->assertSee('first-example.com');

        $detail = route('attack-surface.vulnerabilities.detail', ['organization' => $workspace, 'domain' => $ownDomain, 'host' => $asset->value]);
        $this->get($detail)->assertOk()->assertSee('Outdated web framework')->assertSee('Example Actor');
        $this->get(route('attack-surface.vulnerabilities.detail', [$workspace, $otherDomain]))->assertNotFound();
    }

    public function test_full_port_scan_queues_all_port_chunks_only_for_an_approved_direct_ip(): void
    {
        Queue::fake();
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'First Security', 'first-security', null);
        $domain = $this->domain($workspace, 'first-example.com');
        $domain->forceFill([
            'tls_authorization_id' => fake()->uuid(),
            'tls_scope' => TlsCheck::DIRECT,
            'tls_approved_ip' => '93.184.216.34',
            'tls_approved_by' => $owner->id,
            'tls_approved_at' => now(),
        ])->save();

        $this->actingAs($owner)->post(route('attack-surface.port-scans.store', [$workspace, $domain]), ['consent' => '1'])
            ->assertRedirect()->assertSessionHas('status');

        Queue::assertPushed(ScanPortChunk::class, 256);
        $this->assertDatabaseHas('port_scan_runs', [
            'monitored_domain_id' => $domain->id,
            'target_ip' => '93.184.216.34',
            'total_ports' => 65535,
            'status' => 'queued',
        ]);

        $domain->forceFill(['tls_scope' => TlsCheck::PUBLIC_ENDPOINT, 'tls_approved_ip' => null])->save();
        $this->post(route('attack-surface.port-scans.store', [$workspace, $domain]), ['consent' => '1'])->assertConflict();
    }

    public function test_hidden_observation_stays_hidden_after_discovery_and_can_be_restored(): void
    {
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        $domain = $this->domain($workspace, 'example.com');
        $asset = $this->observation($domain, 'SUBDOMAIN', 'api.example.com', change: true);
        $this->webResult($domain, $asset->value, '93.184.216.34');
        $action = route('domains.assets.visibility', [$workspace, $domain, $asset]);
        $inventory = route('assets.inventory', $workspace);
        $hidden = route('assets.inventory', ['organization' => $workspace, 'state' => 'hidden']);

        $this->actingAs($owner)->patch($action, ['hidden' => '1', 'from_inventory' => '1'])->assertRedirect($inventory.'?state=all');
        app(PassiveInventory::class)->syncSnapshot($domain, $asset->source, [[
            'record_type' => 'SUBDOMAIN', 'value' => $asset->value, 'source' => $asset->source,
        ]]);
        $this->get($inventory)->assertOk()->assertDontSee($asset->value);
        $this->get(route('domains.show', [$workspace, $domain]))->assertOk()->assertViewHas('assets', fn ($assets) => $assets->isEmpty());
        $this->get($hidden)->assertOk()->assertSee($asset->value);
        $this->get(route('domains.show', [$workspace, $domain, 'assets' => 'hidden']))->assertOk()->assertSee('Pulihkan observasi');
        $this->patch($action, ['hidden' => '0', 'from_inventory' => '1', 'from_hidden' => '1'])->assertRedirect($hidden);
        $this->get($inventory)->assertOk()->assertSee($asset->value);
        $this->assertDatabaseHas('audit_logs', ['organization_id' => $workspace->id, 'event' => 'asset.restored']);
    }

    public function test_only_managers_can_delete_a_confirmed_import_from_the_selected_domain(): void
    {
        $owner = User::factory()->create();
        $viewer = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        Membership::create(['organization_id' => $workspace->id, 'user_id' => $viewer->id, 'role' => 'viewer']);
        $domain = $this->domain($workspace, 'example.com');
        $otherDomain = $this->domain($workspace, 'example.net');
        $import = $this->observation($domain, 'SUBDOMAIN', 'manual.example.com', source: 'manual');
        $automatic = $this->observation($domain, 'SUBDOMAIN', 'auto.example.com');
        $delete = route('domains.assets.destroy', [$workspace, $domain, $import]);

        $this->actingAs($viewer)->delete($delete, ['confirm_asset' => '1'])->assertForbidden();
        $this->patch(route('domains.assets.visibility', [$workspace, $domain, $import]), ['hidden' => '1'])->assertForbidden();
        $this->actingAs($owner)->delete(route('domains.assets.destroy', [$workspace, $otherDomain, $import]), ['confirm_asset' => '1'])->assertNotFound();
        $this->delete(route('domains.assets.destroy', [$workspace, $domain, $automatic]), ['confirm_asset' => '1'])->assertConflict();
        $this->delete($delete)->assertSessionHasErrors('confirm_asset');
        $this->delete($delete, ['confirm_asset' => '1'])->assertRedirect();

        $this->assertDatabaseMissing('discovered_assets', ['id' => $import->id]);
        $this->assertDatabaseHas('discovered_assets', ['id' => $automatic->id]);
        $this->assertDatabaseHas('audit_logs', ['organization_id' => $workspace->id, 'event' => 'asset.deleted']);
    }

    private function tlsEvidence(MonitoredDomain $domain, string $issuer): TlsCheck
    {
        return $domain->tlsChecks()->forceCreate([
            'ip_address' => '93.184.216.34',
            'authorization_id' => fake()->uuid(),
            'status' => 'completed',
            'finished_at' => now(),
            'result' => ['protocol' => 'TLSv1.3', 'issuer' => $issuer, 'expires_at' => now()->addMonth()->timestamp],
        ]);
    }

    private function webResult(MonitoredDomain $domain, string $hostname, string $ip, int $status = 200): WebObservation
    {
        if ($domain->web_authorization_id === null) {
            $domain->forceFill(['web_authorization_id' => fake()->uuid()])->save();
        }

        return $domain->webObservations()->create([
            'hostname' => $hostname, 'public_ip' => $ip, 'scheme' => 'https', 'status_code' => $status,
            'authorization_id' => $domain->web_authorization_id, 'checked_at' => now(),
        ]);
    }

    private function domain(Organization $workspace, string $hostname): MonitoredDomain
    {
        $domain = $workspace->monitoredDomains()->create([
            'hostname' => $hostname,
            'verification_token' => 'fixture-token',
            'verification_expires_at' => now()->addDay(),
        ]);
        $domain->forceFill(['verified_at' => now()])->save();

        return $domain;
    }

    private function observation(MonitoredDomain $domain, string $type, string $value, bool $change = false, ?string $source = null): DiscoveredAsset
    {
        $asset = $domain->assets()->forceCreate([
            'record_type' => $type,
            'value' => $value,
            'source' => $source ?? ($type === 'SUBDOMAIN' ? 'certspotter' : 'dns'),
            'first_seen_at' => now(),
            'last_seen_at' => now(),
        ]);
        if ($change) {
            AssetObservationChange::insert(['discovered_asset_id' => $asset->id, 'event' => 'added', 'occurred_at' => now()]);
        }

        return $asset;
    }
}
