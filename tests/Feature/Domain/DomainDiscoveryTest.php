<?php

namespace Tests\Feature\Domain;

use App\Domain\Assets\AssetObservationChange;
use App\Domain\Assets\AuthoritativeTxt;
use App\Domain\Assets\DnsResolver;
use App\Domain\Assets\DomainJobDispatcher;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Tenancy\CreateOrganization;
use App\Domain\Tenancy\Organization;
use App\Jobs\DiscoverDomainAssets;
use App\Jobs\ProbeDomainTls;
use App\Jobs\ProbeWebInventory;
use App\Jobs\VerifyDomainOwnership;
use App\Models\User;
use Closure;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class DomainDiscoveryTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_database_queue_worker_completes_verification_and_passive_discovery(): void
    {
        config(['queue.default' => 'database']);
        [$owner, $workspace, $domain] = $this->registeredDomain();
        $this->useDns(fn ($host, $type) => $type === DNS_TXT ? [$this->proof($domain)] : [
            ['type' => 'AAAA', 'host' => $host, 'ipv6' => '2001:0db8::1'],
        ]);
        $workerOptions = ['--once' => true, '--queue' => 'cti', '--sleep' => 0];

        $this->actingAs($owner)->post(route('domains.verify', [$workspace, $domain]))->assertRedirect();
        $this->assertDatabaseHas('jobs', ['queue' => 'cti']);
        $this->artisan('queue:work', $workerOptions)->assertSuccessful();
        $this->assertNotNull($domain->refresh()->verified_at);

        $this->post(route('domains.approve', [$workspace, $domain]), ['consent' => '1'])->assertRedirect();
        $this->assertDatabaseHas('jobs', ['queue' => 'cti']);
        $this->artisan('queue:work', $workerOptions)->assertSuccessful();

        $this->assertDatabaseCount('jobs', 0);
        $this->assertDatabaseHas('discovered_assets', ['monitored_domain_id' => $domain->id, 'value' => '2001:db8::1']);
    }

    public function test_verification_uses_only_the_current_token_at_the_exact_dns_owner(): void
    {
        [, , $domain] = $this->registeredDomain();
        $job = new VerifyDomainOwnership($domain->organization_id, $domain->id, hash('sha256', $domain->verification_token));
        $this->useDns(fn () => [['type' => 'TXT', 'host' => 'other.example.com', 'txt' => $domain->txtValue()]]);

        $this->app->call([$job, 'handle']);
        $this->assertNull($domain->refresh()->verified_at);
        $this->assertSame('not_found', $domain->verification_status);

        $this->useDns(fn () => [['type' => 'TXT', 'host' => $domain->txtName(), 'entries' => ['cti-jagat-cyber=', $domain->verification_token]]]);
        $this->app->call([$job, 'handle']);
        $this->assertNotNull($domain->refresh()->verified_at);
        $this->assertSame('verified', $domain->verification_status);
    }

    public function test_verification_can_use_the_configured_nameserver_for_its_exact_domain(): void
    {
        [, , $domain] = $this->registeredDomain();
        $this->useDns(fn () => []);
        $this->partialMock(AuthoritativeTxt::class)->shouldAllowMockingProtectedMethods()
            ->shouldReceive('exchange')->once()->with('1.1.1.1', \Mockery::type('string'))
            ->andReturnUsing(function (string $server, string $query) use ($domain): string {
                $token = $domain->verification_token;
                $txt = "\x10cti-jagat-cyber=".chr(strlen($token)).$token;

                return substr($query, 0, 2).pack('n5', 0x8400, 1, 1, 0, 0).substr($query, 12)
                    ."\xc0\x0c".pack('nnNn', 16, 1, 300, strlen($txt)).$txt;
            });
        $job = new VerifyDomainOwnership($domain->organization_id, $domain->id, hash('sha256', $domain->verification_token));

        config(['cti.txt_authority' => ['zone' => 'another.example.com', 'server' => '1.1.1.1']]);
        $this->app->call([$job, 'handle']);
        $this->assertSame('not_found', $domain->refresh()->verification_status);
        config(['cti.txt_authority.zone' => $domain->hostname]);
        $this->app->call([$job, 'handle']);
        $this->assertSame('verified', $domain->refresh()->verification_status);
        $this->assertNotNull($domain->verified_at);
    }

    public function test_discovery_saves_real_observations_and_retires_records_missing_from_a_later_result(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->registeredDomain(verified: true);
        $this->actingAs($owner)->post(route('domains.approve', [$workspace, $domain]), ['consent' => '1'])->assertRedirectToRoute('domains.show', [$workspace, $domain]);
        Queue::assertPushedOn('cti', DiscoverDomainAssets::class);
        $this->useDns(fn ($host, $type) => $type === DNS_TXT ? [$this->proof($domain)] : [
            ['type' => 'A', 'host' => $host, 'ip' => '192.0.2.4'],
            ['type' => 'A', 'host' => $host, 'ip' => '192.0.2.4'],
            ['type' => 'CNAME', 'host' => $host, 'target' => 'edge.example.net.'],
            ['type' => 'A', 'host' => 'edge.example.net', 'ip' => '192.0.2.5'],
        ]);
        $job = Queue::pushed(DiscoverDomainAssets::class)->sole();
        $this->app->call([$job, 'handle']);
        $this->app->call([$job, 'handle']);

        $this->assertDatabaseCount('discovered_assets', 2);
        $this->assertDatabaseHas('discovered_assets', ['monitored_domain_id' => $domain->id, 'value' => 'edge.example.net', 'retired_at' => null]);
        $this->assertDatabaseHas('domain_scan_policies', ['monitored_domain_id' => $domain->id, 'last_status' => 'completed']);

        $this->travel(11)->minutes();
        $this->assertTrue(app(DomainJobDispatcher::class)->discover($domain, manual: true));
        $this->useDns(fn ($host, $type) => $type === DNS_TXT ? [$this->proof($domain)] : [['type' => 'A', 'host' => $host, 'ip' => '192.0.2.6']]);
        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->last(), 'handle']);

        $this->assertSame(3, $domain->assets()->count());
        $this->assertSame(['192.0.2.6'], $domain->assets()->whereNull('retired_at')->pluck('value')->all());
        $this->get(route('domains.show', [$workspace, $domain]))->assertOk()->assertDontSee('192.0.2.6');
    }

    public function test_revoke_during_dns_lookup_prevents_persisting_results(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->registeredDomain(verified: true);
        $this->actingAs($owner)->post(route('domains.approve', [$workspace, $domain]), ['consent' => '1'])->assertRedirect();
        $job = Queue::pushed(DiscoverDomainAssets::class)->sole();
        $this->useDns(function ($host, $type) use ($workspace, $domain) {
            if ($type === DNS_TXT) {
                return [$this->proof($domain)];
            }

            $this->delete(route('domains.revoke', [$workspace, $domain]))->assertRedirect();

            return [['type' => 'A', 'host' => $host, 'ip' => '192.0.2.4']];
        });

        $this->app->call([$job, 'handle']);

        $this->assertDatabaseCount('discovered_assets', 0);
        $this->assertDatabaseHas('domain_scan_policies', ['monitored_domain_id' => $domain->id, 'last_status' => 'cancelled']);
    }

    public function test_worker_records_only_changes_when_dns_entries_disappear_and_return(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->registeredDomain(verified: true);
        $this->actingAs($owner)->post(route('domains.approve', [$workspace, $domain]), ['consent' => '1'])->assertRedirect();

        foreach ([true, true, false, true] as $index => $present) {
            if ($index > 0) {
                $this->travel(11)->minutes();
                $this->assertTrue(app(DomainJobDispatcher::class)->discover($domain, manual: true));
            }
            $this->useDns(fn ($hostname, $type) => $type === DNS_TXT ? [$this->proof($domain)] : ($present
                ? [['type' => 'A', 'host' => $hostname, 'ip' => '192.0.2.7']]
                : []));
            $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->last(), 'handle']);
        }

        $asset = $domain->assets()->sole();
        $this->assertNull($asset->retired_at);
        $this->assertSame(['added', 'removed', 'returned'], AssetObservationChange::query()
            ->where('discovered_asset_id', $asset->id)->orderBy('id')->pluck('event')->all());
    }

    public function test_missing_proof_revokes_the_policy_and_requires_new_approval(): void
    {
        Queue::fake();
        [$owner, $workspace, $domain] = $this->registeredDomain(verified: true);
        $this->actingAs($owner)->post(route('domains.approve', [$workspace, $domain]), ['consent' => '1'])->assertRedirect();
        $this->useDns(function ($host, $type): array {
            $this->assertSame(DNS_TXT, $type);

            return [];
        });

        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->sole(), 'handle']);

        $this->assertNull($domain->refresh()->verified_at);
        $this->assertNotNull($domain->scanPolicy->revoked_at);
        $this->assertDatabaseCount('discovered_assets', 0);
    }

    public function test_scheduler_deduplicates_due_work_and_worker_skips_suspended_tenants(): void
    {
        Queue::fake();
        [$owner, $workspace, $verified] = $this->registeredDomain('verified-example.com', verified: true);
        $this->registeredDomain('pending-example.com');
        $this->actingAs($owner)->post(route('domains.approve', [$workspace, $verified]), ['consent' => '1'])->assertRedirect();
        $verified->scanPolicy()->update(['next_run_at' => now()]);

        $this->artisan('cti:dispatch-domain-jobs')->assertSuccessful();
        $this->artisan('cti:dispatch-domain-jobs')->assertSuccessful();
        Queue::assertPushed(DiscoverDomainAssets::class, 1);
        Queue::assertPushed(VerifyDomainOwnership::class, 1);
        $workspace->update(['subscription_status' => 'suspended']);
        $this->useDns(fn () => $this->fail('A suspended tenant must not run a DNS lookup.'));

        $this->app->call([Queue::pushed(DiscoverDomainAssets::class)->sole(), 'handle']);

        $this->assertDatabaseHas('domain_scan_policies', ['monitored_domain_id' => $verified->id, 'last_status' => 'skipped']);
    }

    public function test_scheduler_automatically_starts_coverage_for_a_verified_domain(): void
    {
        Queue::fake();
        [$owner, , $domain] = $this->registeredDomain(verified: true);

        $this->artisan('cti:dispatch-domain-jobs')->assertSuccessful();

        Queue::assertPushed(DiscoverDomainAssets::class);
        Queue::assertPushed(ProbeDomainTls::class);
        Queue::assertPushed(ProbeWebInventory::class);
        $this->assertDatabaseHas('domain_scan_policies', [
            'monitored_domain_id' => $domain->id,
            'approved_by' => $owner->id,
            'revoked_at' => null,
        ]);
        $domain->refresh();
        $this->assertNotNull($domain->ct_authorization_id);
        $this->assertNotNull($domain->web_authorization_id);
        $this->assertNotNull($domain->tls_authorization_id);
        $this->assertSame('public_endpoint', $domain->tls_scope);
    }

    /** @return array{User, Organization, MonitoredDomain} */
    private function registeredDomain(string $hostname = 'example.com', bool $verified = false): array
    {
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, 'Example Security', $hostname, null);
        $domain = $workspace->monitoredDomains()->create([
            'hostname' => $hostname,
            'verification_token' => 'unique-challenge-for-testing',
            'verification_expires_at' => now()->addDay(),
        ]);

        if ($verified) {
            $domain->forceFill(['verified_at' => now(), 'verification_status' => 'verified'])->save();
        }

        return [$owner, $workspace, $domain];
    }

    /** @return array{type: string, host: string, txt: string} */
    private function proof(MonitoredDomain $domain): array
    {
        return ['type' => 'TXT', 'host' => $domain->txtName(), 'txt' => $domain->txtValue()];
    }

    private function useDns(Closure $resolve): void
    {
        $this->app->instance(DnsResolver::class, new class($resolve) implements DnsResolver
        {
            public function __construct(private Closure $resolve) {}

            public function records(string $hostname, int $type): array
            {
                return ($this->resolve)($hostname, $type);
            }
        });
    }
}
