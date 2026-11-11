<?php

namespace Tests\Feature\Http\Controllers;

use App\Domain\Assets\DnsResolver;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Tenancy\CreateOrganization;
use App\Jobs\VerifyDomainOwnership;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Artisan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Queue;
use Tests\TestCase;

class CtiCronControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_cron_rejects_missing_or_invalid_credentials_and_head_requests(): void
    {
        $token = str_repeat('a', 64);
        config(['cti.cron_token' => $token]);
        Artisan::shouldReceive('call')->never();

        $this->get(route('cti.cron'))->assertNotFound();
        $this->get(route('cti.cron', ['token' => str_repeat('b', 64)]))->assertNotFound();
        $this->get(route('cti.cron', ['token' => ['x']]))->assertNotFound();
        $this->call('HEAD', route('cti.cron', ['token' => $token]))->assertStatus(405);

        config(['cti.cron_token' => '']);
        $this->get(route('cti.cron', ['token' => $token]))->assertNotFound();
    }

    public function test_url_dispatches_a_due_domain_and_processes_it_without_a_separate_worker(): void
    {
        $domain = $this->pendingDomain('example.com');
        $this->expectTxtLookup($domain);
        $url = $this->cronUrl();

        $lock = Cache::lock('cti:cron-url', 120);
        $lock->get();
        try {
            $this->get($url)->assertAccepted()->assertJsonPath('status', 'already_running');
            $this->assertNull($domain->fresh()->verified_at);
        } finally {
            $lock->release();
        }

        $this->get($url)->assertOk()->assertJsonPath('status', 'tick_completed');

        $this->assertNotNull($domain->fresh()->verified_at);
        $this->assertDatabaseCount('jobs', 0);
    }

    public function test_cron_processes_one_cti_job_and_leaves_other_queues_untouched(): void
    {
        $url = $this->cronUrl();
        $first = $this->pendingDomain('first.example.com');
        $second = $this->pendingDomain('second.example.com');
        $this->expectTxtLookup($first);

        Queue::push(new VerifyDomainOwnership($second->organization_id, $second->id, hash('sha256', $second->verification_token)), queue: 'default');
        foreach ([$first, $second] as $domain) {
            Queue::push(new VerifyDomainOwnership($domain->organization_id, $domain->id, hash('sha256', $domain->verification_token)), queue: 'cti');
        }

        $this->get($url)->assertOk()->assertJsonPath('status', 'tick_completed');

        $this->assertNotNull($first->fresh()->verified_at);
        $this->assertNull($second->fresh()->verified_at);
        $this->assertDatabaseCount('jobs', 2);
        $this->assertDatabaseHas('jobs', ['queue' => 'default']);
        $this->assertDatabaseHas('jobs', ['queue' => 'cti']);
    }

    private function cronUrl(): string
    {
        $token = str_repeat('a', 64);
        config(['cti.cron_token' => $token, 'queue.default' => 'database']);

        return route('cti.cron', ['token' => $token]);
    }

    private function pendingDomain(string $hostname): MonitoredDomain
    {
        $owner = User::factory()->create();
        $workspace = app(CreateOrganization::class)->handle($owner, $hostname, str_replace('.', '-', $hostname), null);

        return $workspace->monitoredDomains()->create([
            'hostname' => $hostname,
            'verification_token' => 'fixture-token',
            'verification_expires_at' => now()->addHour(),
        ]);
    }

    private function expectTxtLookup(MonitoredDomain $domain): void
    {
        $this->mock(DnsResolver::class)->shouldReceive('records')->once()
            ->with($domain->txtName(), DNS_TXT)
            ->andReturn([['host' => $domain->txtName(), 'type' => 'TXT', 'txt' => $domain->txtValue()]]);
    }
}
