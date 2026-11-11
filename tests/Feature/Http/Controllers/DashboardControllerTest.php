<?php

namespace Tests\Feature\Http\Controllers;

use App\Domain\Audit\AuditLogger;
use App\Domain\Identity\Membership;
use App\Domain\Tenancy\CreateOrganization;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\DB;
use Tests\TestCase;

class DashboardControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_owner_can_view_their_persisted_organization_and_activity(): void
    {
        $owner = User::factory()->create();
        $organization = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);

        $this->actingAs($owner)->get(route('dashboard', ['organization' => $organization->id]))
            ->assertOk()
            ->assertSee('Example Security')
            ->assertSee('Organisasi dibuat');
    }

    public function test_returns_404_for_an_organization_the_user_does_not_belong_to(): void
    {
        $owner = User::factory()->create();
        $organization = app(CreateOrganization::class)->handle($owner, 'Private Organization', 'private-org', null);
        $outsider = User::factory()->create();

        $this->actingAs($outsider)->get(route('dashboard', ['organization' => $organization->id]))
            ->assertNotFound();
    }

    public function test_a_viewer_can_open_their_workspace_without_access_to_audit_logs(): void
    {
        $owner = User::factory()->create();
        $viewer = User::factory()->create();
        $organization = app(CreateOrganization::class)->handle($owner, 'Example Security', 'example-security', null);
        Membership::create(['organization_id' => $organization->id, 'user_id' => $viewer->id, 'role' => 'viewer']);

        $this->actingAs($viewer)->get(route('dashboard'))
            ->assertOk()
            ->assertSee('Example Security')
            ->assertDontSee('Organisasi dibuat');
    }

    public function test_postgresql_hides_audit_rows_without_scope_and_rejects_a_foreign_tenant_scope(): void
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            $this->markTestSkipped('Requires a dedicated PostgreSQL test database.');
        }

        $owner = User::factory()->create();
        $outsider = User::factory()->create();
        $organization = app(CreateOrganization::class)->handle($owner, 'Private Organization', 'private-org', null);

        $this->assertDatabaseCount('audit_logs', 0);
        $this->assertCount(0, app(AuditLogger::class)->recent($organization->id, $outsider->id));
        $this->assertCount(1, app(AuditLogger::class)->recent($organization->id, $owner->id));
    }

    public function test_audit_service_hides_entries_from_users_without_a_privileged_membership(): void
    {
        $owner = User::factory()->create();
        $outsider = User::factory()->create();
        $organization = app(CreateOrganization::class)->handle($owner, 'Private Organization', 'private-org', null);

        $activity = app(AuditLogger::class)->recent($organization->id, $outsider->id);

        $this->assertCount(0, $activity);
    }
}
