<?php

namespace Tests\Feature\Http\Controllers;

use App\Domain\Audit\AuditLogger;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

class OrganizationControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_returns_201_and_assigns_ownership_to_the_authenticated_creator(): void
    {
        $user = User::factory()->create();

        $response = $this->actingAs($user)->postJson(route('organizations.store'), [
            'name' => 'Example Security',
            'slug' => 'example-security',
            'role' => 'admin',
            'subscription_status' => 'enterprise',
        ]);

        $response->assertCreated()->assertJsonPath('slug', 'example-security');
        $organizationId = $response->json('id');
        $this->assertDatabaseHas('organizations', ['id' => $organizationId, 'subscription_status' => 'trial']);
        $this->assertDatabaseHas('memberships', ['organization_id' => $organizationId, 'user_id' => $user->id, 'role' => 'owner']);
        $this->assertSame(['organization.created'], app(AuditLogger::class)->recent($organizationId, $user->id)->pluck('event')->all());
    }

    public function test_returns_401_for_a_guest_attempting_to_create_an_organization(): void
    {
        $this->postJson(route('organizations.store'), [
            'name' => 'Example Security',
            'slug' => 'example-security',
        ])->assertUnauthorized();

        $this->assertDatabaseCount('organizations', 0);
    }
}
