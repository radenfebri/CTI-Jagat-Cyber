<?php

namespace Tests\Feature\Http\Controllers;

use App\Domain\Audit\AuditLogger;
use App\Domain\Tenancy\Organization;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use RuntimeException;
use Tests\TestCase;

class AuthControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_registration_page_renders_the_organization_field(): void
    {
        $this->get(route('register'))
            ->assertOk()
            ->assertSee('name="organization_name"', false);
    }

    public function test_registration_persists_the_account_organization_membership_and_audit_entry(): void
    {
        $response = $this->post(route('register.store'), $this->registration());

        $response->assertRedirectToRoute('dashboard');
        $user = User::where('email', 'owner@example.test')->firstOrFail();
        $organization = Organization::where('name', 'Example Security')->firstOrFail();
        $this->assertAuthenticatedAs($user);
        $this->assertTrue(Hash::check('example-password-123', $user->password));
        $this->assertSame('trial', $organization->subscription_status);
        $this->assertDatabaseHas('memberships', [
            'user_id' => $user->id,
            'organization_id' => $organization->id,
            'role' => 'owner',
        ]);
        $this->assertSame(['organization.created'], app(AuditLogger::class)->recent($organization->id, $user->id)->pluck('event')->all());
    }

    public function test_registration_rolls_back_all_records_if_the_audit_write_fails(): void
    {
        DB::connection()->beforeExecuting(function (string $query): void {
            $normalizedQuery = str_replace(['"', chr(96)], '', strtolower($query));

            if (str_starts_with($normalizedQuery, 'insert into audit_logs ')) {
                throw new RuntimeException('Audit log write unavailable.');
            }
        });

        $this->post(route('register.store'), $this->registration())->assertServerError();

        $this->assertGuest();
        $this->assertDatabaseCount('users', 0);
        $this->assertDatabaseCount('organizations', 0);
        $this->assertDatabaseCount('memberships', 0);
    }

    public function test_registration_rejects_an_email_already_used_with_different_case(): void
    {
        User::factory()->create(['email' => 'owner@example.test']);

        $this->from(route('register'))->post(route('register.store'), $this->registration())
            ->assertRedirectToRoute('register')
            ->assertSessionHasErrors('email');

        $this->assertDatabaseCount('organizations', 0);
        $this->assertDatabaseCount('memberships', 0);
    }

    public function test_login_authenticates_an_existing_account(): void
    {
        $user = User::factory()->create([
            'email' => 'owner@example.test',
            'password' => 'example-password-123',
        ]);

        $this->post(route('login.store'), [
            'email' => 'OWNER@example.test',
            'password' => 'example-password-123',
        ])->assertRedirectToRoute('dashboard');

        $this->assertAuthenticatedAs($user);
    }

    public function test_logout_ends_the_authenticated_session(): void
    {
        $user = User::factory()->create();

        $this->actingAs($user)->post(route('logout'))->assertRedirectToRoute('login');

        $this->assertGuest();
    }

    /** @return array<string, string> */
    private function registration(): array
    {
        return [
            'name' => 'Organization Owner',
            'email' => 'Owner@example.test',
            'organization_name' => 'Example Security',
            'password' => 'example-password-123',
            'password_confirmation' => 'example-password-123',
        ];
    }
}
