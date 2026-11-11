<?php

namespace App\Domain\Tenancy;

use App\Domain\Audit\AuditLogger;
use App\Domain\Identity\Membership;
use App\Models\User;
use Illuminate\Support\Facades\DB;

final class CreateOrganization
{
    public function __construct(private AuditLogger $audit) {}

    public function handle(User $owner, string $name, string $slug, ?string $ipAddress): Organization
    {
        return DB::transaction(function () use ($owner, $name, $slug, $ipAddress): Organization {
            $organization = Organization::create([
                'name' => $name,
                'slug' => $slug,
            ]);

            Membership::create([
                'organization_id' => $organization->id,
                'user_id' => $owner->id,
                'role' => Membership::OWNER,
            ]);

            $this->audit->record($organization->id, $owner->id, 'organization.created', ipAddress: $ipAddress);

            return $organization;
        });
    }
}
