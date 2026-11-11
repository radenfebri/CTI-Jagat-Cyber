<?php

namespace App\Policies;

use App\Domain\Assets\MonitoredDomain;
use App\Domain\Identity\Membership;
use App\Domain\Tenancy\Organization;
use App\Models\User;

class MonitoredDomainPolicy
{
    public function create(User $user, Organization $organization): bool
    {
        return $this->canManage($user, $organization->id);
    }

    public function manage(User $user, MonitoredDomain $domain): bool
    {
        return $this->canManage($user, $domain->organization_id);
    }

    private function canManage(User $user, string $organizationId): bool
    {
        return Membership::query()->where('organization_id', $organizationId)
            ->where('user_id', $user->id)
            ->whereIn('role', [Membership::OWNER, Membership::ADMIN])
            ->exists();
    }
}
