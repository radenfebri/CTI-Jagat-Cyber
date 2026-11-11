<?php

namespace App\Domain\Audit;

use App\Domain\Identity\Membership;
use Closure;
use Illuminate\Auth\Access\AuthorizationException;
use Illuminate\Database\Query\Builder;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

final class AuditLogger
{
    /** @param array<string, mixed> $context */
    public function record(string $organizationId, int $actorId, string $event, array $context = [], ?string $ipAddress = null): void
    {
        $this->inOrganization($organizationId, $actorId, function () use ($organizationId, $actorId, $event, $context, $ipAddress): void {
            $membership = $this->authorizedMembership($organizationId, $actorId)->lockForUpdate()->first(['id']);

            if ($membership === null) {
                throw new AuthorizationException;
            }

            $timestamp = now();

            DB::table('audit_logs')->insert([
                'id' => (string) Str::uuid(),
                'organization_id' => $organizationId,
                'actor_id' => $actorId,
                'event' => $event,
                'context' => json_encode($context, JSON_THROW_ON_ERROR),
                'ip_address' => $ipAddress,
                'created_at' => $timestamp,
                'updated_at' => $timestamp,
            ]);
        });
    }

    /** @return Collection<int, object> */
    public function recent(string $organizationId, int $actorId): Collection
    {
        return $this->inOrganization($organizationId, $actorId, fn () => DB::table('audit_logs')
            ->where('organization_id', $organizationId)
            ->whereExists($this->authorizedMembership($organizationId, $actorId)->select('id'))
            ->latest()
            ->orderByDesc('id')
            ->limit(10)
            ->get(['event', 'created_at']));
    }

    private function authorizedMembership(string $organizationId, int $actorId): Builder
    {
        return DB::table('memberships')
            ->where('organization_id', $organizationId)
            ->where('user_id', $actorId)
            ->whereIn('role', [Membership::OWNER, Membership::ADMIN]);
    }

    /**
     * @template TResult
     *
     * @param  Closure(): TResult  $operation
     * @return TResult
     */
    private function inOrganization(string $organizationId, int $actorId, Closure $operation): mixed
    {
        if (DB::connection()->getDriverName() !== 'pgsql') {
            return DB::transaction($operation);
        }

        return DB::transaction(function () use ($organizationId, $actorId, $operation): mixed {
            $previous = DB::selectOne(<<<'SQL'
                SELECT current_setting('app.organization_id', true) AS organization_id,
                       current_setting('app.actor_id', true) AS actor_id
                SQL);

            $this->setScope($organizationId, (string) $actorId);
            $result = $operation();
            $this->setScope($previous->organization_id ?? '', $previous->actor_id ?? '');

            return $result;
        });
    }

    private function setScope(string $organizationId, string $actorId): void
    {
        DB::select(
            "SELECT set_config('app.organization_id', ?, true), set_config('app.actor_id', ?, true)",
            [$organizationId, $actorId],
        );
    }
}
