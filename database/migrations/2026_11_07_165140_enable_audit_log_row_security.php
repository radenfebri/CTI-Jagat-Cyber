<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('audit_logs', function (Blueprint $table): void {
            $table->index(['organization_id', 'created_at', 'id']);
        });

        if (DB::connection()->getDriverName() !== 'pgsql') {
            return;
        }

        $scope = <<<'SQL'
            organization_id = NULLIF(current_setting('app.organization_id', true), '')::uuid
            AND EXISTS (
                SELECT 1 FROM memberships
                WHERE memberships.organization_id = audit_logs.organization_id
                  AND memberships.user_id = NULLIF(current_setting('app.actor_id', true), '')::bigint
                  AND memberships.role IN ('owner', 'admin')
            )
            SQL;

        DB::statement("CREATE POLICY audit_logs_read ON audit_logs FOR SELECT USING ($scope)");
        DB::statement("CREATE POLICY audit_logs_insert ON audit_logs FOR INSERT WITH CHECK (
            $scope AND actor_id = NULLIF(current_setting('app.actor_id', true), '')::bigint
        )");
        DB::statement('ALTER TABLE audit_logs ENABLE ROW LEVEL SECURITY');
        DB::statement('ALTER TABLE audit_logs FORCE ROW LEVEL SECURITY');
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (DB::connection()->getDriverName() === 'pgsql') {
            DB::statement('ALTER TABLE audit_logs NO FORCE ROW LEVEL SECURITY');
            DB::statement('ALTER TABLE audit_logs DISABLE ROW LEVEL SECURITY');
            DB::statement('DROP POLICY audit_logs_insert ON audit_logs');
            DB::statement('DROP POLICY audit_logs_read ON audit_logs');
        }

        Schema::table('audit_logs', function (Blueprint $table): void {
            $table->dropIndex(['organization_id', 'created_at', 'id']);
        });
    }
};
