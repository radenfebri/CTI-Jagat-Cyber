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
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->string('tls_scope', 24)->default('direct');
        });

        Schema::table('tls_checks', function (Blueprint $table): void {
            $table->string('scope', 24)->default('direct');
            $table->ipAddress('ip_address')->nullable()->change();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        if (DB::table('tls_checks')->where('scope', 'public_endpoint')->exists()
            || DB::table('monitored_domains')->where('tls_scope', 'public_endpoint')->exists()) {
            throw new RuntimeException('Rollback would remove public endpoint scopes or check history.');
        }

        Schema::table('tls_checks', function (Blueprint $table): void {
            $table->ipAddress('ip_address')->nullable(false)->change();
            $table->dropColumn('scope');
        });

        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->dropColumn('tls_scope');
        });
    }
};
