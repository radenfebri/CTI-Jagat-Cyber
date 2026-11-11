<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->uuid('ct_authorization_id')->nullable();
            $table->string('ct_cursor', 64)->nullable();
            $table->string('ct_status', 24)->nullable();
            $table->timestamp('ct_checked_at')->nullable();
            $table->uuid('tls_authorization_id')->nullable();
            $table->ipAddress('tls_approved_ip')->nullable();
            $table->foreignId('tls_approved_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('tls_approved_at')->nullable();
        });

        Schema::create('tls_checks', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->foreignUuid('monitored_domain_id')->constrained()->cascadeOnDelete();
            $table->foreignId('requested_by')->nullable()->constrained('users')->nullOnDelete();
            $table->uuid('authorization_id');
            $table->ipAddress('ip_address');
            $table->string('status', 24);
            $table->string('reason', 64)->nullable();
            $table->json('result')->nullable();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->timestamps();
            $table->index(['monitored_domain_id', 'created_at']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('tls_checks');

        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->dropConstrainedForeignId('tls_approved_by');
            $table->dropColumn([
                'ct_authorization_id', 'ct_cursor', 'ct_status', 'ct_checked_at',
                'tls_authorization_id', 'tls_approved_ip', 'tls_approved_at',
            ]);
        });
    }
};
