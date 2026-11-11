<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('monitored_domains', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->foreignUuid('organization_id')->constrained()->cascadeOnDelete();
            $table->string('hostname', 236);
            $table->string('verification_token', 64);
            $table->timestamp('verification_expires_at');
            $table->timestamp('verification_checked_at')->nullable();
            $table->string('verification_status', 24)->default('pending');
            $table->timestamp('verified_at')->nullable();
            $table->timestamps();
            $table->unique(['organization_id', 'hostname']);
            $table->index(['verified_at', 'verification_checked_at']);
        });

        Schema::create('domain_scan_policies', function (Blueprint $table): void {
            $table->foreignUuid('monitored_domain_id')->primary()->constrained()->cascadeOnDelete();
            $table->uuid('authorization_id');
            $table->foreignId('approved_by')->nullable()->constrained('users')->nullOnDelete();
            $table->timestamp('approved_at');
            $table->timestamp('revoked_at')->nullable();
            $table->timestamp('next_run_at')->nullable()->index();
            $table->uuid('run_id')->nullable();
            $table->string('last_status', 24)->nullable();
            $table->timestamp('last_queued_at')->nullable();
            $table->timestamp('last_finished_at')->nullable();
            $table->timestamp('last_success_at')->nullable();
            $table->timestamps();
        });

        Schema::create('discovered_assets', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->foreignUuid('monitored_domain_id')->constrained()->cascadeOnDelete();
            $table->string('record_type', 12);
            $table->string('value', 253);
            $table->string('source', 32);
            $table->timestamp('first_seen_at');
            $table->timestamp('last_seen_at');
            $table->timestamp('retired_at')->nullable();
            $table->unique(['monitored_domain_id', 'record_type', 'value', 'source'], 'asset_observation_unique');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('discovered_assets');
        Schema::dropIfExists('domain_scan_policies');
        Schema::dropIfExists('monitored_domains');
    }
};
