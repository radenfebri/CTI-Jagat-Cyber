<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->uuid('web_authorization_id')->nullable();
            $table->timestamp('web_next_run_at')->nullable()->index();
        });

        Schema::create('web_observations', function (Blueprint $table): void {
            $table->id();
            $table->foreignUuid('monitored_domain_id')->constrained()->cascadeOnDelete();
            $table->string('hostname', 253);
            $table->uuid('authorization_id');
            $table->ipAddress('public_ip')->nullable();
            $table->string('scheme', 5)->nullable();
            $table->unsignedSmallInteger('status_code')->nullable();
            $table->timestamp('checked_at');
            $table->unique(['monitored_domain_id', 'hostname']);
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('web_observations');

        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->dropIndex(['web_next_run_at']);
            $table->dropColumn(['web_authorization_id', 'web_next_run_at']);
        });
    }
};
