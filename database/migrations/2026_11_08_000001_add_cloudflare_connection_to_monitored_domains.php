<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->char('cloudflare_zone_id', 32)->nullable();
            $table->text('cloudflare_api_token')->nullable();
            $table->index(['organization_id', 'cloudflare_zone_id']);
        });
    }

    public function down(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->dropIndex(['organization_id', 'cloudflare_zone_id']);
            $table->dropColumn(['cloudflare_zone_id', 'cloudflare_api_token']);
        });
    }
};
