<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('monitored_domains', function (Blueprint $table): void {
            $table->timestamp('zone_checked_at')->nullable();
            $table->string('zone_status', 24)->nullable();
        });
    }

    public function down(): void
    {
        Schema::table('monitored_domains', fn (Blueprint $table) => $table->dropColumn(['zone_checked_at', 'zone_status']));
    }
};
