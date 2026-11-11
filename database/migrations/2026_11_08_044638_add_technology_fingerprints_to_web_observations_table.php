<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('web_observations', function (Blueprint $table): void {
            $table->string('server_header', 255)->nullable()->after('status_code');
            $table->json('technologies')->nullable()->after('server_header');
        });
    }

    public function down(): void
    {
        Schema::table('web_observations', function (Blueprint $table): void {
            $table->dropColumn(['server_header', 'technologies']);
        });
    }
};
