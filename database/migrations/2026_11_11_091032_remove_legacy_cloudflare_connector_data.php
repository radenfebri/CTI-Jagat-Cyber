<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        DB::table('monitored_domains')->update([
            'cloudflare_zone_id' => null,
            'cloudflare_api_token' => null,
            'zone_checked_at' => null,
            'zone_status' => null,
        ]);
    }

    public function down(): void
    {
        // Credentials are intentionally not restored after being removed.
    }
};
