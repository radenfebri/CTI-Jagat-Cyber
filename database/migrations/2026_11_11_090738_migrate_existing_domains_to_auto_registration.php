<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Support\Facades\DB;

return new class extends Migration
{
    public function up(): void
    {
        $timestamp = now();
        DB::table('monitored_domains')->whereNull('verified_at')->update([
            'verification_status' => 'auto_registered',
            'verification_checked_at' => $timestamp,
            'verified_at' => $timestamp,
        ]);
    }

    public function down(): void
    {
        DB::table('monitored_domains')->where('verification_status', 'auto_registered')->update([
            'verification_status' => 'pending',
            'verification_checked_at' => null,
            'verified_at' => null,
        ]);
    }
};
