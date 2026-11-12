<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::table('port_scan_results', function (Blueprint $table): void {
            $table->string('product', 80)->nullable()->after('service');
            $table->string('service_version', 80)->nullable()->after('product');
            $table->string('cpe', 255)->nullable()->after('service_version');
            $table->string('banner', 512)->nullable()->after('cpe');
            $table->string('fingerprint_source', 32)->nullable()->after('banner');
        });
    }

    public function down(): void
    {
        Schema::table('port_scan_results', function (Blueprint $table): void {
            $table->dropColumn(['product', 'service_version', 'cpe', 'banner', 'fingerprint_source']);
        });
    }
};
