<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('port_scan_results', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->foreignUuid('port_scan_run_id')->constrained()->cascadeOnDelete();
            $table->unsignedSmallInteger('port');
            $table->string('protocol', 8)->default('tcp');
            $table->string('state', 16)->default('open');
            $table->unsignedSmallInteger('latency_ms')->nullable();
            $table->string('service', 64)->nullable();
            $table->timestamp('observed_at');
            $table->timestamps();
            $table->unique(['port_scan_run_id', 'port', 'protocol']);
            $table->index(['port_scan_run_id', 'state']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('port_scan_results');
    }
};
