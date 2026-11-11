<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('port_scan_runs', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->foreignUuid('monitored_domain_id')->constrained()->cascadeOnDelete();
            $table->foreignId('requested_by')->nullable()->constrained('users')->nullOnDelete();
            $table->ipAddress('target_ip');
            $table->unsignedSmallInteger('range_start')->default(1);
            $table->unsignedSmallInteger('range_end')->default(65535);
            $table->unsignedInteger('total_ports')->default(65535);
            $table->unsignedInteger('completed_ports')->default(0);
            $table->unsignedInteger('open_ports')->default(0);
            $table->string('status', 20)->default('queued');
            $table->text('last_error')->nullable();
            $table->timestamp('started_at')->nullable();
            $table->timestamp('finished_at')->nullable();
            $table->timestamps();
            $table->index(['monitored_domain_id', 'created_at']);
            $table->index(['monitored_domain_id', 'status']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('port_scan_runs');
    }
};
