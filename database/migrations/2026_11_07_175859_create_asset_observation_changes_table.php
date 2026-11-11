<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('asset_observation_changes', function (Blueprint $table): void {
            $table->id();
            $table->foreignUuid('discovered_asset_id')->constrained()->cascadeOnDelete();
            $table->string('event', 16);
            $table->timestamp('occurred_at');
            $table->index(['discovered_asset_id', 'occurred_at'], 'asset_change_history');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('asset_observation_changes');
    }
};
