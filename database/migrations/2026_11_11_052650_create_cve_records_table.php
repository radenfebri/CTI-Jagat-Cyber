<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    public function up(): void
    {
        Schema::create('cve_records', function (Blueprint $table): void {
            $table->uuid('id')->primary();
            $table->string('cve_id', 32)->unique();
            $table->string('source', 40)->default('nvd');
            $table->string('title', 255)->nullable();
            $table->text('description')->nullable();
            $table->string('severity', 16)->nullable();
            $table->decimal('cvss_score', 4, 1)->nullable();
            $table->string('cvss_vector', 255)->nullable();
            $table->boolean('cisa_kev')->default(false);
            $table->json('affected_cpes')->nullable();
            $table->json('references')->nullable();
            $table->timestamp('published_at')->nullable();
            $table->timestamp('last_modified_at')->nullable();
            $table->timestamps();
            $table->index(['source', 'last_modified_at']);
            $table->index(['cisa_kev', 'severity']);
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('cve_records');
    }
};
