<?php

namespace App\Http\Controllers;

use App\Domain\Audit\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\ValidationException;

class CloudflareConnectionController extends Controller
{
    public function __construct(private AuditLogger $audit) {}

    public function update(Request $request, string $organization, string $domain): RedirectResponse
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $target = $workspace->monitoredDomains()->findOrFail($domain);
        Gate::authorize('manage', $target);

        $data = $request->validate([
            'enabled' => ['required', 'boolean'],
            'zone_id' => ['nullable', 'string', 'size:32', 'regex:/\A[a-f0-9]{32}\z/i'],
            'api_token' => ['nullable', 'string', 'max:4096'],
        ]);
        $enabled = $request->boolean('enabled');

        if ($enabled && $target->verified_at === null) {
            throw ValidationException::withMessages(['zone_id' => 'Verifikasi domain terlebih dahulu.']);
        }

        if ($enabled && blank($data['zone_id'] ?? null)) {
            throw ValidationException::withMessages(['zone_id' => 'Masukkan Zone ID Cloudflare.']);
        }

        if ($enabled && blank($data['api_token'] ?? null) && blank($target->cloudflare_api_token)) {
            throw ValidationException::withMessages(['api_token' => 'Masukkan API Token Cloudflare dengan izin Zone DNS Read.']);
        }

        DB::transaction(function () use ($request, $workspace, $target, $enabled, $data): void {
            $current = $workspace->monitoredDomains()->lockForUpdate()->findOrFail($target->id);
            $current->forceFill([
                'cloudflare_zone_id' => $enabled ? strtolower($data['zone_id']) : null,
                'cloudflare_api_token' => $enabled
                    ? ($data['api_token'] ?? null) ?: $current->cloudflare_api_token
                    : null,
                'zone_checked_at' => null,
                'zone_status' => null,
            ])->save();
            if ($enabled) {
                $current->scanPolicy()->whereNull('revoked_at')->update(['next_run_at' => now()]);
            }

            $this->audit->record($workspace->id, $request->user()->id, $enabled ? 'domain.cloudflare_connected' : 'domain.cloudflare_disconnected', [
                'domain_id' => $current->id,
                'hostname' => $current->hostname,
            ], $request->ip());
        });

        return to_route('domains.show', [$workspace, $target])->with('status', $enabled
            ? 'Konektor Cloudflare tersimpan untuk domain ini.'
            : 'Konektor Cloudflare dilepas dari domain ini.');
    }
}
