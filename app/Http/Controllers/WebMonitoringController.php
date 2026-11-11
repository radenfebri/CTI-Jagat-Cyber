<?php

namespace App\Http\Controllers;

use App\Domain\Audit\AuditLogger;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;

class WebMonitoringController extends Controller
{
    public function update(Request $request, string $organization, string $domain, AuditLogger $audit): RedirectResponse
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $target = $workspace->monitoredDomains()->findOrFail($domain);
        Gate::authorize('manage', $target);
        $request->validate(['enabled' => ['required', 'boolean']]);
        $enabled = $request->boolean('enabled');
        if ($enabled) {
            $request->validate(['consent' => ['accepted']]);
        }

        DB::transaction(function () use ($request, $workspace, $target, $enabled, $audit): void {
            $current = $workspace->monitoredDomains()->lockForUpdate()->findOrFail($target->id);
            if ($enabled) {
                abort_unless($workspace->allowsDiscovery(), 403);
                abort_if($current->verified_at === null, 409, 'Verifikasi domain terlebih dahulu.');
            }

            if ($enabled === ($current->web_authorization_id !== null)) {
                return;
            }

            $current->forceFill([
                'web_authorization_id' => $enabled ? (string) Str::uuid() : null,
                'web_next_run_at' => $enabled ? now() : null,
            ])->save();
            $audit->record($workspace->id, $request->user()->id, $enabled ? 'domain.web_enabled' : 'domain.web_disabled', [
                'domain_id' => $current->id, 'hostname' => $current->hostname,
            ], $request->ip());
        });

        return to_route('domains.show', [$workspace, $target])->with('status', $enabled
            ? 'Pemeriksaan web aktif. Hasil muncul setelah jadwal berikutnya.'
            : 'Pemeriksaan web dihentikan.');
    }
}
