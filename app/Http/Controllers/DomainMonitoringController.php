<?php

namespace App\Http\Controllers;

use App\Domain\Assets\DomainJobDispatcher;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\ObservedNetwork;
use App\Domain\Assets\TlsCheck;
use App\Domain\Audit\AuditLogger;
use App\Jobs\ProbeDomainTls;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;

class DomainMonitoringController extends Controller
{
    public function __construct(private AuditLogger $audit, private DomainJobDispatcher $jobs) {}

    public function configureCt(Request $request, string $organization, string $domain): RedirectResponse
    {
        $target = $this->target($request, $organization, $domain);
        $request->validate(['enabled' => ['required', 'boolean']]);
        $enabled = $request->boolean('enabled');

        DB::transaction(function () use ($request, $target, $enabled): void {
            $current = MonitoredDomain::query()->lockForUpdate()->findOrFail($target->id);
            if ($enabled) {
                abort_unless($current->organization->allowsDiscovery(), 403);
                abort_unless($current->verified_at && $current->scanPolicy?->isAuthorized(), 409, 'Aktifkan izin discovery pasif terlebih dahulu.');
            }
            if ($enabled === ($current->ct_authorization_id !== null)) {
                return;
            }

            $current->forceFill([
                'ct_authorization_id' => $enabled ? (string) Str::uuid() : null,
                'ct_status' => $enabled ? 'pending' : null,
            ])->save();
            if ($enabled) {
                $current->scanPolicy()->whereNull('revoked_at')->update(['next_run_at' => now()]);
            }
            $this->record($request, $current, $enabled ? 'domain.ct_enabled' : 'domain.ct_disabled');
        });

        return to_route('domains.show', [$target->organization_id, $target->id])
            ->with('status', $enabled ? 'Pencarian sertifikat akan ikut discovery pasif berikutnya.' : 'Pencarian sertifikat dinonaktifkan.');
    }

    public function approveTls(Request $request, string $organization, string $domain): RedirectResponse
    {
        $target = $this->target($request, $organization, $domain);
        $data = $request->validate([
            'scope' => ['sometimes', Rule::in([TlsCheck::DIRECT, TlsCheck::PUBLIC_ENDPOINT])],
            'ip_address' => [Rule::requiredIf($request->input('scope') !== TlsCheck::PUBLIC_ENDPOINT), 'prohibited_if:scope,'.TlsCheck::PUBLIC_ENDPOINT, 'ip'],
            'consent' => ['accepted'],
        ]);
        $scope = $data['scope'] ?? TlsCheck::DIRECT;
        $address = null;
        if ($scope === TlsCheck::DIRECT) {
            $address = ObservedNetwork::normalize($data['ip_address']);
            if ($address === null || ObservedNetwork::classify($address) !== 'public_unknown') {
                throw ValidationException::withMessages(['ip_address' => 'Pilih IP publik langsung yang Anda kelola. Untuk Cloudflare, gunakan mode endpoint publik.']);
            }
        }

        DB::transaction(function () use ($request, $target, $scope, $address): void {
            $current = MonitoredDomain::query()->lockForUpdate()->findOrFail($target->id);
            abort_unless($current->organization->allowsDiscovery(), 403);
            abort_if($current->verified_at === null, 409, 'Verifikasi DNS TXT diperlukan.');
            if ($scope === TlsCheck::DIRECT) {
                $observed = $current->assets()->whereNull('retired_at');
                if ((clone $observed)->where('record_type', 'CNAME')->exists()
                    || ! $observed->whereIn('record_type', ['A', 'AAAA'])->where('value', $address)->exists()) {
                    throw ValidationException::withMessages(['ip_address' => 'IP langsung harus tercatat pada A atau AAAA aktif untuk hostname ini. Untuk alias CNAME, gunakan mode endpoint publik.']);
                }
            }

            $this->cancelOutstandingChecks($current);
            $this->cancelOutstandingPortScans($current);
            $current->forceFill([
                'tls_authorization_id' => (string) Str::uuid(),
                'tls_approved_ip' => $address,
                'tls_scope' => $scope,
                'tls_approved_by' => $request->user()->id,
                'tls_approved_at' => now(),
            ])->save();
            $this->record($request, $current, 'domain.tls_approved', ['scope' => $scope] + ($address === null ? [] : ['ip_address' => $address]));
        });

        return $this->redirectToTls($target, 'Izin TLS tersimpan. Jalankan pemeriksaan saat Anda siap.');
    }

    public function revokeTls(Request $request, string $organization, string $domain): RedirectResponse
    {
        $target = $this->target($request, $organization, $domain);

        DB::transaction(function () use ($request, $target): void {
            $current = MonitoredDomain::query()->lockForUpdate()->findOrFail($target->id);
            if ($current->tls_authorization_id === null) {
                return;
            }

            $this->cancelOutstandingChecks($current);
            $this->cancelOutstandingPortScans($current);
            $current->forceFill([
                'tls_authorization_id' => null,
                'tls_approved_ip' => null,
                'tls_scope' => TlsCheck::DIRECT,
                'tls_approved_by' => null,
                'tls_approved_at' => null,
            ])->save();
            $this->record($request, $current, 'domain.tls_revoked');
        });

        return $this->redirectToTls($target, 'Izin TLS dicabut.');
    }

    public function queueTls(Request $request, string $organization, string $domain): RedirectResponse
    {
        $target = $this->target($request, $organization, $domain);

        $queued = DB::transaction(function () use ($request, $target): bool {
            $current = MonitoredDomain::query()->lockForUpdate()->findOrFail($target->id);
            abort_unless($current->organization->allowsDiscovery(), 403);
            abort_unless($current->hasTlsScope(), 409, 'Setujui cakupan TLS terlebih dahulu.');

            if ($current->tlsChecks()->where('created_at', '>', now()->subMinutes(10))->exists()) {
                return false;
            }

            $this->cancelOutstandingChecks($current);
            $check = $current->tlsChecks()->create([
                'requested_by' => $request->user()->id,
                'authorization_id' => $current->tls_authorization_id,
                'ip_address' => $current->tls_approved_ip,
                'scope' => $current->tls_scope,
                'status' => 'queued',
            ]);
            $this->record($request, $current, 'domain.tls_queued', ['check_id' => $check->id]);
            $this->jobs->dispatchInTransaction(new ProbeDomainTls($current->organization_id, $current->id, $check->id));

            return true;
        });

        return $this->redirectToTls($target, $queued ? 'Pemeriksaan TLS dimasukkan ke antrean.' : 'Tunggu 10 menit sejak permintaan TLS terakhir.');
    }

    private function target(Request $request, string $organization, string $domain): MonitoredDomain
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $target = $workspace->monitoredDomains()->findOrFail($domain);
        Gate::authorize('manage', $target);

        return $target;
    }

    private function cancelOutstandingChecks(MonitoredDomain $domain): void
    {
        $domain->tlsChecks()->whereIn('status', ['queued', 'running'])
            ->update(['status' => 'cancelled', 'reason' => 'scope_or_queue_expired', 'finished_at' => now()]);
    }

    private function cancelOutstandingPortScans(MonitoredDomain $domain): void
    {
        $domain->portScanRuns()->whereIn('status', ['queued', 'running'])
            ->update(['status' => 'cancelled', 'last_error' => 'Cakupan IP langsung berubah atau dicabut.', 'finished_at' => now()]);
    }

    /** @param array<string, string> $context */
    private function record(Request $request, MonitoredDomain $domain, string $event, array $context = []): void
    {
        $this->audit->record($domain->organization_id, $request->user()->id, $event, [
            'domain_id' => $domain->id,
        ] + $context, $request->ip());
    }

    private function redirectToTls(MonitoredDomain $domain, string $status): RedirectResponse
    {
        return redirect()->to(route('domains.show', [$domain->organization_id, $domain->id]).'#tls')->with('status', $status);
    }
}
