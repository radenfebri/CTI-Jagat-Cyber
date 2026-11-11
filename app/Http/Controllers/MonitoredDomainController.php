<?php

namespace App\Http\Controllers;

use App\Domain\Assets\CloudflareZoneInventory;
use App\Domain\Assets\DomainJobDispatcher;
use App\Domain\Assets\DomainName;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\WebObservation;
use App\Domain\Audit\AuditLogger;
use App\Domain\Tenancy\Organization;
use Illuminate\Contracts\View\View;
use Illuminate\Database\UniqueConstraintViolationException;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;
use Illuminate\Validation\Rule;
use Illuminate\Validation\ValidationException;

class MonitoredDomainController extends Controller
{
    public function __construct(private AuditLogger $audit, private DomainJobDispatcher $jobs) {}

    public function index(Request $request, string $organization): View
    {
        $workspace = $this->workspace($request, $organization);
        $domains = $workspace->monitoredDomains()
            ->withCount(['assets as subdomains_count' => fn ($query) => $query
                ->where('record_type', 'SUBDOMAIN')->whereNull('retired_at')])
            ->withCount(['assets as active_subdomains_count' => function ($query): void {
                $query->where('record_type', 'SUBDOMAIN')->whereNull('retired_at')->whereNull('hidden_at')
                    ->whereExists(function ($observations): void {
                        $observations->selectRaw('1')->from('web_observations')
                            ->whereColumn('web_observations.monitored_domain_id', 'discovered_assets.monitored_domain_id')
                            ->whereColumn('web_observations.hostname', 'discovered_assets.value')
                            ->whereColumn('web_observations.authorization_id', 'monitored_domains.web_authorization_id')
                            ->whereBetween('web_observations.status_code', [100, 599])
                            ->where('web_observations.checked_at', '>=', now()->subHours(48));
                    });
            }])
            ->addSelect(['web_ip' => WebObservation::query()->select('public_ip')->responded()
                ->whereColumn('monitored_domain_id', 'monitored_domains.id')
                ->whereColumn('hostname', 'monitored_domains.hostname')
                ->whereColumn('authorization_id', 'monitored_domains.web_authorization_id')
                ->whereNotNull('monitored_domains.verified_at')->limit(1)])
            ->orderBy('hostname')->paginate(15);
        $canManage = Gate::allows('create', [MonitoredDomain::class, $workspace]);

        return view('domains.index', compact('workspace', 'domains', 'canManage'));
    }

    public function show(Request $request, string $organization, string $domain, CloudflareZoneInventory $zone): View
    {
        $workspace = $this->workspace($request, $organization);
        $monitoredDomain = $workspace->monitoredDomains()->with('scanPolicy')->findOrFail($domain);
        $canManage = Gate::allows('manage', $monitoredDomain);
        $assetView = $request->query('assets') === 'hidden' ? 'hidden' : 'subdomains';
        $assetSearch = $request->query('q');
        $assetSearch = is_string($assetSearch) ? mb_substr(trim($assetSearch), 0, 100) : '';
        $webRoot = $monitoredDomain->webObservations()->where('hostname', $monitoredDomain->hostname)
            ->where('authorization_id', $monitoredDomain->web_authorization_id)->first();
        $assetCandidates = $monitoredDomain->assets()
            ->where('record_type', 'SUBDOMAIN')->whereNull('retired_at')
            ->when($assetView === 'hidden', fn ($query) => $query->whereNotNull('hidden_at'), fn ($query) => $query->whereNull('hidden_at'));
        if ($assetSearch !== '') {
            $pattern = '%'.strtr($assetSearch, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
            $assetCandidates->whereRaw("discovered_assets.value LIKE ? ESCAPE '!'", [$pattern]);
        }
        $representativeIds = (clone $assetCandidates)->selectRaw('MIN(discovered_assets.id)')->groupBy('discovered_assets.value');
        $assets = $assetCandidates
            ->join('web_observations', function ($join): void {
                $join->on('web_observations.monitored_domain_id', '=', 'discovered_assets.monitored_domain_id')
                    ->on('web_observations.hostname', '=', 'discovered_assets.value');
            })
            ->where('web_observations.authorization_id', $monitoredDomain->web_authorization_id)
            ->whereBetween('web_observations.status_code', [100, 599])->where('web_observations.checked_at', '>=', now()->subHours(48))
            ->whereIn('discovered_assets.id', $representativeIds)
            ->orderBy('discovered_assets.value')->orderBy('discovered_assets.id')
            ->paginate(25, ['discovered_assets.*', 'web_observations.public_ip', 'web_observations.scheme', 'web_observations.status_code'])
            ->appends(['assets' => $assetView, 'q' => $assetSearch]);
        $sourceLabels = $monitoredDomain->assets()->whereIn('value', $assets->getCollection()->pluck('value'))
            ->where('record_type', 'SUBDOMAIN')->whereNull('retired_at')->get(['value', 'source'])
            ->groupBy('value')->map(fn ($items) => $items->map(fn ($item) => $item->subdomainSourceLabel())->unique()->implode(' / '));
        $assets->getCollection()->transform(function ($asset) use ($sourceLabels) {
            $asset->source_labels = $sourceLabels->get($asset->value, $asset->subdomainSourceLabel());

            return $asset;
        });
        $zoneConfigured = $zone->configuredFor($monitoredDomain);

        return view('domains.show', compact('workspace', 'monitoredDomain', 'assets', 'assetView', 'assetSearch', 'canManage', 'zoneConfigured', 'webRoot'));
    }

    public function store(Request $request, string $organization): RedirectResponse
    {
        $workspace = $this->workspace($request, $organization);
        Gate::authorize('create', [MonitoredDomain::class, $workspace]);
        $data = $request->validate(['hostname' => ['required', 'string', 'max:253']]);
        $hostname = DomainName::normalize($data['hostname']);

        if ($hostname === null || strlen(MonitoredDomain::TXT_PREFIX.$hostname) > 253) {
            throw ValidationException::withMessages(['hostname' => 'Masukkan nama domain publik tanpa URL, port, atau wildcard.']);
        }

        try {
            $domain = DB::transaction(function () use ($request, $workspace, $hostname): MonitoredDomain {
                $current = Organization::query()->lockForUpdate()->findOrFail($workspace->id);

                if ($current->monitoredDomains()->count() >= config('cti.domain_limit')) {
                    throw ValidationException::withMessages(['hostname' => 'Organisasi sudah mencapai batas domain.']);
                }

                $domain = $current->monitoredDomains()->create(['hostname' => $hostname] + $this->newChallenge());
                $this->record($request, $domain, 'domain.registered');

                return $domain;
            });
        } catch (UniqueConstraintViolationException) {
            throw ValidationException::withMessages(['hostname' => 'Domain ini sudah terdaftar di organisasi Anda.']);
        }

        return $this->backToDomain($domain, 'Domain ditambahkan. Pasang record TXT untuk verifikasi.');
    }

    public function rotateToken(Request $request, string $organization, string $domain): RedirectResponse
    {
        $target = $this->manageableDomain($request, $organization, $domain);

        DB::transaction(function () use ($request, $target): void {
            $current = $target->newQuery()->lockForUpdate()->findOrFail($target->id);
            abort_if($current->verified_at !== null, 409, 'Domain sudah terverifikasi.');
            $current->forceFill($this->newChallenge() + ['verification_status' => 'pending', 'verification_checked_at' => null])->save();
            $this->record($request, $current, 'domain.challenge_rotated');
        });

        return $this->backToDomain($target, 'Token baru dibuat. Ganti nilai TXT pada DNS.');
    }

    public function destroy(Request $request, string $organization, string $domain): RedirectResponse
    {
        $target = $this->manageableDomain($request, $organization, $domain);
        $request->validate(
            ['delete_confirmation' => ['required', 'string', Rule::in([$target->hostname])]],
            ['delete_confirmation.required' => 'Ketik nama domain untuk konfirmasi.', 'delete_confirmation.in' => 'Nama domain yang diketik harus sama persis.'],
        );

        DB::transaction(function () use ($request, $target): void {
            $workspace = Organization::query()->lockForUpdate()->findOrFail($target->organization_id);
            $current = $workspace->monitoredDomains()->lockForUpdate()->findOrFail($target->id);
            $this->record($request, $current, 'domain.deleted');
            $current->delete();
        });

        return to_route('domains.index', $organization)->with('status', $target->hostname.' dihapus dari organisasi.');
    }

    public function verify(Request $request, string $organization, string $domain): RedirectResponse
    {
        $target = $this->manageableDomain($request, $organization, $domain)->load('organization');
        abort_unless($target->organization->allowsDiscovery(), 403);
        abort_if($target->verified_at !== null || $target->verification_expires_at->isPast(), 409, 'Token kedaluwarsa atau domain sudah terverifikasi.');

        $this->jobs->verify($target);

        return $this->backToDomain($target, 'Pemeriksaan TXT dimasukkan ke antrean. Muat ulang halaman untuk melihat hasilnya.');
    }

    public function approve(Request $request, string $organization, string $domain): RedirectResponse
    {
        $target = $this->manageableDomain($request, $organization, $domain);
        $request->validate(['consent' => ['accepted'], 'include_certificates' => ['sometimes', 'accepted']]);

        DB::transaction(function () use ($request, $target): void {
            $workspace = Organization::query()->lockForUpdate()->findOrFail($target->organization_id);
            $current = $workspace->monitoredDomains()->lockForUpdate()->findOrFail($target->id);
            abort_unless($workspace->allowsDiscovery(), 403);
            abort_if($current->verified_at === null, 409, 'Verifikasi kepemilikan domain terlebih dahulu.');

            if ($current->scanPolicy()->first()?->isAuthorized()) {
                return;
            }

            $current->scanPolicy()->updateOrCreate([], [
                'authorization_id' => (string) Str::uuid(),
                'approved_by' => $request->user()->id,
                'approved_at' => now(),
                'revoked_at' => null,
                'next_run_at' => now(),
                'run_id' => null,
                'last_status' => null,
                'last_finished_at' => null,
            ]);
            $this->record($request, $current, 'domain.passive_scope_approved');
            if ($request->boolean('include_certificates')) {
                $current->forceFill(['ct_authorization_id' => (string) Str::uuid(), 'ct_status' => 'pending'])->save();
                $this->record($request, $current, 'domain.ct_enabled');
            }
        });

        $this->jobs->discover($target);

        return $this->backToDomain($target, 'Cakupan pasif disetujui. Lihat status discovery di bawah.');
    }

    public function revoke(Request $request, string $organization, string $domain): RedirectResponse
    {
        $target = $this->manageableDomain($request, $organization, $domain);

        DB::transaction(function () use ($request, $target): void {
            $current = $target->newQuery()->lockForUpdate()->findOrFail($target->id);
            $policy = $current->scanPolicy()->lockForUpdate()->first();

            if ($policy?->isAuthorized()) {
                $policy->update(['revoked_at' => now(), 'next_run_at' => null, 'last_status' => 'cancelled', 'last_finished_at' => now()]);
                $current->forceFill(['ct_authorization_id' => null])->save();
                $this->record($request, $current, 'domain.passive_scope_revoked');
            }
        });

        return $this->backToDomain($target, 'Izin discovery pasif dicabut.');
    }

    public function discover(Request $request, string $organization, string $domain): RedirectResponse
    {
        $target = $this->manageableDomain($request, $organization, $domain);
        $queued = $this->jobs->discover($target, manual: true);

        return $this->backToDomain($target, $queued
            ? 'Discovery dimasukkan ke antrean.'
            : 'Discovery belum dapat dijalankan. Periksa izin, status organisasi, atau tunggu 10 menit sejak permintaan terakhir.');
    }

    private function workspace(Request $request, string $organization): Organization
    {
        return $request->user()->organizations()->whereKey($organization)->firstOrFail();
    }

    private function manageableDomain(Request $request, string $organization, string $domain): MonitoredDomain
    {
        $target = $this->workspace($request, $organization)->monitoredDomains()->findOrFail($domain);
        Gate::authorize('manage', $target);

        return $target;
    }

    /** @return array{verification_token: string, verification_expires_at: Carbon} */
    private function newChallenge(): array
    {
        return [
            'verification_token' => Str::random(48),
            'verification_expires_at' => now()->addDays(config('cti.verification_token_days')),
        ];
    }

    private function record(Request $request, MonitoredDomain $domain, string $event): void
    {
        $this->audit->record($domain->organization_id, $request->user()->id, $event, [
            'domain_id' => $domain->id,
            'hostname' => $domain->hostname,
        ], $request->ip());
    }

    private function backToDomain(MonitoredDomain $domain, string $status): RedirectResponse
    {
        return to_route('domains.show', ['organization' => $domain->organization_id, 'domain' => $domain->id])->with('status', $status);
    }
}
