<?php

namespace App\Http\Controllers;

use App\Domain\Assets\DiscoveredAsset;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\ObservedNetwork;
use App\Domain\Assets\PortScanRun;
use App\Domain\Assets\TlsCheck;
use App\Domain\Assets\VulnerabilityFinding;
use App\Domain\Assets\WebObservation;
use App\Jobs\ScanPortChunk;
use Illuminate\Contracts\View\View;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Gate;

class AttackSurfaceController extends Controller
{
    public function startPortScan(Request $request, string $organization, string $domain): RedirectResponse
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $monitoredDomain = $workspace->monitoredDomains()->findOrFail($domain);
        Gate::authorize('manage', $monitoredDomain);
        $request->validate(['consent' => ['accepted']], ['consent.accepted' => 'Konfirmasi bahwa organisasi Anda memiliki izin memindai IP ini.']);
        abort_unless($monitoredDomain->verified_at !== null, 409, 'Verifikasi TXT domain terlebih dahulu.');
        abort_unless($monitoredDomain->hasTlsScope() && $monitoredDomain->tls_scope === TlsCheck::DIRECT, 409, 'Scan penuh membutuhkan IP langsung yang disetujui. IP Cloudflare/WAF tidak dipindai sebagai origin.');
        abort_unless(ObservedNetwork::classify((string) $monitoredDomain->tls_approved_ip) === 'public_unknown', 409, 'IP yang disetujui bukan endpoint publik langsung yang dapat dipindai.');

        if ($monitoredDomain->portScanRuns()->whereIn('status', ['queued', 'running'])->exists()) {
            return back()->with('status', 'Scan seluruh port sudah berjalan untuk domain ini.');
        }

        $run = DB::transaction(fn (): PortScanRun => $monitoredDomain->portScanRuns()->create([
            'requested_by' => $request->user()->id,
            'target_ip' => $monitoredDomain->tls_approved_ip,
            'range_start' => 1,
            'range_end' => 65535,
            'total_ports' => 65535,
            'status' => 'queued',
        ]));
        $chunkSize = config('cti.port_scan.chunk_size', 256);
        for ($start = 1; $start <= 65535; $start += $chunkSize) {
            dispatch(new ScanPortChunk($run->id, $start, min(65535, $start + $chunkSize - 1)));
        }

        return back()->with('status', 'Scan TCP port 1–65535 dimasukkan ke antrean worker.');
    }

    public function cancelPortScan(Request $request, string $organization, string $domain, string $run): RedirectResponse
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $monitoredDomain = $workspace->monitoredDomains()->findOrFail($domain);
        Gate::authorize('manage', $monitoredDomain);
        $monitoredDomain->portScanRuns()->whereKey($run)->whereIn('status', ['queued', 'running'])->update([
            'status' => 'cancelled',
            'finished_at' => now(),
            'last_error' => 'Dibatalkan oleh operator.',
        ]);

        return back()->with('status', 'Scan port dibatalkan.');
    }

    public function vulnerabilities(Request $request, string $organization): View
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $search = mb_substr(trim((string) $request->query('q', '')), 0, 100);
        $dedupe = DiscoveredAsset::query()
            ->selectRaw('MIN(id)')
            ->where('record_type', 'SUBDOMAIN')
            ->whereNull('retired_at')->whereNull('hidden_at')
            ->whereHas('monitoredDomain', fn (Builder $query) => $query
                ->where('organization_id', $workspace->id)->whereNotNull('verified_at'))
            ->groupBy('monitored_domain_id', 'value');
        $assetsQuery = DiscoveredAsset::query()
            ->whereIn('id', $dedupe)
            ->with('monitoredDomain:id,hostname')
            ->when($search !== '', function (Builder $query) use ($search): void {
                $pattern = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
                $query->where(function (Builder $nested) use ($pattern): void {
                    $nested->whereRaw("value LIKE ? ESCAPE '!'", [$pattern])
                        ->orWhereHas('monitoredDomain', fn (Builder $domain) => $domain
                            ->whereRaw("hostname LIKE ? ESCAPE '!'", [$pattern]));
                });
            })
            ->orderBy('value')->orderBy('id');

        $assets = $assetsQuery->paginate(25)->appends(['q' => $search]);
        $this->attachWebObservations($assets);
        $selectedId = $request->string('asset')->toString();
        $selectedAsset = $selectedId !== ''
            ? (clone $assetsQuery)->whereKey($selectedId)->first()
            : null;
        if (! $selectedAsset) {
            $legacyDomainId = $request->string('domain')->toString();
            $selectedAsset = $legacyDomainId !== ''
                ? (clone $assetsQuery)->where('monitored_domain_id', $legacyDomainId)->first()
                : null;
        }
        $selectedAsset ??= $assets->first();

        $summary = [
            'domains' => $workspace->monitoredDomains()->whereNotNull('verified_at')->count(),
            'subdomains' => (clone $assetsQuery)->reorder()->count(),
            'findings' => VulnerabilityFinding::query()->whereHas('monitoredDomain', fn (Builder $query) => $query
                ->where('organization_id', $workspace->id))->whereNotIn('status', ['resolved', 'accepted'])->count(),
        ];

        $preview = $selectedAsset ? $this->assetPreview($selectedAsset) : null;

        return view('domains.vulnerabilities', compact('workspace', 'assets', 'search', 'selectedAsset', 'preview', 'summary'));
    }

    public function vulnerabilityDetail(Request $request, string $organization, string $domain): View
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $monitoredDomain = $workspace->monitoredDomains()->whereNotNull('verified_at')->findOrFail($domain);
        $canManage = Gate::allows('manage', $monitoredDomain);
        $hostname = mb_strtolower(trim($request->string('host')->toString()));
        $hostname = $hostname !== '' ? rtrim($hostname, '.') : $monitoredDomain->hostname;

        abort_unless(
            $hostname === $monitoredDomain->hostname
                || $monitoredDomain->assets()->where('record_type', 'SUBDOMAIN')->where('value', $hostname)->exists(),
            404,
        );

        $preview = $this->surfacePreview($monitoredDomain);
        $host = $preview['hosts']->firstWhere('hostname', $hostname);
        $findings = $monitoredDomain->vulnerabilityFindings()->where('hostname', $hostname)
            ->whereNotIn('status', ['resolved', 'accepted'])->latest('detected_at')->latest('id')->get();

        return view('domains.vulnerability-detail', compact('workspace', 'monitoredDomain', 'hostname', 'host', 'findings', 'preview', 'canManage'));
    }

    public function index(Request $request, string $organization): View
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $history = TlsCheck::query()->whereHas('monitoredDomain', fn (Builder $query) => $query->where('organization_id', $workspace->id));
        $summary = [
            'completed' => (clone $history)->where('status', 'completed')->count(),
            'failed' => (clone $history)->where('status', 'failed')->count(),
            'pending' => (clone $history)->whereIn('status', ['queued', 'running'])->count(),
        ];
        $checks = $history->with('monitoredDomain:id,hostname')->latest()->orderByDesc('id')->paginate(15, pageName: 'checks');
        $domains = $workspace->monitoredDomains()->whereNotNull('verified_at')->orderBy('hostname')
            ->paginate(10, pageName: 'scope');
        $checks->appends(['scope' => $domains->currentPage()])->fragment('tls-history');
        $domains->appends(['checks' => $checks->currentPage()])->fragment('scope');

        return view('domains.attack-surface', compact('workspace', 'summary', 'checks', 'domains'));
    }

    public function show(Request $request, string $organization, string $domain): View
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $monitoredDomain = $workspace->monitoredDomains()->findOrFail($domain);
        $tlsChecks = $monitoredDomain->tlsChecks()->latest()->orderByDesc('id')->limit(10)->get();
        $canManage = Gate::allows('manage', $monitoredDomain);
        $verified = $monitoredDomain->verified_at !== null;
        $tlsCandidates = collect();

        if ($canManage && $verified && ! $monitoredDomain->hasTlsScope()) {
            $current = $monitoredDomain->assets()->whereNull('retired_at');
            if (! (clone $current)->where('record_type', 'CNAME')->exists()) {
                $tlsCandidates = $current->whereIn('record_type', ['A', 'AAAA'])->orderBy('value')->limit(200)->pluck('value')
                    ->filter(fn (string $address) => ObservedNetwork::classify($address) === 'public_unknown')->unique();
            }
        }

        return view('domains.tls', compact('workspace', 'monitoredDomain', 'tlsChecks', 'canManage', 'verified', 'tlsCandidates'));
    }

    /** @return array{assets: Collection, hosts: Collection, observations: Collection, ports: Collection, technologies: Collection, ips: Collection, findings: Collection, threatActors: Collection, latestObservedAt: mixed} */
    private function surfacePreview(MonitoredDomain $domain): array
    {
        $assets = $domain->assets()
            ->select(['id', 'monitored_domain_id', 'record_type', 'value', 'source', 'last_seen_at'])
            ->where('record_type', 'SUBDOMAIN')->whereNull('retired_at')->whereNull('hidden_at')
            ->orderBy('value')->get();
        $hosts = collect([$domain->hostname])->merge($assets->pluck('value'))->unique()->values();
        $observations = $domain->webObservations()
            ->whereIn('hostname', $hosts->all())->where('checked_at', '>=', now()->subHours(48))
            ->orderByDesc('checked_at')->get()->groupBy('hostname')->map(fn (Collection $rows): WebObservation => $rows->first());
        $tls = $domain->tlsChecks()->where('status', 'completed')->latest('finished_at')->latest('id')->first();
        $portScan = $domain->portScanRuns()->with('results')->latest('created_at')->first();
        $signals = $this->signals($observations, $tls);
        if ($portScan?->results->isNotEmpty()) {
            $signals['ports'] = $signals['ports']->merge($portScan->results->map(fn ($result): array => [
                'port' => $result->port,
                'protocol' => strtoupper($result->protocol),
                'state' => $result->state === 'open' ? 'Terbuka' : $result->state,
                'service' => $result->service,
            ]))->unique('port')->sortBy('port')->values();
        }
        $findings = $domain->vulnerabilityFindings()->whereNotIn('status', ['resolved', 'accepted'])
            ->latest('detected_at')->latest('id')->limit(20)->get();
        $hostRows = $hosts->map(function (string $hostname) use ($domain, $assets, $observations, $tls): array {
            $observation = $observations->get($hostname);
            $hostSignals = $this->signals($observation ? collect([$observation]) : collect(), $hostname === $domain->hostname ? $tls : null);

            return [
                'hostname' => $hostname,
                'asset' => $assets->firstWhere('value', $hostname),
                'observation' => $observation,
                'ports' => $hostSignals['ports'],
                'technologies' => $hostSignals['technologies'],
            ];
        });
        if ($portScan?->results->isNotEmpty()) {
            $scanPorts = $portScan->results->map(fn ($result): array => [
                'port' => $result->port,
                'protocol' => strtoupper($result->protocol),
                'state' => $result->state === 'open' ? 'Terbuka' : $result->state,
                'service' => $result->service,
            ]);
            $hostRows = $hostRows->map(function (array $row) use ($domain, $scanPorts): array {
                if ($row['hostname'] !== $domain->hostname) {
                    return $row;
                }

                $row['ports'] = $row['ports']->merge($scanPorts)->unique('port')->sortBy('port')->values();

                return $row;
            });
        }

        return [
            'assets' => $assets,
            'hosts' => $hostRows,
            'observations' => $observations,
            'ports' => $signals['ports'],
            'technologies' => $signals['technologies'],
            'ips' => $observations->pluck('public_ip')->filter()->unique()->values(),
            'findings' => $findings,
            'threatActors' => $findings->pluck('threat_actor')->filter()->unique()->values(),
            'latestObservedAt' => $observations->pluck('checked_at')->filter()->max(),
            'portScan' => $portScan,
        ];
    }

    /** @return array{ports: Collection, technologies: Collection} */
    private function signals(Collection $observations, ?TlsCheck $tls): array
    {
        $ports = collect();
        $technologies = collect(['DNS']);

        foreach ($observations as $observation) {
            $port = $observation->scheme === 'https' ? 443 : 80;
            $ports->push(['port' => $port, 'protocol' => strtoupper($observation->scheme), 'state' => 'Teramati']);
            $technologies->push(strtoupper($observation->scheme));
            foreach ($observation->technologies ?? [] as $technology) {
                if (is_array($technology) && filled($technology['name'] ?? null)) {
                    $technologies->push($technology['name'].(filled($technology['version'] ?? null) ? ' '.$technology['version'] : ''));
                }
            }
            if (ObservedNetwork::classify((string) $observation->public_ip) === 'cloudflare') {
                $technologies->push('Cloudflare WAF/CDN');
            }
        }

        if ($tls?->result) {
            $ports->push(['port' => 443, 'protocol' => 'TLS', 'state' => 'Teramati']);
            $technologies->push('TLS certificate');
        }

        return ['ports' => $ports->unique('port')->values(), 'technologies' => $technologies->unique()->values()];
    }

    private function attachWebObservations($assets): void
    {
        if ($assets->isEmpty()) {
            return;
        }

        $observations = WebObservation::query()
            ->whereIn('monitored_domain_id', $assets->getCollection()->pluck('monitored_domain_id'))
            ->whereIn('hostname', $assets->getCollection()->pluck('value'))
            ->where('checked_at', '>=', now()->subHours(48))
            ->orderByDesc('checked_at')->get()
            ->groupBy(fn (WebObservation $observation): string => $observation->monitored_domain_id.'|'.$observation->hostname)
            ->map(fn (Collection $rows): WebObservation => $rows->first());

        $assets->getCollection()->each(function (DiscoveredAsset $asset) use ($observations): void {
            $asset->setAttribute('web_observation', $observations->get($asset->monitored_domain_id.'|'.$asset->value));
        });
    }

    /** @return array{asset: DiscoveredAsset, domain: MonitoredDomain, hostname: string, observation: ?WebObservation, ports: Collection, technologies: Collection, ips: Collection, findings: Collection, threatActors: Collection, latestObservedAt: mixed, portScan: ?PortScanRun} */
    private function assetPreview(DiscoveredAsset $asset): array
    {
        $domain = $asset->relationLoaded('monitoredDomain') ? $asset->monitoredDomain : $asset->monitoredDomain()->firstOrFail();
        $observation = $asset->getAttribute('web_observation') instanceof WebObservation
            ? $asset->getAttribute('web_observation')
            : $domain->webObservations()->where('hostname', $asset->value)->latest('checked_at')->first();
        $tls = $domain->tlsChecks()->where('status', 'completed')->latest('finished_at')->latest('id')->first();
        $portScan = $domain->portScanRuns()->with('results')->latest('created_at')->first();
        $signals = $this->signals($observation ? collect([$observation]) : collect(), $tls);

        if ($portScan?->results->isNotEmpty() && (! $observation?->public_ip || $portScan->target_ip === $observation->public_ip)) {
            $signals['ports'] = $signals['ports']->merge($portScan->results->map(fn ($result): array => [
                'port' => $result->port,
                'protocol' => strtoupper($result->protocol),
                'state' => $result->state === 'open' ? 'Terbuka' : $result->state,
                'service' => $result->service,
            ]))->unique('port')->sortBy('port')->values();
        }

        $findings = $domain->vulnerabilityFindings()->where('hostname', $asset->value)
            ->whereNotIn('status', ['resolved', 'accepted'])->latest('detected_at')->latest('id')->get();

        return [
            'asset' => $asset,
            'domain' => $domain,
            'hostname' => $asset->value,
            'observation' => $observation,
            'ports' => $signals['ports'],
            'technologies' => $signals['technologies'],
            'ips' => collect([$observation?->public_ip])->filter()->unique()->values(),
            'findings' => $findings,
            'threatActors' => $findings->pluck('threat_actor')->filter()->unique()->values(),
            'latestObservedAt' => $observation?->checked_at,
            'portScan' => $portScan,
        ];
    }
}
