<?php

namespace App\Http\Controllers;

use App\Domain\Assets\DiscoveredAsset;
use App\Domain\Assets\MonitoredDomain;
use App\Domain\Assets\ObservedNetwork;
use App\Domain\Assets\PortScanDispatcher;
use App\Domain\Assets\PortScanRun;
use App\Domain\Assets\TlsCheck;
use App\Domain\Assets\VulnerabilityFinding;
use App\Domain\Assets\WebObservation;
use Illuminate\Contracts\View\View;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Pagination\LengthAwarePaginator;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Gate;
use Illuminate\Support\Str;

class AttackSurfaceController extends Controller
{
    public function startPortScan(Request $request, string $organization, string $domain, PortScanDispatcher $portScanDispatcher): RedirectResponse
    {
        $workspace = $request->user()->organizations()->whereKey($organization)->firstOrFail();
        $monitoredDomain = $workspace->monitoredDomains()->findOrFail($domain);
        Gate::authorize('manage', $monitoredDomain);
        $request->validate(['consent' => ['accepted']], ['consent.accepted' => 'Confirm that your organization is authorized to scan this IP address.']);
        abort_unless($monitoredDomain->verified_at !== null, 409, 'The domain is not active.');
        abort_unless($monitoredDomain->hasTlsScope() && $monitoredDomain->tls_scope === TlsCheck::DIRECT, 409, 'A full scan requires an approved direct public IP. Cloudflare and WAF edge addresses are not scanned as origin servers.');
        abort_unless(ObservedNetwork::classify((string) $monitoredDomain->tls_approved_ip) === 'public_unknown', 409, 'The approved address is not a directly scannable public endpoint.');

        if ($monitoredDomain->portScanRuns()->whereIn('status', ['queued', 'running'])->exists()) {
            return back()->with('status', 'A full port scan is already running for this domain.');
        }

        $run = $portScanDispatcher->queue($monitoredDomain, $request->user()->id);

        if ($run === null) {
            return back()->with('status', 'The scan could not be created because the approved direct IP changed.');
        }

        return back()->with('status', 'The TCP 1-65535 manual scan was queued.');
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
            ->with('monitoredDomain')
            ->when($search !== '', function (Builder $query) use ($search): void {
                $pattern = '%'.strtr($search, ['!' => '!!', '%' => '!%', '_' => '!_']).'%';
                $query->where(function (Builder $nested) use ($pattern): void {
                    $nested->whereRaw("value LIKE ? ESCAPE '!'", [$pattern])
                        ->orWhereHas('monitoredDomain', fn (Builder $domain) => $domain
                            ->whereRaw("hostname LIKE ? ESCAPE '!'", [$pattern]));
                });
            })
            ->orderBy('value')->orderBy('id');

        $assets = (clone $assetsQuery)->paginate(25)->appends(['q' => $search]);
        $this->attachWebObservations($assets);
        $this->attachVulnerabilitySummaries($assets);
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
        $canManage = $selectedAsset ? Gate::allows('manage', $selectedAsset->monitoredDomain) : false;

        return view('domains.vulnerabilities', compact('workspace', 'assets', 'search', 'selectedAsset', 'preview', 'summary', 'canManage'));
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
        $severity = $this->severitySummary($findings);

        return view('domains.vulnerability-detail', compact('workspace', 'monitoredDomain', 'hostname', 'host', 'findings', 'severity', 'preview', 'canManage'));
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

        if ($canManage && $verified) {
            $current = $monitoredDomain->assets()->whereNull('retired_at');
            $tlsCandidates = $current->whereIn('record_type', ['A', 'AAAA'])->orderBy('value')->limit(200)->pluck('value')
                ->filter(fn (string $address) => ObservedNetwork::classify($address) === 'public_unknown')->unique();
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
        $signals = $this->signals($observations, $tls, $portScan?->results);
        $findings = $domain->vulnerabilityFindings()->whereNotIn('status', ['resolved', 'accepted'])
            ->latest('detected_at')->latest('id')->limit(20)->get();
        $hostRows = $hosts->map(function (string $hostname) use ($domain, $assets, $observations, $tls, $portScan): array {
            $observation = $observations->get($hostname);
            $portResults = $portScan && ($hostname === $domain->hostname || $observation?->public_ip === $portScan->target_ip)
                ? $portScan->results
                : collect();
            $hostSignals = $this->signals(
                $observation ? collect([$observation]) : collect(),
                $hostname === $domain->hostname ? $tls : null,
                $portResults,
            );

            return [
                'hostname' => $hostname,
                'asset' => $assets->firstWhere('value', $hostname),
                'observation' => $observation,
                'ports' => $hostSignals['ports'],
                'technologies' => $hostSignals['technologies'],
                'technologyGroups' => $hostSignals['technologyGroups'],
                'cveCoverage' => $hostSignals['cveCoverage'],
                'edgeProtected' => $hostSignals['edgeProtected'],
            ];
        });

        return [
            'assets' => $assets,
            'hosts' => $hostRows,
            'observations' => $observations,
            'ports' => $signals['ports'],
            'technologies' => $signals['technologies'],
            'technologyGroups' => $signals['technologyGroups'],
            'cveCoverage' => $signals['cveCoverage'],
            'edgeProtected' => $signals['edgeProtected'],
            'ips' => $observations->pluck('public_ip')->filter()->unique()->values(),
            'findings' => $findings,
            'threatActors' => $findings->pluck('threat_actor')->filter()->unique()->values(),
            'latestObservedAt' => $observations->pluck('checked_at')->filter()->max(),
            'portScan' => $portScan,
        ];
    }

    /** @return array{ports: Collection, technologies: Collection, technologyGroups: Collection, cveCoverage: array{versioned: int, eligible: int}, edgeProtected: bool} */
    private function signals(Collection $observations, ?TlsCheck $tls, ?Collection $portResults = null): array
    {
        $ports = collect();
        $technologyFacts = collect([['name' => 'DNS', 'version' => null, 'category' => 'Infrastructure']]);

        foreach ($observations as $observation) {
            if (in_array($observation->scheme, ['http', 'https'], true)) {
                $port = $observation->scheme === 'https' ? 443 : 80;
                $ports->push(['port' => $port, 'protocol' => strtoupper($observation->scheme), 'state' => 'Observed']);
                $technologyFacts->push(['name' => strtoupper($observation->scheme), 'version' => null, 'category' => 'Protocols']);
            }
            foreach ($observation->technologies ?? [] as $technology) {
                if (is_array($technology) && filled($technology['name'] ?? null)) {
                    $technologyFacts->push([
                        'name' => (string) $technology['name'],
                        'version' => filled($technology['version'] ?? null) ? (string) $technology['version'] : null,
                        'category' => filled($technology['category'] ?? null) ? (string) $technology['category'] : 'Other',
                    ]);
                }
            }
            if (ObservedNetwork::classify((string) $observation->public_ip) === 'cloudflare') {
                $technologyFacts->push(['name' => 'Cloudflare WAF/CDN', 'version' => null, 'category' => 'CDN']);
            }
        }

        if ($tls?->result) {
            $ports->push(['port' => 443, 'protocol' => 'TLS', 'state' => 'Observed']);
            $technologyFacts->push(['name' => 'TLS certificate', 'version' => null, 'category' => 'Security']);
        }

        foreach ($portResults ?? collect() as $result) {
            $ports->push([
                'port' => $result->port,
                'protocol' => strtoupper($result->protocol),
                'state' => $result->state === 'open' ? 'Open' : $result->state,
                'service' => $result->service,
                'product' => $result->product,
                'version' => $result->service_version,
                'cpe' => $result->cpe,
            ]);
            if (filled($result->product ?? null)) {
                $technologyFacts->push([
                    'name' => (string) $result->product,
                    'version' => filled($result->service_version) ? (string) $result->service_version : null,
                    'category' => 'Network services',
                ]);
            }
        }

        $technologyFacts = $technologyFacts
            ->unique(fn (array $technology): string => Str::lower($technology['name'].'|'.($technology['version'] ?? '')))
            ->values();
        $technologies = $technologyFacts->map(fn (array $technology): string => $technology['name']
            .(filled($technology['version']) ? ' '.$technology['version'] : ''));
        $technologyGroups = $technologyFacts->groupBy('category')->map(fn (Collection $items): Collection => $items
            ->map(fn (array $technology): string => $technology['name']
                .(filled($technology['version']) ? ' '.$technology['version'] : ''))->unique()->values());
        $versioned = $technologyFacts->filter(fn (array $technology): bool => filled($technology['version']));
        $eligible = $versioned->filter(fn (array $technology): bool => is_array(
            config('cve.technology_cpe.'.Str::lower($technology['name'])),
        ));

        return [
            'ports' => $ports->unique('port')->sortBy('port')->values(),
            'technologies' => $technologies->unique()->values(),
            'technologyGroups' => $technologyGroups,
            'cveCoverage' => ['versioned' => $versioned->count(), 'eligible' => $eligible->count()],
            'edgeProtected' => $technologyFacts->contains(fn (array $technology): bool => Str::contains(
                Str::lower($technology['name']), ['cloudflare', 'waf'],
            )),
        ];
    }

    private function attachWebObservations(LengthAwarePaginator $assets): void
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

    private function attachVulnerabilitySummaries(LengthAwarePaginator $assets): void
    {
        if ($assets->isEmpty()) {
            return;
        }

        $assetRows = $assets->getCollection();
        $findings = VulnerabilityFinding::query()
            ->select(['id', 'monitored_domain_id', 'hostname', 'severity', 'cvss_score'])
            ->whereIn('monitored_domain_id', $assetRows->pluck('monitored_domain_id')->unique())
            ->whereIn('hostname', $assetRows->pluck('value')->unique())
            ->whereNotIn('status', ['resolved', 'accepted'])
            ->get()
            ->groupBy(fn (VulnerabilityFinding $finding): string => $finding->monitored_domain_id.'|'.$finding->hostname);

        $assetRows->each(function (DiscoveredAsset $asset) use ($findings): void {
            $assetFindings = $findings->get($asset->monitored_domain_id.'|'.$asset->value, collect());
            $asset->setAttribute('vulnerability_summary', $this->severitySummary($assetFindings));
        });
    }

    /** @return array{severity: ?string, label: string, max_score: ?float, count: int} */
    private function severitySummary(Collection $findings): array
    {
        $highest = $findings
            ->map(function (VulnerabilityFinding $finding): array {
                $score = $finding->cvss_score !== null && is_numeric($finding->cvss_score)
                    ? (float) $finding->cvss_score
                    : null;

                return ['severity' => $finding->cvssSeverity(), 'score' => $score];
            })
            ->sortByDesc(fn (array $finding): float => ($finding['severity']->rank() * 1000) + ($finding['score'] ?? -1))
            ->first();

        $highestSeverity = $highest['severity'] ?? null;

        return [
            'severity' => $highestSeverity?->value,
            'label' => $highestSeverity?->label() ?? 'No findings',
            'max_score' => $highest['score'] ?? null,
            'count' => $findings->count(),
        ];
    }

    /** @return array{asset: DiscoveredAsset, domain: MonitoredDomain, hostname: string, observation: ?WebObservation, ports: Collection, technologies: Collection, technologyGroups: Collection, cveCoverage: array{versioned: int, eligible: int}, edgeProtected: bool, ips: Collection, findings: Collection, severity: array{severity: ?string, label: string, max_score: ?float, count: int}, threatActors: Collection, latestObservedAt: mixed, portScan: ?PortScanRun} */
    private function assetPreview(DiscoveredAsset $asset): array
    {
        $domain = $asset->relationLoaded('monitoredDomain') ? $asset->monitoredDomain : $asset->monitoredDomain()->firstOrFail();
        $observation = $asset->getAttribute('web_observation') instanceof WebObservation
            ? $asset->getAttribute('web_observation')
            : $domain->webObservations()->where('hostname', $asset->value)->latest('checked_at')->first();
        $tls = $domain->tlsChecks()->where('status', 'completed')->latest('finished_at')->latest('id')->first();
        $portScan = $domain->portScanRuns()->with('results')->latest('created_at')->first();
        $portResults = $portScan?->results->isNotEmpty() && (! $observation?->public_ip || $portScan->target_ip === $observation->public_ip)
            ? $portScan->results
            : collect();
        $signals = $this->signals($observation ? collect([$observation]) : collect(), $tls, $portResults);

        $findings = $domain->vulnerabilityFindings()->where('hostname', $asset->value)
            ->whereNotIn('status', ['resolved', 'accepted'])->latest('detected_at')->latest('id')->get();

        return [
            'asset' => $asset,
            'domain' => $domain,
            'hostname' => $asset->value,
            'observation' => $observation,
            'ports' => $signals['ports'],
            'technologies' => $signals['technologies'],
            'technologyGroups' => $signals['technologyGroups'],
            'cveCoverage' => $signals['cveCoverage'],
            'edgeProtected' => $signals['edgeProtected'],
            'ips' => collect([$observation?->public_ip])->filter()->unique()->values(),
            'findings' => $findings,
            'severity' => $this->severitySummary($findings),
            'threatActors' => $findings->pluck('threat_actor')->filter()->unique()->values(),
            'latestObservedAt' => $observation?->checked_at,
            'portScan' => $portScan,
        ];
    }
}
