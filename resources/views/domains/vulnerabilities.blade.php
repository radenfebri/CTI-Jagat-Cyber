@extends('domains.shell')

@section('title', 'Asset Vulnerabilities')

@section('domain-content')
    @php($scan = $preview['portScan'] ?? null)
    @php($scanActive = in_array($scan?->status, ['queued', 'running'], true))
    @php($canScan = $preview && $canManage && $preview['domain']->hasTlsScope() && $preview['domain']->tls_scope === 'direct')

    <section class="cti-panel flex flex-wrap items-center justify-between gap-4 px-4 py-3.5">
        <div class="flex min-w-0 items-center gap-3">
            <span class="grid size-9 shrink-0 place-items-center rounded-lg bg-signal-bg text-signal"><x-cti-icon name="shield" class="size-4"/></span>
            <div class="min-w-0">
                <p class="cti-eyebrow text-signal">Attack Surface</p>
                <h1 class="mt-0.5 text-lg font-bold tracking-tight">Asset Vulnerabilities</h1>
                <p class="mt-0.5 text-xs text-muted">Ports, public IPs, technologies, CVEs, and related threat actors.</p>
            </div>
        </div>
        <dl class="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs">
            <div><dt class="text-muted">Domains</dt><dd class="font-bold tabular-nums">{{ $summary['domains'] }}</dd></div>
            <div><dt class="text-muted">Assets</dt><dd class="font-bold tabular-nums">{{ $summary['subdomains'] }}</dd></div>
            <div><dt class="text-muted">Open findings</dt><dd class="font-bold tabular-nums {{ $summary['findings'] > 0 ? 'text-amber-200' : 'text-signal' }}">{{ $summary['findings'] }}</dd></div>
        </dl>
    </section>

    <div class="grid min-w-0 items-start gap-3 lg:grid-cols-[minmax(0,1.55fr)_minmax(18rem,0.8fr)]">
        <section class="cti-panel min-w-0 overflow-hidden">
            <header class="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
                <div>
                    <h2 class="text-sm font-bold">Observed assets</h2>
                    <p class="mt-0.5 text-xs text-muted">Select a row to inspect its current exposure.</p>
                </div>
                <form method="get" action="{{ route('attack-surface.vulnerabilities', $workspace) }}" class="flex w-full max-w-xs items-center gap-1.5 sm:w-auto">
                    <label for="surface-search" class="sr-only">Search assets</label>
                    <div class="relative min-w-0 flex-1 sm:w-52">
                        <x-cti-icon name="search" class="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted"/>
                        <input id="surface-search" name="q" value="{{ $search }}" class="cti-field min-h-9 py-1.5 pl-8 text-xs" maxlength="100" placeholder="Search assets">
                    </div>
                    <button class="cti-primary min-h-9 px-2.5" aria-label="Search" title="Search"><x-cti-icon name="search" class="size-3.5"/></button>
                </form>
            </header>

            @if ($assets->isEmpty())
                <div class="grid justify-items-center gap-2 px-5 py-10 text-center">
                    <span class="grid size-10 place-items-center rounded-xl bg-raised text-muted"><x-cti-icon name="shield" class="size-4"/></span>
                    <p class="text-xs text-muted">No discovered assets are ready for analysis.</p>
                </div>
            @else
                <div class="overflow-x-auto">
                    <table class="w-full min-w-[44rem] table-fixed text-left text-xs">
                        <thead class="border-b border-line bg-canvas/55 text-[0.68rem] font-semibold tracking-wide text-muted">
                            <tr>
                                <th scope="col" class="w-[35%] px-4 py-2.5">Asset</th>
                                <th scope="col" class="w-[22%] px-3 py-2.5">Public IP</th>
                                <th scope="col" class="w-[16%] px-3 py-2.5">HTTP</th>
                                <th scope="col" class="w-[20%] px-3 py-2.5">Severity</th>
                                <th scope="col" class="w-10 px-2 py-2.5"><span class="sr-only">Select</span></th>
                            </tr>
                        </thead>
                        <tbody class="divide-y divide-line">
                            @foreach ($assets as $asset)
                                @php($selected = $selectedAsset?->is($asset))
                                @php($observation = $asset->web_observation)
                                @php($assetSeverity = $asset->vulnerability_summary)
                                @php($assetAnchor = 'asset-'.$asset->id)
                                @php($assetUrl = route('attack-surface.vulnerabilities', ['organization' => $workspace, 'q' => $search, 'page' => $assets->currentPage(), 'asset' => $asset->id]))
                                <tr id="{{ $assetAnchor }}" data-surface-row tabindex="0" role="link" data-href="{{ $assetUrl }}#{{ $assetAnchor }}" @if ($selected) aria-current="true" @endif @class(['scroll-mt-4 cursor-pointer border-l-2 transition-colors', 'border-signal bg-signal-bg/55' => $selected, 'border-transparent hover:bg-raised/60' => ! $selected])>
                                    <td class="px-4 py-2.5">
                                        <a href="{{ $assetUrl }}#{{ $assetAnchor }}" class="block min-w-0">
                                            <span class="block truncate font-semibold {{ $selected ? 'text-signal' : '' }}">{{ $asset->value }}</span>
                                            <span class="mt-0.5 block truncate text-[0.68rem] text-muted">{{ $asset->monitoredDomain->hostname }}</span>
                                        </a>
                                    </td>
                                    <td class="px-3 py-2.5 font-mono text-[0.7rem] text-muted">{{ $observation?->public_ip ?? 'Not observed' }}</td>
                                    <td class="px-3 py-2.5">
                                        @if ($observation && filled($observation->scheme) && filled($observation->status_code))
                                            <span @class(['inline-flex rounded-full px-2 py-0.5 text-[0.68rem] font-semibold', 'bg-signal-bg text-signal' => $observation->status_code < 400, 'bg-amber-500/15 text-amber-200' => $observation->status_code >= 400 && $observation->status_code < 500, 'bg-red-500/15 text-red-200' => $observation->status_code >= 500])>{{ strtoupper($observation->scheme) }} {{ $observation->status_code }}</span>
                                        @else
                                            <span class="text-muted">Pending</span>
                                        @endif
                                    </td>
                                    <td class="px-3 py-2.5">
                                        <x-severity-badge :severity="$assetSeverity['severity']" :score="$assetSeverity['max_score']" :label="$assetSeverity['label']" />
                                    </td>
                                    <td class="px-2 py-2.5 text-right text-muted"><x-cti-icon name="chevron" class="size-3.5"/></td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
                @if ($assets->hasPages())
                    <div class="border-t border-line px-3 py-1.5">{{ $assets->onEachSide(1)->links('components.compact-pagination') }}</div>
                @endif
            @endif
        </section>

        <aside id="preview" class="cti-panel min-w-0 scroll-mt-4 p-4 lg:sticky lg:top-3">
            @if ($preview && $selectedAsset)
                <div class="flex items-start gap-2.5">
                    <span class="grid size-9 shrink-0 place-items-center rounded-lg bg-signal-bg text-signal"><x-cti-icon name="activity" class="size-4"/></span>
                    <div class="min-w-0 flex-1">
                        <p class="cti-eyebrow text-signal">Asset Summary</p>
                        <div class="mt-0.5 flex flex-wrap items-center gap-1.5">
                            <h2 class="break-all text-sm font-bold">{{ $selectedAsset->value }}</h2>
                            <x-severity-badge :severity="$preview['severity']['severity']" :score="$preview['severity']['max_score']" :label="$preview['severity']['label']" />
                        </div>
                        <p class="mt-0.5 text-[0.68rem] text-muted">{{ $preview['latestObservedAt'] ? 'Observed '.$preview['latestObservedAt']->timezone('Asia/Jakarta')->format('d F Y, H:i').' WIB' : 'Awaiting web observation' }}</p>
                    </div>
                </div>

                <dl class="mt-4 grid grid-cols-4 gap-1.5">
                    @foreach ([
                        ['Public IPs', $preview['ips']->count()],
                        ['Open ports', $preview['ports']->count()],
                        ['Technologies', $preview['technologies']->count()],
                        ['CVEs', $preview['findings']->count()],
                    ] as [$label, $value])
                        <div class="rounded-lg border border-line bg-canvas px-2 py-2 text-center"><dt class="truncate text-[0.62rem] text-muted">{{ $label }}</dt><dd class="mt-0.5 text-sm font-bold tabular-nums">{{ $value }}</dd></div>
                    @endforeach
                </dl>

                <div class="mt-4 grid gap-3.5">
                    <section>
                        <h3 class="text-xs font-semibold">Public IP</h3>
                        <p class="mt-1.5 font-mono text-xs text-muted">{{ $preview['ips']->first() ?? 'Not observed' }}</p>
                    </section>
                    <section>
                        <h3 class="text-xs font-semibold">Open ports and services</h3>
                        <div class="mt-1.5 flex flex-wrap gap-1.5">
                            @forelse ($preview['ports'] as $port)
                                <span class="rounded-md border border-line bg-canvas px-2 py-1 text-[0.68rem]"><strong>{{ $port['port'] }}</strong> / {{ $port['protocol'] }}{{ filled($port['service'] ?? null) ? ' / '.$port['service'] : '' }}{{ filled($port['version'] ?? null) ? ' '.$port['version'] : '' }}</span>
                            @empty
                                <span class="text-[0.68rem] text-muted">No open ports recorded.</span>
                            @endforelse
                        </div>
                    </section>
                    <section>
                        <h3 class="text-xs font-semibold">Detected technologies</h3>
                        <div class="mt-1.5 grid gap-2">
                            @forelse ($preview['technologyGroups'] as $category => $technologies)
                                <div>
                                    <p class="text-[0.62rem] font-semibold uppercase tracking-wide text-muted">{{ $category }}</p>
                                    <div class="mt-1 flex flex-wrap gap-1">
                                        @foreach ($technologies as $technology)
                                            <span class="rounded-md border border-signal/20 bg-signal-bg px-1.5 py-0.5 text-[0.65rem] text-signal">{{ $technology }}</span>
                                        @endforeach
                                    </div>
                                </div>
                            @empty
                                <span class="text-[0.68rem] text-muted">No technology fingerprint yet.</span>
                            @endforelse
                        </div>
                        @if ($preview['edgeProtected'])
                            <p class="mt-2 text-[0.65rem] leading-4 text-amber-200">Edge fingerprint only. Origin products remain hidden unless the scanner is explicitly allowlisted or given an authorized direct origin.</p>
                        @endif
                    </section>
                    <section class="rounded-lg border border-line bg-canvas p-3">
                        <h3 class="text-xs font-semibold">CVE and threat intelligence</h3>
                        @if ($preview['findings']->isEmpty())
                            @if ($preview['cveCoverage']['eligible'] > 0)
                                <p class="mt-1 text-[0.68rem] leading-5 text-muted">Versioned product evidence is available. Correlation is pending, or NVD has no matching affected range.</p>
                            @elseif ($preview['cveCoverage']['versioned'] > 0)
                                <p class="mt-1 text-[0.68rem] leading-5 text-muted">Versions were detected, but none currently has a reliable CPE mapping.</p>
                            @else
                                <p class="mt-1 text-[0.68rem] leading-5 text-muted">No reliable product version is exposed. CVEs are not guessed from a product name alone.</p>
                            @endif
                        @else
                            <div class="mt-2 grid gap-2">
                                @foreach ($preview['findings']->take(3) as $finding)
                                    <div class="text-[0.68rem]">
                                        <div class="flex flex-wrap items-center gap-1.5"><p class="font-semibold">{{ $finding->cve_id ?? $finding->title }}</p><x-severity-badge :severity="$finding->cvssSeverity()->value" :score="$finding->cvss_score" :label="$finding->cvssSeverity()->label()" /></div>
                                        <p class="mt-0.5 text-muted">{{ $finding->threat_actor ?: 'No actor attribution' }}</p>
                                    </div>
                                @endforeach
                            </div>
                        @endif
                    </section>
                </div>

                <div class="mt-4 grid gap-2 border-t border-line pt-3">
                    @if ($canScan)
                        @if ($scanActive)
                            <button type="button" disabled class="cti-primary min-h-9 w-full cursor-not-allowed px-3 py-2 text-xs opacity-55"><x-cti-icon name="activity" class="size-3.5"/> Scan in Progress</button>
                        @else
                            <form method="post" action="{{ route('attack-surface.port-scans.store', ['organization' => $workspace, 'domain' => $preview['domain']]) }}">
                                @csrf
                                <input type="hidden" name="consent" value="1">
                                <button class="cti-primary min-h-9 w-full px-3 py-2 text-xs"><x-cti-icon name="activity" class="size-3.5"/> Manual Scan</button>
                            </form>
                        @endif
                    @endif
                    <a href="{{ route('attack-surface.vulnerabilities.detail', ['organization' => $workspace, 'domain' => $preview['domain'], 'host' => $preview['hostname']]) }}" @class(['inline-flex min-h-8 items-center justify-center gap-1.5 rounded-lg text-xs font-semibold transition-colors', 'text-signal hover:bg-raised' => $canScan, 'cti-primary px-3 py-2' => ! $canScan])>View Details <x-cti-icon name="arrow" class="size-3.5"/></a>
                </div>
            @else
                <div class="grid min-h-56 place-items-center text-center"><p class="text-xs text-muted">Select an asset to view its exposure summary.</p></div>
            @endif
        </aside>
    </div>

    <script>
        document.querySelectorAll('[data-surface-row]').forEach((row) => {
            const open = () => window.location.assign(row.dataset.href);
            row.addEventListener('click', (event) => { if (!event.target.closest('a')) open(); });
            row.addEventListener('keydown', (event) => { if ((event.key === 'Enter' || event.key === ' ') && !event.target.closest('a')) { event.preventDefault(); open(); } });
        });
    </script>
@endsection
