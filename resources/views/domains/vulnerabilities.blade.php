@extends('domains.shell')

@section('title', 'Kerentanan aset')

@section('domain-content')
    <section class="cti-hero relative isolate overflow-hidden rounded-2xl border border-[#284050] p-6 text-white sm:px-8">
        <x-cti-radar class="pointer-events-none absolute -right-12 -z-10 w-64 opacity-35 sm:right-4 sm:opacity-65"/>
        <p class="cti-eyebrow text-[#8af1df]">Attack Surface</p>
        <h1 class="mt-2 text-2xl font-bold tracking-tight sm:text-3xl">Kerentanan aset</h1>
        <p class="mt-2 max-w-2xl text-sm leading-6 text-[#c0d4e9]">Pantau domain terdaftar, layanan yang terlihat, teknologi yang terdeteksi, dan temuan yang nantinya dikorelasikan dengan CVE serta threat actor.</p>
    </section>

    <dl class="grid gap-3 sm:grid-cols-3">
        <div class="cti-panel p-4"><dt class="text-xs text-muted">Domain terdaftar</dt><dd class="mt-1 text-xl font-bold tabular-nums">{{ $summary['domains'] }}</dd></div>
        <div class="cti-panel p-4"><dt class="text-xs text-muted">Subdomain teramati</dt><dd class="mt-1 text-xl font-bold tabular-nums">{{ $summary['subdomains'] }}</dd></div>
        <div class="cti-panel p-4"><dt class="text-xs text-muted">Temuan terbuka</dt><dd class="mt-1 text-xl font-bold tabular-nums {{ $summary['findings'] > 0 ? 'text-amber-200' : 'text-signal' }}">{{ $summary['findings'] }}</dd></div>
    </dl>

    <div class="grid min-w-0 gap-5 xl:grid-cols-[minmax(0,1.1fr)_minmax(22rem,0.9fr)]">
        <section class="cti-panel min-w-0 overflow-hidden">
            <header class="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-4 sm:px-6">
                <div>
                    <h2 class="text-base font-bold">Aset organisasi</h2>
                    <p class="mt-1 text-xs text-muted">Pilih subdomain untuk melihat ringkasan attack surface.</p>
                </div>
                <form method="get" action="{{ route('attack-surface.vulnerabilities', $workspace) }}" class="flex w-full items-center gap-2 sm:w-auto">
                    <label for="surface-search" class="sr-only">Cari subdomain</label>
                    <input id="surface-search" name="q" value="{{ $search }}" class="cti-field min-w-0 sm:w-52" maxlength="100" placeholder="Cari subdomain">
                    <button class="cti-primary min-h-10 px-3 text-xs"><x-cti-icon name="search" class="size-4"/> Cari</button>
                </form>
            </header>
            @if ($assets->isEmpty())
                <div class="grid justify-items-center gap-3 px-5 py-12 text-center">
                    <span class="grid size-11 place-items-center rounded-xl bg-raised text-muted"><x-cti-icon name="shield"/></span>
                    <p class="text-sm text-muted">Belum ada subdomain terverifikasi untuk dianalisis.</p>
                    <a href="{{ route('domains.index', $workspace) }}" class="text-sm text-signal hover:underline">Buka manajemen domain</a>
                </div>
            @else
                <div class="overflow-x-auto">
                    <table class="w-full min-w-[42rem] text-left text-sm">
                        <thead class="border-b border-line bg-canvas/55 text-[0.7rem] font-semibold tracking-wide text-muted">
                            <tr><th scope="col" class="px-5 py-3 sm:px-6">Subdomain</th><th scope="col" class="px-3 py-3">Domain induk</th><th scope="col" class="px-3 py-3">IP publik</th><th scope="col" class="px-3 py-3">Respons</th><th scope="col" class="px-3 py-3 text-right">Detail</th></tr>
                        </thead>
                        <tbody class="divide-y divide-line">
                            @foreach ($assets as $asset)
                                @php($selected = $selectedAsset?->is($asset))
                                @php($observation = $asset->web_observation)
                                @php($assetUrl = route('attack-surface.vulnerabilities', ['organization' => $workspace, 'q' => $search, 'asset' => $asset->id]))
                                <tr data-surface-row tabindex="0" role="link" data-href="{{ $assetUrl }}#preview" @class(['cursor-pointer bg-signal-bg/55' => $selected, 'cursor-pointer hover:bg-raised/60' => ! $selected])>
                                    <td class="px-5 py-4 sm:px-6"><a href="{{ $assetUrl }}#preview" class="flex min-w-0 items-center gap-2.5"><span @class(['grid size-8 shrink-0 place-items-center rounded-lg border text-signal', 'border-signal/35 bg-signal-bg' => $selected, 'border-line bg-canvas' => ! $selected])><x-cti-icon name="globe" class="size-4"/></span><span class="min-w-0 truncate font-semibold">{{ $asset->value }}</span></a></td>
                                    <td class="px-3 py-4 text-xs text-muted">{{ $asset->monitoredDomain->hostname }}</td>
                                    <td class="px-3 py-4 font-mono text-xs text-muted">{{ $observation?->public_ip ?? '—' }}</td>
                                    <td class="px-3 py-4 text-xs">@if ($observation)<span @class(['rounded-full px-2 py-1 font-semibold', 'bg-signal-bg text-signal' => $observation->status_code < 400, 'bg-amber-500/15 text-amber-200' => $observation->status_code >= 400 && $observation->status_code < 500, 'bg-red-500/15 text-red-200' => $observation->status_code >= 500])>{{ strtoupper($observation->scheme) }} {{ $observation->status_code }}</span>@else<span class="text-muted">Belum diperiksa</span>@endif</td>
                                    <td class="px-3 py-4 text-right"><a href="{{ route('attack-surface.vulnerabilities.detail', ['organization' => $workspace, 'domain' => $asset->monitored_domain_id, 'host' => $asset->value]) }}" class="inline-flex items-center gap-1 text-xs font-semibold text-signal hover:underline">Buka <x-cti-icon name="arrow" class="size-3.5"/></a></td>
                                </tr>
                            @endforeach
                        </tbody>
                    </table>
                </div>
                @if ($assets->hasPages())
                    <div class="border-t border-line px-5 py-3 sm:px-6">{{ $assets->links() }}</div>
                @endif
            @endif
        </section>

        <aside id="preview" class="cti-panel min-w-0 scroll-mt-5 p-5 sm:p-6">
            @if ($preview && $selectedAsset)
                <div class="flex items-start gap-3">
                    <span class="grid size-11 shrink-0 place-items-center rounded-xl bg-signal-bg text-signal"><x-cti-icon name="activity"/></span>
                    <div class="min-w-0">
                        <p class="cti-eyebrow text-signal">Ringkasan aset</p>
                        <h2 class="mt-1 break-all text-lg font-bold">{{ $selectedAsset->value }}</h2>
                        <p class="mt-1 text-xs text-muted">Domain induk: {{ $preview['domain']->hostname }}</p>
                        <p class="mt-1 text-xs text-muted">{{ $preview['latestObservedAt'] ? 'Terakhir diamati '.$preview['latestObservedAt']->timezone('Asia/Jakarta')->format('d/m/Y H:i').' WIB' : 'Belum ada pemeriksaan web dalam 48 jam terakhir.' }}</p>
                    </div>
                </div>

                <div class="mt-5 grid grid-cols-2 gap-2.5">
                    <div class="rounded-xl border border-line bg-canvas p-3"><p class="text-xs text-muted">Subdomain</p><p class="mt-1 text-lg font-bold">1</p></div>
                    <div class="rounded-xl border border-line bg-canvas p-3"><p class="text-xs text-muted">IP publik</p><p class="mt-1 text-lg font-bold">{{ $preview['ips']->count() }}</p></div>
                    <div class="rounded-xl border border-line bg-canvas p-3"><p class="text-xs text-muted">Port teramati</p><p class="mt-1 text-lg font-bold">{{ $preview['ports']->count() }}</p></div>
                    <div class="rounded-xl border border-line bg-canvas p-3"><p class="text-xs text-muted">Temuan</p><p class="mt-1 text-lg font-bold {{ $preview['findings']->isNotEmpty() ? 'text-amber-200' : 'text-signal' }}">{{ $preview['findings']->count() }}</p></div>
                </div>

                <div class="mt-5 grid gap-4">
                    <div>
                        <h3 class="text-sm font-semibold">Port terbuka / layanan</h3>
                        <div class="mt-2 flex flex-wrap gap-2">
                            @forelse ($preview['ports'] as $port)
                                <span class="rounded-lg border border-line bg-canvas px-2.5 py-1.5 text-xs"><strong>{{ $port['port'] }}</strong> · {{ $port['protocol'] }}{{ filled($port['service'] ?? null) ? ' · '.$port['service'] : '' }}</span>
                            @empty
                                <span class="text-xs text-muted">Belum ada hasil pemeriksaan port.</span>
                            @endforelse
                        </div>
                    </div>
                    <div>
                        <h3 class="text-sm font-semibold">Teknologi terdeteksi</h3>
                        <div class="mt-2 flex flex-wrap gap-2">
                            @foreach ($preview['technologies'] as $technology)
                                <span class="rounded-lg border border-signal/20 bg-signal-bg px-2.5 py-1.5 text-xs text-signal">{{ $technology }}</span>
                            @endforeach
                        </div>
                    </div>
                    <div class="rounded-xl border border-line bg-canvas p-3">
                        <h3 class="text-sm font-semibold">CVE &amp; threat actor</h3>
                        @if ($preview['findings']->isEmpty())
                            @php($hasVersionEvidence = collect($preview['observation']?->technologies ?? [])->contains(fn ($technology) => is_array($technology) && filled($technology['version'] ?? null)))
                            <p class="mt-1 text-xs leading-5 text-muted">Belum ada temuan kerentanan. {{ $hasVersionEvidence ? 'Versi terdeteksi dan sedang menunggu korelasi CVE.' : 'Versi produk belum terlihat dari endpoint ini, sehingga CVE belum dibuat untuk mencegah false positive.' }}</p>
                        @else
                            <p class="mt-1 text-xs text-muted">{{ $preview['findings']->count() }} temuan terbuka menunggu triase.</p>
                        @endif
                    </div>
                </div>

                <a href="{{ route('attack-surface.vulnerabilities.detail', ['organization' => $workspace, 'domain' => $preview['domain'], 'host' => $preview['hostname']]) }}" class="cti-primary mt-5 inline-flex w-full justify-center"><x-cti-icon name="arrow" class="size-4"/> Buka detail aset</a>
            @else
                <div class="grid min-h-72 place-items-center text-center">
                    <div><span class="mx-auto grid size-12 place-items-center rounded-2xl bg-raised text-muted"><x-cti-icon name="shield"/></span><p class="mt-3 text-sm text-muted">Pilih subdomain untuk melihat preview.</p></div>
                </div>
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
