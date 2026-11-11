@extends('domains.shell')

@section('title', 'Inventaris aset')

@section('domain-content')
    <section class="cti-hero relative isolate flex min-h-48 flex-wrap items-end justify-between gap-6 overflow-hidden rounded-2xl border border-[#284050] p-6 text-white sm:p-8">
        <x-cti-radar class="pointer-events-none absolute -right-12 -z-10 w-64 opacity-35 sm:right-4 sm:opacity-65"/>
        <div>
            <p class="cti-eyebrow text-[#8af1df]">Manajemen Aset</p>
            <h1 class="mt-2 text-3xl font-bold tracking-tight">Inventaris web</h1>
            <p class="mt-2 max-w-xl text-sm leading-6 text-[#c0d4e9]">Subdomain dengan respons HTTP dalam 48 jam terakhir, beserta IP publik yang dipakai saat diperiksa.</p>
        </div>
        <a href="{{ route('domains.index', $workspace) }}" class="cti-primary"><x-cti-icon name="settings" class="size-4"/> Kelola domain</a>
    </section>

    <dl class="grid gap-3 sm:grid-cols-3">
        @foreach ([
            ['globe', 'Subdomain merespons', $summary['subdomains']],
            ['organization', 'Domain dengan hasil', $summary['domains']],
            ['server', 'IP publik unik', $summary['addresses']],
        ] as [$icon, $label, $value])
            <div class="cti-panel flex items-center gap-4 p-4">
                <span class="grid size-11 shrink-0 place-items-center rounded-xl bg-signal-bg text-signal"><x-cti-icon :name="$icon"/></span>
                <div>
                    <dt class="text-xs font-medium text-muted">{{ $label }}</dt>
                    <dd class="mt-0.5 text-2xl font-bold tabular-nums">{{ $value }}</dd>
                </div>
            </div>
        @endforeach
    </dl>

    <section class="cti-panel min-w-0 overflow-hidden">
        <div class="flex flex-wrap items-end justify-between gap-4 border-b border-line p-5">
            <div>
                <h2 class="text-lg font-bold">{{ $hidden ? 'Observasi disembunyikan' : 'Subdomain yang merespons' }}</h2>
                <p class="mt-1 text-sm text-muted">IP bisa berupa alamat CDN atau WAF yang menerima koneksi.</p>
            </div>
            <form method="get" action="{{ route('assets.inventory', $workspace) }}" class="flex w-full flex-wrap items-end gap-2 sm:w-auto">
                <div class="min-w-44 flex-1">
                    <label for="search-assets" class="mb-1 block text-xs font-semibold text-muted">Subdomain atau IP publik</label>
                    <input id="search-assets" name="q" value="{{ $search }}" class="cti-field w-full" maxlength="100" placeholder="Cari di inventaris">
                </div>
                <div>
                    <label for="asset-state" class="mb-1 block text-xs font-semibold text-muted">Tampilan</label>
                    <select id="asset-state" name="state" class="cti-field">
                        <option value="all" @selected(! $hidden)>Ditampilkan</option>
                        <option value="hidden" @selected($hidden)>Disembunyikan</option>
                    </select>
                </div>
                <button class="cti-primary"><x-cti-icon name="search" class="size-4"/> Cari</button>
            </form>
        </div>

        @if ($assets->isEmpty())
            <div class="grid justify-items-center gap-3 px-5 py-10 text-center">
                <span class="grid size-12 place-items-center rounded-2xl bg-raised text-muted"><x-cti-icon name="globe"/></span>
                <p class="font-semibold">Belum ada hasil untuk tampilan ini</p>
                <p class="max-w-md text-sm text-muted">Aktifkan pemeriksaan web dari detail domain terverifikasi. Hasil tampil setelah cron menjalankan pemeriksaan.</p>
                <a href="{{ route('domains.index', $workspace) }}" class="cti-primary"><x-cti-icon name="arrow" class="size-4"/> Lihat domain</a>
            </div>
        @else
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm">
                    <thead class="bg-raised text-xs text-muted">
                        <tr><th scope="col" class="px-5 py-3">Subdomain</th><th scope="col" class="px-5 py-3">IP publik</th><th scope="col" class="px-5 py-3">Respons</th><th scope="col" class="px-5 py-3">Diperiksa (WIB)</th><th scope="col" class="px-5 py-3">Domain</th></tr>
                    </thead>
                    <tbody class="divide-y divide-line">
                        @foreach ($assets as $asset)
                            <tr class="hover:bg-raised/60">
                                <td class="min-w-44 px-5 py-4 font-semibold wrap-anywhere">{{ $asset->hostname }}</td>
                                <td class="min-w-36 px-5 py-4 font-mono text-xs text-muted">{{ $asset->public_ip }}</td>
                                @php($status = (int) $asset->status_code)
                                <td class="min-w-32 px-5 py-4"><span @class([
                                    'inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-semibold',
                                    'bg-signal-bg text-signal' => $status >= 200 && $status < 300,
                                    'bg-amber-500/15 text-amber-200' => $status >= 300 && $status < 400,
                                    'bg-red-500/15 text-red-200' => $status >= 400,
                                ])><x-cti-icon :name="$status >= 200 && $status < 300 ? 'check' : 'activity'" class="size-3.5"/> {{ strtoupper($asset->scheme) }} {{ $status }}</span></td>
                                <td class="min-w-36 px-5 py-4 text-xs text-muted">{{ $asset->checked_at->timezone('Asia/Jakarta')->format('d/m/Y H:i') }}</td>
                                <td class="min-w-36 px-5 py-4">
                                    <a href="{{ route('domains.show', [$workspace, $asset->monitoredDomain, 'assets' => $hidden ? 'hidden' : 'subdomains']) }}#inventaris" class="inline-flex items-center gap-1.5 wrap-anywhere text-signal hover:underline">{{ $asset->monitoredDomain->hostname }} <x-cti-icon name="chevron" class="size-3.5"/></a>
                                </td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
            @if ($assets->hasPages())
                <div class="border-t border-line p-4">{{ $assets->links() }}</div>
            @endif
        @endif
    </section>
@endsection
