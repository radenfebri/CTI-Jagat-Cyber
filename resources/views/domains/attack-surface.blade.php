@extends('domains.shell')

@section('title', 'Layanan TLS')

@section('domain-content')
    @php
        $labels = ['queued' => 'Dalam antrean', 'running' => 'Berjalan', 'completed' => 'Selesai', 'failed' => 'Gagal', 'cancelled' => 'Dibatalkan'];
        $localTime = fn ($time) => $time?->timezone('Asia/Jakarta')->format('d/m/Y H:i') ?? '—';
    @endphp
    <section class="cti-hero relative isolate overflow-hidden rounded-2xl border border-[#284050] p-6 text-white sm:px-8">
        <x-cti-radar class="pointer-events-none absolute -right-12 -z-10 w-64 opacity-35 sm:right-4 sm:opacity-65"/>
        <p class="cti-eyebrow text-[#8af1df]">Attack Surface</p>
        <h1 class="mt-2 text-3xl font-bold tracking-tight">Layanan TLS eksternal</h1>
        <p class="mt-2 max-w-xl text-sm leading-6 text-[#c0d4e9]">Lihat bukti dari pemeriksaan TLS pada port 443 untuk endpoint publik, termasuk WAF dan CDN, atau IP langsung yang disetujui.</p>
        <a href="#scope" class="cti-primary mt-4 inline-flex">Pilih cakupan pemeriksaan <x-cti-icon name="arrow" class="size-4"/></a>
    </section>

    <dl class="grid gap-3 sm:grid-cols-3">
        @foreach (['completed' => 'Pemeriksaan berhasil', 'failed' => 'Pemeriksaan gagal', 'pending' => 'Menunggu atau berjalan'] as $key => $label)
            <div class="cti-panel p-4">
                <dt class="text-xs font-medium text-muted">{{ $label }}</dt>
                <dd class="mt-1 text-2xl font-bold">{{ $summary[$key] }}</dd>
            </div>
        @endforeach
    </dl>

    <section id="tls-history" class="cti-panel min-w-0 overflow-hidden">
        <div class="border-b border-line p-5">
            <h2 class="text-lg font-bold">Riwayat pemeriksaan TLS</h2>
            <p class="mt-1 text-sm text-muted">Setiap baris mewakili satu pemeriksaan. Waktu ditampilkan dalam WIB.</p>
        </div>
        @if ($checks->isEmpty())
            <p class="p-5 text-sm text-muted">Belum ada pemeriksaan TLS. Pilih domain terverifikasi di bawah untuk melihat cakupannya.</p>
        @else
            <div class="overflow-x-auto">
                <table class="w-full text-left text-sm">
                    <thead class="bg-raised text-xs text-muted">
                        <tr><th scope="col" class="p-3">Endpoint</th><th scope="col" class="p-3">Status</th><th scope="col" class="p-3">Bukti TLS</th><th scope="col" class="p-3">Diminta pada</th></tr>
                    </thead>
                    <tbody class="divide-y divide-line">
                        @foreach ($checks as $check)
                            @php($expiresAt = $check->result['expires_at'] ?? null)
                            <tr>
                                <td class="min-w-40 p-3">
                                    <a class="font-medium wrap-anywhere text-signal hover:underline" href="{{ route('attack-surface.tls', [$workspace, $check->monitoredDomain]) }}">{{ $check->monitoredDomain->hostname }}</a>
                                    <span class="mt-1 block text-xs text-muted">{{ $check->scopeLabel() }}</span>
                                    @if ($check->ip_address)
                                        <span class="block text-xs text-muted">{{ str_contains($check->ip_address, ':') ? '['.$check->ip_address.']' : $check->ip_address }}:443</span>
                                    @endif
                                </td>
                                <td class="p-3">{{ $labels[$check->status] ?? $check->status }}</td>
                                <td class="min-w-44 p-3 text-xs leading-5 text-muted">
                                    @if ($check->result)
                                        <span class="block">{{ $check->result['protocol'] ?? 'TLS' }} · {{ $check->result['issuer'] ?? 'Penerbit tidak tercatat' }}</span>
                                        @if (is_numeric($expiresAt))
                                            <span>Berlaku hingga {{ $localTime(\Illuminate\Support\Carbon::createFromTimestamp($expiresAt, 'UTC')) }}</span>
                                        @endif
                                    @else
                                        —
                                    @endif
                                </td>
                                <td class="min-w-32 p-3 text-xs text-muted">{{ $localTime($check->created_at) }}</td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
            @if ($checks->hasPages())
                <div class="border-t border-line p-4">{{ $checks->links() }}</div>
            @endif
        @endif
    </section>

    <section id="scope" class="cti-panel min-w-0 p-5">
        <h2 class="text-lg font-bold">Cakupan pemeriksaan</h2>
        <p class="mt-1 text-sm text-muted">Pemilik atau admin memilih domain terverifikasi dan mengizinkan pemeriksaan endpoint publik atau IP langsung yang dikelola.</p>
        <ul class="mt-3 divide-y divide-line">
            @forelse ($domains as $target)
                <li class="flex flex-wrap items-center justify-between gap-2 py-3">
                    <span class="text-sm font-semibold wrap-anywhere">{{ $target->hostname }}</span>
                    <a href="{{ route('attack-surface.tls', [$workspace, $target]) }}" class="rounded-lg border border-line px-3 py-2 text-sm text-signal hover:bg-raised">{{ $target->hasTlsScope() ? 'Cakupan disetujui' : 'Lihat cakupan TLS' }}</a>
                </li>
            @empty
                <li class="py-3 text-sm text-muted">Belum ada domain terverifikasi. <a href="{{ route('domains.index', $workspace) }}" class="text-signal underline">Kelola domain dan verifikasi</a></li>
            @endforelse
        </ul>
        @if ($domains->hasPages())
            <div class="border-t border-line pt-4">{{ $domains->links() }}</div>
        @endif
    </section>
@endsection
