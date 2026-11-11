@extends('domains.shell')

@section('title', 'Cakupan TLS')

@section('domain-content')
    @php
        $statusLabels = ['queued' => 'Dalam antrean', 'running' => 'Berjalan', 'completed' => 'Selesai', 'failed' => 'Gagal', 'cancelled' => 'Dibatalkan'];
        $formatTime = fn ($time) => $time ? $time->timezone('Asia/Jakarta')->format('d/m/Y H:i').' WIB' : '—';
    @endphp
    <section class="cti-hero rounded-2xl border border-[#284050] p-6 text-white">
        <p class="cti-eyebrow text-[#8af1df]">Manajemen Aset · Cakupan TLS</p>
        <h1 class="mt-2 text-2xl font-bold wrap-anywhere">{{ $monitoredDomain->hostname }}</h1>
        <a href="{{ route('domains.show', [$workspace, $monitoredDomain]) }}" class="mt-3 inline-block text-sm text-[#c0d4e9] underline">Buka detail aset</a>
    </section>
    @include('domains.tls-scope')
@endsection
