@extends('domains.shell')

@section('title', 'TLS Scope')

@section('domain-content')
    @php
        $statusLabels = ['queued' => 'Queued', 'running' => 'Running', 'completed' => 'Completed', 'failed' => 'Failed', 'cancelled' => 'Cancelled'];
        $formatTime = fn ($time) => $time ? $time->timezone('Asia/Jakarta')->format('d/m/Y H:i').' WIB' : '—';
    @endphp
    <section class="cti-hero rounded-2xl border border-[#284050] p-5 text-white">
        <p class="cti-eyebrow text-[#8af1df]">Asset Management · TLS Scope</p>
        <h1 class="mt-2 text-xl font-bold wrap-anywhere">{{ $monitoredDomain->hostname }}</h1>
        <a href="{{ route('domains.show', [$workspace, $monitoredDomain]) }}" class="mt-3 inline-flex items-center gap-1 text-xs text-[#c0d4e9] hover:text-white">
            View asset <x-cti-icon name="arrow" class="size-3.5"/>
        </a>
    </section>
    @include('domains.tls-scope')
@endsection
