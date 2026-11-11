@extends('layouts.workspace')

@section('content')
    @php
        $activeOrganization = $workspace ?? $organization ?? null;
        $dashboardUrl = route('dashboard', $activeOrganization ? ['organization' => $activeOrganization->id] : []);
        $onDashboard = request()->routeIs('dashboard');
        $onDomains = request()->routeIs('domains.*');
        $onAttackSurface = request()->routeIs('attack-surface*');
        $menu = 'flex items-center gap-2 rounded-xl px-3 py-2 text-[13px] font-semibold hover:bg-raised hover:text-ink';
        $item = 'block rounded-lg px-3 py-1.5 text-[13px] hover:bg-raised hover:text-ink';
        $highlight = 'bg-signal-bg text-signal';
    @endphp
    <div class="min-h-dvh lg:grid lg:grid-cols-[15.5rem_minmax(0,1fr)]">
        <aside class="flex flex-col gap-4 border-b border-line bg-panel p-4 lg:sticky lg:top-0 lg:h-dvh lg:gap-8 lg:overflow-y-auto lg:border-r lg:border-b-0 lg:p-5">
            <a href="{{ $dashboardUrl }}" class="flex items-center gap-3">
                <img src="{{ asset('jagat-mark.svg') }}" alt="" width="40" height="40" class="size-10">
                <span class="grid gap-0.5">
                    <span class="text-[15px] leading-tight font-bold">{{ config('app.name') }}</span>
                    <span class="cti-eyebrow text-muted">Intelijen siber</span>
                </span>
            </a>
            <nav aria-label="Navigasi workspace" class="flex min-h-0 flex-1 flex-col gap-1 sm:grid sm:grid-cols-2 lg:flex lg:grid-cols-1">
                <p class="cti-eyebrow mb-2 hidden px-3 text-muted lg:block">Workspace</p>
                <a href="{{ $dashboardUrl }}" class="{{ $menu }} {{ $onDashboard ? $highlight : 'text-muted' }}" @if ($onDashboard) aria-current="page" @endif>
                    <x-cti-icon name="dashboard" class="size-4"/> Ringkasan
                </a>
                @if ($activeOrganization)
                    <details class="group" @if ($onAttackSurface) open @endif>
                        <summary class="{{ $menu }} cursor-pointer list-none {{ $onAttackSurface ? $highlight : 'text-muted' }} [&::-webkit-details-marker]:hidden">
                            <x-cti-icon name="shield" class="size-4"/> Attack Surface
                            <x-cti-icon name="chevron" class="ml-auto size-3 group-open:rotate-90"/>
                        </summary>
                        <ul class="ml-4 space-y-1 border-l border-line pl-2 text-muted">
                            <li><a href="{{ route('attack-surface.vulnerabilities', $activeOrganization) }}" class="{{ $item }} {{ request()->routeIs('attack-surface.vulnerabilities*') ? $highlight : '' }}" @if (request()->routeIs('attack-surface.vulnerabilities*')) aria-current="page" @endif>Kerentanan aset</a></li>
                        </ul>
                    </details>
                    <a href="{{ $dashboardUrl }}#organization" class="{{ $menu }} text-muted"><x-cti-icon name="users" class="size-4"/> Organisasi</a>
                    @if ($canViewAudit ?? false)
                        <a href="#activity" class="{{ $menu }} text-muted"><x-cti-icon name="activity" class="size-4"/> Aktivitas</a>
                    @endif
                    <details class="group lg:mt-auto lg:pt-4" @if ($onDomains) open @endif>
                        <summary class="{{ $menu }} cursor-pointer list-none text-muted [&::-webkit-details-marker]:hidden">
                            <x-cti-icon name="organization" class="size-4"/> Manajemen Aset
                            <x-cti-icon name="chevron" class="ml-auto size-3 group-open:rotate-90"/>
                        </summary>
                        <ul class="ml-4 space-y-1 border-l border-line pl-2 text-muted">
                            <li><a href="{{ route('domains.index', $activeOrganization) }}" class="{{ $item }} {{ $onDomains ? $highlight : '' }}" @if ($onDomains) aria-current="{{ request()->routeIs('domains.index') ? 'page' : 'location' }}" @endif>Domain &amp; verifikasi</a></li>
                        </ul>
                    </details>
                @endif
            </nav>
            @if ($activeOrganization)
                <div class="mt-auto hidden rounded-xl border border-line bg-canvas px-3.5 py-3 lg:block">
                    <p class="cti-eyebrow text-signal">Organisasi aktif</p>
                    <p class="mt-1 text-xs wrap-anywhere text-muted">{{ $activeOrganization->name }}</p>
                </div>
            @endif
        </aside>

        <div class="min-w-0">
            @include('layouts.portal-header')
            <main id="main" class="mx-auto grid max-w-[100rem] gap-6 px-4 py-6 sm:px-7 sm:py-8 lg:px-9">
                @yield('portal-content')
            </main>
        </div>
    </div>
@endsection
