@extends('layouts.workspace')

@section('content')
    @php
        $activeOrganization = $workspace ?? $organization ?? null;
        $dashboardUrl = route('dashboard', $activeOrganization ? ['organization' => $activeOrganization->id] : []);
        $onDashboard = request()->routeIs('dashboard');
        $onDomains = request()->routeIs('domains.*');
        $onAttackSurface = request()->routeIs('attack-surface*');
        $onVulnerabilities = request()->routeIs('attack-surface.vulnerabilities*');
        $menu = 'flex items-center gap-2 rounded-lg px-2 py-1.5 text-[0.72rem] font-semibold transition-colors hover:bg-raised hover:text-ink';
        $item = 'block rounded-md border-l-2 border-transparent px-2 py-1.5 text-[0.68rem] transition-colors hover:bg-raised hover:text-ink';
        $highlight = 'border-signal bg-signal-bg text-signal';
        $section = 'bg-raised/45 text-ink';
    @endphp
    <div class="min-h-dvh lg:grid lg:grid-cols-[13rem_minmax(0,1fr)]">
        <aside class="flex flex-col gap-3 border-b border-line bg-panel p-3 lg:sticky lg:top-0 lg:h-dvh lg:gap-5 lg:overflow-y-auto lg:border-r lg:border-b-0 lg:p-3.5">
            <a href="{{ $dashboardUrl }}" class="flex items-center gap-2.5">
                <img src="{{ asset('jagat-mark.svg') }}" alt="" width="36" height="36" class="size-9">
                <span class="grid min-w-0 gap-0.5">
                    <span class="truncate text-sm leading-tight font-bold">{{ config('app.name') }}</span>
                    <span class="whitespace-nowrap text-[0.58rem] font-semibold tracking-[0.16em] uppercase text-muted">Cyber Intelligence</span>
                </span>
            </a>
            <nav aria-label="Workspace navigation" class="flex min-h-0 flex-1 flex-col gap-1 sm:grid sm:grid-cols-2 lg:flex lg:grid-cols-1">
                <p class="mb-1.5 hidden px-2 text-[0.58rem] font-semibold tracking-[0.16em] uppercase text-muted lg:block">Workspace</p>
                <a href="{{ $dashboardUrl }}" class="{{ $menu }} {{ $onDashboard ? $highlight : 'text-muted' }}" @if ($onDashboard) aria-current="page" @endif>
                    <x-cti-icon name="dashboard" class="size-3.5"/> Overview
                </a>
                @if ($activeOrganization)
                    <details class="group" @if ($onAttackSurface) open @endif>
                        <summary class="{{ $menu }} cursor-pointer list-none {{ $onAttackSurface ? $section : 'text-muted' }} [&::-webkit-details-marker]:hidden">
                            <x-cti-icon name="shield" class="size-3.5"/> Attack Surface
                            <x-cti-icon name="chevron" class="ml-auto size-3 group-open:rotate-90"/>
                        </summary>
                        <ul class="mt-1 ml-3.5 space-y-0.5 border-l border-line pl-1.5 text-muted">
                            <li><a href="{{ route('attack-surface.vulnerabilities', $activeOrganization) }}" class="{{ $item }} {{ $onVulnerabilities ? $highlight : '' }}" @if ($onVulnerabilities) aria-current="page" @endif>Asset Vulnerabilities</a></li>
                        </ul>
                    </details>
                    <a href="{{ $dashboardUrl }}#organization" class="{{ $menu }} text-muted"><x-cti-icon name="users" class="size-3.5"/> Organization</a>
                    <details class="group lg:mt-auto lg:pt-3" @if ($onDomains) open @endif>
                        <summary class="{{ $menu }} cursor-pointer list-none {{ $onDomains ? $section : 'text-muted' }} [&::-webkit-details-marker]:hidden">
                            <x-cti-icon name="organization" class="size-3.5"/> Asset Management
                            <x-cti-icon name="chevron" class="ml-auto size-3 group-open:rotate-90"/>
                        </summary>
                        <ul class="mt-1 ml-3.5 space-y-0.5 border-l border-line pl-1.5 text-muted">
                            <li><a href="{{ route('domains.index', $activeOrganization) }}" class="{{ $item }} {{ $onDomains ? $highlight : '' }}" @if ($onDomains) aria-current="{{ request()->routeIs('domains.index') ? 'page' : 'location' }}" @endif>Domain</a></li>
                        </ul>
                    </details>
                @endif
            </nav>
            @if ($activeOrganization)
                <div class="mt-auto hidden rounded-lg border border-line bg-canvas px-2.5 py-2 lg:block">
                    <p class="text-[0.56rem] font-semibold tracking-[0.16em] uppercase text-signal">Active Organization</p>
                    <p class="mt-1 text-[0.68rem] wrap-anywhere text-muted">{{ $activeOrganization->name }}</p>
                </div>
            @endif
        </aside>

        <div class="min-w-0">
            @include('layouts.portal-header')
            <main id="main" class="mx-auto grid max-w-[100rem] gap-4 px-3 py-4 sm:px-5 sm:py-6 lg:px-7">
                @yield('portal-content')
            </main>
        </div>
    </div>
@endsection
