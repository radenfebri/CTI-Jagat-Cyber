@extends('layouts.portal')

@section('title', 'Overview')

@section('portal-content')
    <section class="cti-panel relative isolate flex min-h-32 items-center overflow-hidden px-5 py-5 sm:px-6">
        <x-cti-radar class="pointer-events-none absolute -right-12 -z-10 w-56 opacity-25 sm:right-4"/>
        <div class="min-w-0 max-w-2xl">
            <p class="cti-eyebrow text-signal">Security Operations</p>
            <h1 class="mt-1 text-xl font-bold tracking-tight">Security Overview</h1>
            <p class="mt-1 text-xs leading-5 text-muted">Monitor organization access and security coverage from one workspace.</p>
        </div>
    </section>

    @if ($organization)
        @php
            $roles = ['owner' => 'Owner', 'admin' => 'Admin', 'analyst' => 'Analyst', 'viewer' => 'Viewer'];
            $statuses = ['trial' => 'Trial', 'active' => 'Active', 'past_due' => 'Past due', 'suspended' => 'Suspended', 'cancelled' => 'Cancelled', 'expired' => 'Expired'];
        @endphp
        <dl class="grid grid-cols-2 gap-2 lg:grid-cols-3">
            @foreach ([
                ['users', 'Members', $memberCount],
                ['shield', 'Your role', $roles[$organization->pivot->role] ?? $organization->pivot->role],
                ['organization', 'Subscription', $statuses[$organization->subscription_status] ?? $organization->subscription_status],
            ] as [$icon, $label, $value])
                <div class="cti-panel flex min-w-0 items-center gap-3 px-3 py-2.5">
                    <span class="grid size-8 shrink-0 place-items-center rounded-lg bg-signal-bg text-signal"><x-cti-icon :name="$icon" class="size-3.5"/></span>
                    <div class="min-w-0"><dt class="text-[0.68rem] text-muted">{{ $label }}</dt><dd class="mt-0.5 truncate text-sm font-bold">{{ $value }}</dd></div>
                </div>
            @endforeach
        </dl>

        <section id="organization" class="cti-panel max-w-xl p-4">
            <p class="cti-eyebrow text-signal">Workspace Access</p>
            <h2 class="mt-1 text-sm font-bold">Active Organization</h2>
            <p class="mt-1 text-xs wrap-break-word text-muted">{{ $organization->name }}</p>
            @if ($organizations->count() > 1)
                <form method="get" action="{{ route('dashboard') }}" class="mt-3 flex items-end gap-2">
                    <div class="min-w-0 flex-1">
                        <label for="organization-choice" class="mb-1 block text-[0.68rem] text-muted">Switch organization</label>
                        <select name="organization" id="organization-choice" class="cti-field min-h-9 py-1.5 text-xs">
                            @foreach ($organizations as $option)
                                <option value="{{ $option->id }}" @selected($option->id === $organization->id)>{{ $option->name }}</option>
                            @endforeach
                        </select>
                    </div>
                    <button type="submit" class="cti-primary min-h-9 px-2.5" aria-label="Open organization" title="Open organization"><x-cti-icon name="arrow" class="size-3.5"/></button>
                </form>
            @endif
        </section>
    @else
        <section class="cti-panel p-4">
            <h2 class="text-sm font-bold">No Organization</h2>
            <p class="mt-1 text-xs text-muted">This account is not a member of an organization.</p>
        </section>
    @endif
@endsection
