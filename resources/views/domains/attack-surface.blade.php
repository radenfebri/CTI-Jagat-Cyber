@extends('domains.shell')

@section('title', 'TLS Services')

@section('domain-content')
    @php
        $labels = ['queued' => 'Queued', 'running' => 'Running', 'completed' => 'Completed', 'failed' => 'Failed', 'cancelled' => 'Cancelled'];
        $localTime = fn ($time) => $time?->timezone('Asia/Jakarta')->format('d/m/Y H:i') ?? '—';
    @endphp

    <section class="cti-hero relative isolate overflow-hidden rounded-2xl border border-[#284050] p-5 text-white sm:px-6">
        <x-cti-radar class="pointer-events-none absolute -right-12 -z-10 w-64 opacity-35 sm:right-4 sm:opacity-65"/>
        <p class="cti-eyebrow text-[#8af1df]">Attack Surface</p>
        <h1 class="mt-2 text-2xl font-bold tracking-tight">External TLS Services</h1>
        <p class="mt-2 max-w-xl text-xs leading-5 text-[#c0d4e9]">Review port 443 TLS evidence for public endpoints, including WAF and CDN addresses or approved direct IPs.</p>
        <a href="#scope" class="cti-primary mt-4 inline-flex">Review Scope <x-cti-icon name="arrow" class="size-4"/></a>
    </section>

    <dl class="grid gap-3 sm:grid-cols-3">
        @foreach (['completed' => 'Completed', 'failed' => 'Failed', 'pending' => 'Pending or running'] as $key => $label)
            <div class="cti-panel p-4">
                <dt class="text-xs font-medium text-muted">{{ $label }}</dt>
                <dd class="mt-1 text-xl font-bold">{{ $summary[$key] }}</dd>
            </div>
        @endforeach
    </dl>

    <section id="tls-history" class="cti-panel min-w-0 overflow-hidden">
        <div class="border-b border-line p-4">
            <h2 class="text-base font-bold">TLS Check History</h2>
            <p class="mt-1 text-xs text-muted">Each row represents one check. Times are shown in WIB.</p>
        </div>
        @if ($checks->isEmpty())
            <p class="p-4 text-xs text-muted">No TLS checks are available. Select a domain below to review its scope.</p>
        @else
            <div class="overflow-x-auto">
                <table class="w-full text-left text-xs">
                    <thead class="bg-raised text-xs text-muted">
                        <tr>
                            <th scope="col" class="p-3">Endpoint</th>
                            <th scope="col" class="p-3">Status</th>
                            <th scope="col" class="p-3">TLS Evidence</th>
                            <th scope="col" class="p-3">Requested</th>
                        </tr>
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
                                <td class="min-w-44 p-3 leading-5 text-muted">
                                    @if ($check->result)
                                        <span class="block">{{ $check->result['protocol'] ?? 'TLS' }} · {{ $check->result['issuer'] ?? 'Issuer unavailable' }}</span>
                                        @if (is_numeric($expiresAt))
                                            <span>Valid until {{ $localTime(\Illuminate\Support\Carbon::createFromTimestamp($expiresAt, 'UTC')) }}</span>
                                        @endif
                                    @else
                                        —
                                    @endif
                                </td>
                                <td class="min-w-32 p-3 text-muted">{{ $localTime($check->created_at) }}</td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
            @if ($checks->hasPages())
                <div class="border-t border-line px-3 py-1.5">{{ $checks->onEachSide(1)->links('components.compact-pagination') }}</div>
            @endif
        @endif
    </section>

    <section id="scope" class="cti-panel min-w-0 p-4">
        <h2 class="text-base font-bold">Monitoring Scope</h2>
        <p class="mt-1 text-xs text-muted">Owners and administrators manage public endpoint or directly managed IP monitoring scope.</p>
        <ul class="mt-3 divide-y divide-line">
            @forelse ($domains as $target)
                <li class="flex flex-wrap items-center justify-between gap-2 py-2.5">
                    <span class="text-xs font-semibold wrap-anywhere">{{ $target->hostname }}</span>
                    <a href="{{ route('attack-surface.tls', [$workspace, $target]) }}" class="rounded-lg border border-line px-2.5 py-1.5 text-xs text-signal hover:bg-raised">{{ $target->hasTlsScope() ? 'Approved' : 'Review TLS Scope' }}</a>
                </li>
            @empty
                <li class="py-3 text-xs text-muted">No domains are registered. <a href="{{ route('domains.index', $workspace) }}" class="text-signal underline">Manage domains</a></li>
            @endforelse
        </ul>
        @if ($domains->hasPages())
            <div class="border-t border-line px-3 py-1.5">{{ $domains->onEachSide(1)->links('components.compact-pagination') }}</div>
        @endif
    </section>
@endsection
