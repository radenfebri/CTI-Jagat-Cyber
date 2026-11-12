@extends('domains.shell')

@section('title', 'Asset Inventory')

@section('domain-content')
    <section class="cti-panel flex flex-wrap items-center justify-between gap-4 px-4 py-3.5">
        <div><p class="cti-eyebrow text-signal">Asset Management</p><h1 class="mt-0.5 text-lg font-bold">Web Asset Inventory</h1><p class="mt-0.5 text-xs text-muted">Subdomains with HTTP responses observed within the last 48 hours.</p></div>
        <dl class="flex items-center gap-5 text-xs">
            <div><dt class="text-muted">Assets</dt><dd class="font-bold tabular-nums">{{ $summary['subdomains'] }}</dd></div>
            <div><dt class="text-muted">Domains</dt><dd class="font-bold tabular-nums">{{ $summary['domains'] }}</dd></div>
            <div><dt class="text-muted">Public IPs</dt><dd class="font-bold tabular-nums">{{ $summary['addresses'] }}</dd></div>
        </dl>
    </section>

    <section class="cti-panel min-w-0 overflow-hidden">
        <header class="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
            <div><h2 class="text-sm font-bold">Responsive Subdomains</h2><p class="mt-0.5 text-[0.68rem] text-muted">Addresses may belong to a CDN or WAF edge.</p></div>
            <form method="get" action="{{ route('assets.inventory', $workspace) }}" class="flex w-full max-w-xs items-center gap-1.5 sm:w-auto">
                <label for="search-assets" class="sr-only">Search assets</label>
                <input id="search-assets" name="q" value="{{ $search }}" class="cti-field min-h-9 py-1.5 text-xs" maxlength="100" placeholder="Hostname or public IP">
                <button class="cti-primary min-h-9 px-2.5" aria-label="Search" title="Search"><x-cti-icon name="search" class="size-3.5"/></button>
            </form>
        </header>

        @if ($assets->isEmpty())
            <p class="px-4 py-8 text-center text-xs text-muted">No responsive assets have been observed yet.</p>
        @else
            <div class="overflow-x-auto">
                <table class="w-full min-w-[44rem] text-left text-xs">
                    <thead class="bg-raised text-[0.68rem] text-muted"><tr><th scope="col" class="px-4 py-2.5">Subdomain</th><th scope="col" class="px-3 py-2.5">Public IP</th><th scope="col" class="px-3 py-2.5">HTTP</th><th scope="col" class="px-3 py-2.5">Checked (WIB)</th><th scope="col" class="px-3 py-2.5">Domain</th></tr></thead>
                    <tbody class="divide-y divide-line">
                        @foreach ($assets as $asset)
                            <tr class="hover:bg-raised/60">
                                <td class="px-4 py-2.5 font-semibold wrap-anywhere">{{ $asset->hostname }}</td>
                                <td class="px-3 py-2.5 font-mono text-[0.68rem] text-muted">{{ $asset->public_ip }}</td>
                                @php($status = (int) $asset->status_code)
                                <td class="px-3 py-2.5"><span @class(['rounded-full px-2 py-0.5 text-[0.68rem] font-semibold', 'bg-signal-bg text-signal' => $status < 300, 'bg-amber-500/15 text-amber-200' => $status >= 300 && $status < 400, 'bg-red-500/15 text-red-200' => $status >= 400])>{{ strtoupper($asset->scheme) }} {{ $status }}</span></td>
                                <td class="px-3 py-2.5 text-[0.68rem] text-muted">{{ $asset->checked_at->timezone('Asia/Jakarta')->format('Y-m-d H:i') }}</td>
                                <td class="px-3 py-2.5"><a href="{{ route('domains.show', [$workspace, $asset->monitoredDomain]) }}#inventory" class="text-signal hover:underline">{{ $asset->monitoredDomain->hostname }}</a></td>
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
            @if ($assets->hasPages())<div class="border-t border-line px-3 py-1.5">{{ $assets->onEachSide(1)->links('components.compact-pagination') }}</div>@endif
        @endif
    </section>
@endsection
