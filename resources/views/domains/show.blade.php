@extends('domains.shell')

@section('title', $monitoredDomain->hostname)

@section('domain-content')
    <section class="cti-hero flex flex-wrap items-center justify-between gap-3 rounded-2xl border border-[#284050] px-4 py-4 text-white">
        <div class="min-w-0">
            <p class="cti-eyebrow text-[#8af1df]">Asset Management / Domain</p>
            <h1 class="mt-1 text-lg font-bold tracking-tight wrap-break-word">{{ $monitoredDomain->hostname }}</h1>
            <p class="mt-1 text-xs text-[#c0d4e9]">Automatic discovery is active.</p>
        </div>
        @if ($canManage)
            <a href="#domain-settings" class="grid size-8 place-items-center rounded-lg border border-white/15 bg-[#162a3d] text-[#c0d4e9] hover:text-white" aria-label="Domain settings" title="Domain settings"><x-cti-icon name="settings" class="size-3.5"/></a>
        @endif
    </section>

    <section class="cti-panel p-4">
        <div class="flex items-start gap-3">
            <span class="grid size-8 shrink-0 place-items-center rounded-lg bg-signal-bg text-signal"><x-cti-icon name="activity" class="size-3.5"/></span>
            <div>
                <h2 class="text-sm font-bold">Continuous Asset Discovery</h2>
                <p class="mt-1 text-xs leading-5 text-muted">Public DNS, Certificate Transparency, web responses, and discovered assets are collected by scheduled workers.</p>
            </div>
        </div>

        @if ($canManage)
            <div class="mt-3 grid gap-2 md:grid-cols-2">
                <details class="rounded-lg border border-line px-3 py-1.5" @if ($errors->has('zone_file')) open @endif>
                    <summary class="cursor-pointer py-1.5 text-xs font-semibold">Import BIND zone</summary>
                    <form class="grid gap-2 pb-2 pt-1" method="post" enctype="multipart/form-data" action="{{ route('domains.zone-file.store', [$workspace, $monitoredDomain]) }}">
                        @csrf
                        <label for="zone-file" class="text-[0.68rem] text-muted">DNS zone export</label>
                        <input id="zone-file" name="zone_file" type="file" required class="cti-field min-h-9 py-1.5 text-xs" aria-describedby="zone-file-hint">
                        <p id="zone-file-hint" class="text-[0.68rem] text-muted">Maximum 256 KB and 1,000 in-zone hostnames.</p>
                        <button class="cti-primary min-h-9 justify-self-start px-3 py-2 text-xs"><x-cti-icon name="upload" class="size-3.5"/> Import</button>
                    </form>
                </details>
                <details class="rounded-lg border border-line px-3 py-1.5" @if ($errors->has('hostnames')) open @endif>
                    <summary class="cursor-pointer py-1.5 text-xs font-semibold">Import hostnames</summary>
                    <form class="grid gap-2 pb-2 pt-1" method="post" action="{{ route('domains.hostnames.store', [$workspace, $monitoredDomain]) }}">
                        @csrf
                        <label for="hostnames" class="text-[0.68rem] text-muted">One hostname per line</label>
                        <textarea id="hostnames" name="hostnames" rows="3" maxlength="64000" required class="cti-field text-xs" placeholder="{{ 'api.'.$monitoredDomain->hostname }}">{{ old('hostnames') }}</textarea>
                        <p class="text-[0.68rem] text-muted">Up to 250 fully qualified or relative hostnames.</p>
                        <button class="cti-primary min-h-9 justify-self-start px-3 py-2 text-xs"><x-cti-icon name="plus" class="size-3.5"/> Import</button>
                    </form>
                </details>
            </div>
        @endif
    </section>

    <section id="inventory" aria-labelledby="inventory-heading" class="cti-panel min-w-0 overflow-hidden">
        <header class="flex flex-wrap items-center justify-between gap-3 border-b border-line px-4 py-3">
            <div class="flex min-w-0 items-center gap-2.5">
                <span class="grid size-8 shrink-0 place-items-center rounded-lg bg-signal-bg text-signal"><x-cti-icon name="globe" class="size-3.5"/></span>
                <div>
                    <div class="flex items-center gap-2"><h2 id="inventory-heading" class="text-sm font-bold">Observed Subdomains</h2><span class="rounded-md bg-raised px-2 py-0.5 text-[0.68rem] font-semibold text-muted">{{ $assets->total() }}</span></div>
                    <p class="mt-0.5 text-[0.68rem] text-muted">HTTP responses observed within the last 48 hours.</p>
                </div>
            </div>
            <form method="get" action="{{ route('domains.show', [$workspace, $monitoredDomain]) }}#inventory" class="flex w-full max-w-xs items-center gap-1.5 sm:w-auto">
                <label for="asset-search" class="sr-only">Search subdomains</label>
                <div class="relative min-w-0 flex-1 sm:w-52">
                    <x-cti-icon name="search" class="pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2 text-muted"/>
                    <input id="asset-search" name="q" value="{{ $assetSearch }}" class="cti-field min-h-9 py-1.5 pl-8 text-xs" maxlength="100" placeholder="Search subdomains">
                </div>
                <button class="cti-primary min-h-9 px-2.5" aria-label="Search" title="Search"><x-cti-icon name="search" class="size-3.5"/></button>
            </form>
        </header>

        @if ($assets->isEmpty())
            <p class="px-4 py-8 text-center text-xs text-muted">{{ $assetSearch !== '' ? 'No subdomains match your search.' : 'No responsive subdomains have been observed yet.' }}</p>
        @else
            <div class="overflow-x-auto">
                <table class="w-full min-w-[42rem] table-fixed text-left text-xs">
                    <thead class="border-b border-line bg-canvas/55 text-[0.68rem] font-semibold text-muted">
                        <tr>
                            <th scope="col" class="w-[35%] px-4 py-2.5">Subdomain</th>
                            <th scope="col" class="w-[21%] px-3 py-2.5">Public IP</th>
                            <th scope="col" class="w-[25%] px-3 py-2.5">Source</th>
                            <th scope="col" class="w-[13%] px-3 py-2.5">HTTP</th>
                            @if ($canManage)<th scope="col" class="w-10 px-2 py-2.5"><span class="sr-only">Action</span></th>@endif
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-line">
                        @foreach ($assets as $asset)
                            <tr class="hover:bg-raised/45">
                                <td class="px-4 py-2.5 font-semibold wrap-anywhere">{{ $asset->value }}</td>
                                <td class="px-3 py-2.5 font-mono text-[0.68rem] text-muted">{{ $asset->public_ip }}</td>
                                <td class="px-3 py-2.5 text-[0.68rem] text-muted">{{ $asset->source_labels }}</td>
                                <td class="px-3 py-2.5">
                                    @php($status = (int) $asset->status_code)
                                    <span @class(['inline-flex rounded-full px-2 py-0.5 text-[0.68rem] font-semibold', 'bg-signal-bg text-signal' => $status < 300, 'bg-amber-500/15 text-amber-200' => $status >= 300 && $status < 400, 'bg-red-500/15 text-red-200' => $status >= 400])>{{ strtoupper($asset->scheme) }} {{ $status }}</span>
                                </td>
                                @if ($canManage)<td class="px-2 py-2 text-right">@include('domains.asset-actions', ['fromInventory' => false])</td>@endif
                            </tr>
                        @endforeach
                    </tbody>
                </table>
            </div>
            @if ($assets->hasPages())<div class="border-t border-line px-3 py-1.5">{{ $assets->onEachSide(1)->links('components.compact-pagination') }}</div>@endif
        @endif
    </section>

    @if ($canManage)
        <section id="domain-settings" class="cti-panel p-4">
            <details @if ($errors->has('delete_confirmation')) open @endif>
                <summary class="cursor-pointer text-xs font-semibold text-red-300">Delete Domain</summary>
                <p class="mt-2 max-w-xl text-xs leading-5 text-muted">Permanent deletion removes discovery data, schedules, observations, and scan history for this domain.</p>
                <form class="mt-3 flex max-w-lg flex-wrap items-end gap-2" method="post" action="{{ route('domains.destroy', [$workspace, $monitoredDomain]) }}">
                    @csrf
                    @method('DELETE')
                    <div class="min-w-0 flex-1">
                        <label for="delete-confirmation" class="mb-1 block text-[0.68rem] text-muted">Type <strong>{{ $monitoredDomain->hostname }}</strong> to confirm</label>
                        <input id="delete-confirmation" name="delete_confirmation" class="cti-field min-h-9 py-1.5 text-xs" autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="253" required>
                    </div>
                    <button class="inline-flex min-h-9 items-center gap-1.5 rounded-lg border border-red-500/45 px-3 text-xs font-semibold text-red-300 hover:bg-red-500/10"><x-cti-icon name="trash" class="size-3.5"/> Delete</button>
                </form>
            </details>
        </section>
    @endif
@endsection
