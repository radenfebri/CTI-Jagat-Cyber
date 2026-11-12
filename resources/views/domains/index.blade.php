@extends('domains.shell')

@section('title', 'Domains')

@section('domain-content')
    <section class="cti-hero relative isolate flex min-h-28 items-center overflow-hidden rounded-2xl border border-[#284050] p-4 text-white sm:px-5">
        <x-cti-radar class="pointer-events-none absolute -right-12 -z-10 w-56 opacity-30 sm:right-4 sm:opacity-70"/>
        <div>
            <p class="cti-eyebrow text-[#8af1df]">Asset Management</p>
            <h1 class="mt-1 text-lg font-bold tracking-tight">Registered Domains</h1>
            <p class="mt-1 max-w-lg text-xs leading-5 text-[#c0d4e9]">Add a primary domain to start automatic public discovery.</p>
        </div>
    </section>

    <div @class(['grid items-start gap-3', 'lg:grid-cols-[minmax(0,2fr)_minmax(16rem,1fr)]' => $canManage])>
        <section class="cti-panel min-w-0 overflow-hidden">
            <div class="flex items-center justify-between gap-3 border-b border-line px-4 py-3">
                <h2 class="text-sm font-bold">Registered Domains</h2>
                <span class="rounded-md bg-raised px-2 py-0.5 text-[0.68rem] font-semibold text-muted">{{ $domains->total() }} domains</span>
            </div>
            @forelse ($domains as $domain)
                <a href="{{ route('domains.show', [$workspace, $domain]) }}" class="flex items-center gap-2.5 border-b border-line px-4 py-2.5 last:border-b-0 hover:bg-raised">
                    <span class="grid size-8 shrink-0 place-items-center rounded-lg bg-signal-bg text-signal"><x-cti-icon name="globe" class="size-3.5"/></span>
                    <span class="min-w-0 grow">
                        <span class="block text-xs font-semibold wrap-break-word">{{ $domain->hostname }}</span>
                        <span class="mt-0.5 flex flex-wrap items-center gap-x-2 text-[0.68rem] text-muted">
                            <span>{{ number_format($domain->subdomains_count) }} discovered</span>
                            <span class="text-signal">{{ number_format($domain->active_subdomains_count) }} responsive</span>
                            <span>{{ $domain->web_authorization_id ? 'Discovery active' : 'Discovery pending' }} @if ($domain->web_ip) / {{ $domain->web_ip }} @endif</span>
                        </span>
                    </span>
                    <x-cti-icon name="chevron" class="size-3.5 text-muted"/>
                </a>
            @empty
                <p class="p-5 text-xs leading-5 text-muted">No domains registered. {{ $canManage ? 'Add a primary domain to begin discovery.' : 'An owner or administrator can add domains.' }}</p>
            @endforelse
            @if ($domains->hasPages())
                <div class="border-t border-line px-3 py-1.5">{{ $domains->onEachSide(1)->links('components.compact-pagination') }}</div>
            @endif
        </section>

        @if ($canManage)
            <section class="cti-panel p-4">
                <p class="cti-eyebrow text-signal">Onboarding</p>
                <h2 class="mt-1 text-sm font-bold">Add Domain</h2>
                <form method="post" action="{{ route('domains.store', $workspace) }}" class="mt-3 grid gap-2.5">
                    @csrf
                    <div class="grid gap-1">
                        <label for="hostname" class="text-xs font-semibold">Domain name</label>
                        <input id="hostname" name="hostname" class="cti-field min-h-9 py-1.5 text-xs" placeholder="company.com" value="{{ old('hostname') }}" maxlength="253" autocapitalize="none" spellcheck="false" required>
                    </div>
                    <p class="text-[0.68rem] leading-5 text-muted">Public asset discovery starts automatically.</p>
                    <button class="cti-primary min-h-9 justify-self-start px-3 py-2 text-xs"><x-cti-icon name="plus" class="size-3.5"/> Add Domain</button>
                </form>
            </section>
        @endif
    </div>
@endsection
