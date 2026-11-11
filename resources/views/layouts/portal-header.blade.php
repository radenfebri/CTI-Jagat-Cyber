<header class="border-b border-line bg-panel">
    <div class="mx-auto flex max-w-[100rem] flex-wrap items-center justify-between gap-3 px-4 py-3.5 sm:px-7 lg:px-9">
        <p class="flex items-center gap-2 text-sm text-muted">
            <span>{{ $onAttackSurface ? 'Attack Surface' : (($onDomains || request()->routeIs('assets.inventory')) ? 'Manajemen Aset' : 'Workspace') }}</span>
            <x-cti-icon name="chevron" class="size-3 shrink-0"/>
            <span class="font-medium wrap-anywhere text-ink">@yield('title', 'Ringkasan')</span>
        </p>
        <div class="flex min-w-0 flex-wrap items-center gap-2.5">
            <label for="theme-choice" class="sr-only">Tema tampilan</label>
            <select id="theme-choice" class="rounded-lg border border-line bg-canvas px-2 py-2 text-xs font-medium text-ink">
                <option value="dark">Gelap</option>
                <option value="light">Terang</option>
                <option value="system">Sistem</option>
            </select>
            <span class="hidden max-w-44 truncate text-sm font-semibold sm:inline">{{ auth()->user()->name }}</span>
            <form method="post" action="{{ route('logout') }}">
                @csrf
                <button type="submit" class="flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-2 text-xs font-medium text-muted hover:bg-raised hover:text-ink"><x-cti-icon name="logout" class="size-4"/> Keluar</button>
            </form>
        </div>
    </div>
</header>
