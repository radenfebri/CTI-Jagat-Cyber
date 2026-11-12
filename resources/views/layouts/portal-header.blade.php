<header class="border-b border-line bg-panel">
    <div class="mx-auto flex max-w-[100rem] flex-wrap items-center justify-between gap-2 px-4 py-2.5 sm:px-6 lg:px-7">
        <p class="flex items-center gap-1.5 text-xs text-muted">
            <span>{{ $onAttackSurface ? 'Attack Surface' : (($onDomains || request()->routeIs('assets.inventory')) ? 'Asset Management' : 'Workspace') }}</span>
            <x-cti-icon name="chevron" class="size-3 shrink-0"/>
            <span class="font-medium wrap-anywhere text-ink">@yield('title', 'Overview')</span>
        </p>
        <div class="flex min-w-0 flex-wrap items-center gap-2">
            <div role="group" aria-label="Display theme" class="flex rounded-lg border border-line bg-canvas p-0.5">
                <button type="button" data-theme-choice="light" aria-label="Use light theme" title="Light theme" class="grid size-7 place-items-center rounded-md text-muted transition-colors hover:bg-raised hover:text-ink aria-pressed:bg-raised aria-pressed:text-signal"><x-cti-icon name="sun" class="size-3.5"/></button>
                <button type="button" data-theme-choice="dark" aria-label="Use dark theme" title="Dark theme" class="grid size-7 place-items-center rounded-md text-muted transition-colors hover:bg-raised hover:text-ink aria-pressed:bg-raised aria-pressed:text-signal"><x-cti-icon name="moon" class="size-3.5"/></button>
            </div>
            <span class="hidden max-w-40 truncate text-xs font-semibold sm:inline">{{ auth()->user()->name }}</span>
            <form method="post" action="{{ route('logout') }}">
                @csrf
                <button type="submit" class="grid size-8 place-items-center rounded-lg border border-line text-muted hover:bg-raised hover:text-ink" aria-label="Sign out" title="Sign out"><x-cti-icon name="logout" class="size-3.5"/></button>
            </form>
        </div>
    </div>
</header>
