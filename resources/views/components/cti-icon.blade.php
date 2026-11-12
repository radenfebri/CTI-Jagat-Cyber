@props(['name'])

<svg {{ $attributes->class('size-5 shrink-0') }} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
    @switch($name)
        @case('shield')
            <path d="M12 22s7-3 7-9V5l-7-3-7 3v8c0 6 7 9 7 9Z"/><path d="M8 12h2l1.5-3 2 6 1-3H16"/>
            @break
        @case('dashboard')
            <rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/>
            @break
        @case('activity')
            <path d="M3 12h4l3-7 4 14 3-7h4"/>
            @break
        @case('organization')
            <path d="M3 21h18M5 21V6l7-3v18m0-12h7v12M8 8v1m0 3v1m0 3v1m7-4v1m0 3v1"/>
            @break
        @case('users')
            <circle cx="9" cy="7" r="3"/><path d="M3 21v-2a5 5 0 0 1 5-5h2a5 5 0 0 1 5 5v2m1-17a3 3 0 0 1 0 6m2 4a5 5 0 0 1 3 5v2"/>
            @break
        @case('logout')
            <path d="M10 17l5-5-5-5m5 5H3m10-8h5a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2h-5"/>
            @break
        @case('arrow')
            <path d="M4 12h15m-6-6 6 6-6 6"/>
            @break
        @case('arrow-left')
            <path d="M20 12H5m6-6-6 6 6 6"/>
            @break
        @case('lock')
            <rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>
            @break
        @case('chevron')
            <path d="m9 5 7 7-7 7"/>
            @break
        @case('globe')
            <circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18 14 14 0 0 1 0-18Z"/>
            @break
        @case('check')
            <path d="m5 12 4 4L19 6"/>
            @break
        @case('search')
            <circle cx="11" cy="11" r="6"/><path d="m16 16 4 4"/>
            @break
        @case('server')
            <rect x="3" y="4" width="18" height="7" rx="2"/><rect x="3" y="13" width="18" height="7" rx="2"/><path d="M7 7.5h1m-1 9h1"/>
            @break
        @case('refresh')
            <path d="M20 10a8 8 0 1 0-2 8m2-14v6h-6"/>
            @break
        @case('plus')
            <path d="M12 5v14M5 12h14"/>
            @break
        @case('trash')
            <path d="M4 7h16m-14 0 1 14h10l1-14M9 7V4h6v3m-5 3v7m4-7v7"/>
            @break
        @case('settings')
            <path d="M5 7h14M5 12h14M5 17h14"/><circle cx="9" cy="7" r="2" fill="currentColor"/><circle cx="15" cy="12" r="2" fill="currentColor"/><circle cx="10" cy="17" r="2" fill="currentColor"/>
            @break
        @case('upload')
            <path d="M12 16V4m-4 4 4-4 4 4M4 16v4h16v-4"/>
            @break
        @case('pause')
            <path d="M9 5v14m6-14v14"/>
            @break
        @case('eye')
            <path d="M2.5 12S6 6 12 6s9.5 6 9.5 6-3.5 6-9.5 6-9.5-6-9.5-6Z"/><circle cx="12" cy="12" r="2.5"/>
            @break
        @case('eye-off')
            <path d="m4 4 16 16M10 6.2c.6-.1 1.3-.2 2-.2 6 0 9.5 6 9.5 6a13 13 0 0 1-2 2.5M6.3 7.8A15 15 0 0 0 2.5 12S6 18 12 18c1.3 0 2.5-.3 3.6-.7"/>
            @break
        @case('close')
            <path d="m6 6 12 12M6 18 18 6"/>
            @break
        @case('sun')
            <circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M4.93 4.93l1.41 1.41m11.32 11.32 1.41 1.41M2 12h2m16 0h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/>
            @break
        @case('moon')
            <path d="M20.5 14.2A8 8 0 0 1 9.8 3.5 8.5 8.5 0 1 0 20.5 14.2Z"/>
            @break
    @endswitch
</svg>
