<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="CTI Jagat Cyber - cyber threat intelligence workspace.">
    <title>@yield('title') - {{ config('app.name') }}</title>
    <link rel="icon" href="{{ asset('jagat-mark.svg') }}" type="image/svg+xml">
    <script>
        (() => {
            const media = matchMedia('(prefers-color-scheme: light)');
            let choice = null;
            try { choice = localStorage.getItem('cti-jagat-theme'); } catch {}
            if (!['dark', 'light'].includes(choice)) choice = null;
            const resolvedTheme = () => choice ?? (media.matches ? 'light' : 'dark');
            const apply = () => {
                document.documentElement.dataset.theme = resolvedTheme();
                document.querySelectorAll('[data-theme-choice]').forEach((button) => {
                    button.setAttribute('aria-pressed', String(button.dataset.themeChoice === resolvedTheme()));
                    button.dataset.active = String(button.dataset.themeChoice === resolvedTheme());
                });
            };
            apply();
            media.addEventListener('change', () => { if (choice === null) apply(); });
            document.addEventListener('DOMContentLoaded', () => {
                apply();
                document.querySelectorAll('[data-theme-choice]').forEach((button) => {
                    button.addEventListener('click', () => {
                        choice = button.dataset.themeChoice;
                        apply();
                        try { localStorage.setItem('cti-jagat-theme', choice); } catch {}
                    });
                });
            });
        })();
    </script>
    @vite('resources/css/app.css')
    @fonts
</head>
<body class="min-h-dvh bg-canvas font-sans text-ink antialiased">
    <a href="#main" class="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-lg focus:bg-panel focus:p-3">Skip to content</a>
    @yield('content')
</body>
</html>
