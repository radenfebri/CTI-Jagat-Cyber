<!doctype html>
<html lang="id" data-theme="dark">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="description" content="CTI Jagat Cyber — workspace intelijen ancaman siber.">
    <title>@yield('title') · {{ config('app.name') }}</title>
    <link rel="icon" href="{{ asset('jagat-mark.svg') }}" type="image/svg+xml">
    <script>
        (() => {
            const media = matchMedia('(prefers-color-scheme: light)');
            let choice = 'dark';
            try { choice = localStorage.getItem('cti-jagat-theme') || 'dark'; } catch {}
            if (!['dark', 'light', 'system'].includes(choice)) choice = 'dark';
            const apply = () => {
                document.documentElement.dataset.theme = choice === 'system' ? (media.matches ? 'light' : 'dark') : choice;
            };
            apply();
            media.addEventListener('change', apply);
            document.addEventListener('DOMContentLoaded', () => {
                const picker = document.getElementById('theme-choice');
                if (!picker) return;
                picker.value = choice;
                picker.addEventListener('change', () => {
                    choice = picker.value;
                    apply();
                    try { localStorage.setItem('cti-jagat-theme', choice); } catch {}
                });
            });
        })();
    </script>
    @vite('resources/css/app.css')
    @fonts
</head>
<body class="min-h-dvh bg-canvas font-sans text-ink antialiased">
    <a href="#main" class="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-50 focus:rounded-lg focus:bg-panel focus:p-3">Lewati ke konten</a>
    @yield('content')
</body>
</html>
