@extends('layouts.workspace')

@php($isRegistration = $register ?? false)
@section('title', $isRegistration ? 'Buat akun' : 'Masuk')

@section('content')
<main id="main" class="mx-auto grid min-h-dvh w-full max-w-[100rem] gap-3 p-3 sm:gap-6 sm:p-6 lg:grid-cols-[minmax(0,1.05fr)_minmax(0,1fr)]">
    <section class="cti-hero relative isolate flex min-h-42 flex-col justify-between gap-8 overflow-hidden rounded-2xl border border-[#284050] p-6 text-white sm:p-10 lg:min-h-full">
        <a href="{{ route('home') }}" class="flex items-center gap-3 self-start">
            <img src="{{ asset('jagat-mark.svg') }}" alt="" width="44" height="44" class="size-11">
            <span class="grid gap-0.5">
                <span class="text-lg font-bold">{{ config('app.name') }}</span>
                <span class="cti-eyebrow text-[#a5bcd4]">Cyber Threat Intelligence</span>
            </span>
        </a>
        <div class="hidden lg:block">
            <x-cti-radar class="mx-auto max-h-[40vh] w-full max-w-md opacity-90"/>
            <p class="cti-eyebrow text-[#83ead8]">Security workspace</p>
            <p class="mt-2 text-4xl font-bold tracking-tight">See Beyond Threats.</p>
            <p class="mt-3 max-w-sm text-sm leading-6 text-[#c0d4e9]">Satu workspace untuk melihat aktivitas dan mengelola akses organisasi Anda.</p>
        </div>
        <p class="text-xs text-[#a5bcd4]">Workspace organisasi</p>
    </section>

    <section class="flex items-center justify-center px-3 py-7 sm:px-6">
        <div class="w-full max-w-md">
            <p class="cti-eyebrow text-signal">{{ $isRegistration ? 'Mulai workspace' : 'Akses workspace' }}</p>
            <h1 class="mt-2 text-3xl font-bold tracking-tight sm:text-4xl">{{ $isRegistration ? 'Buat akun organisasi' : 'Masuk ke workspace' }}</h1>
            <p class="mt-2 text-sm leading-6 text-muted">{{ $isRegistration ? 'Daftarkan organisasi dan akun pemiliknya.' : 'Gunakan email dan kata sandi akun Anda.' }}</p>

            @if ($errors->any())
                <ul class="mt-5 list-disc rounded-xl border border-red-500/30 bg-red-500/10 py-3 pr-4 pl-8 text-sm text-ink" role="alert">
                    @foreach ($errors->all() as $error)
                        <li>{{ $error }}</li>
                    @endforeach
                </ul>
            @endif

            <form method="post" action="{{ route($isRegistration ? 'register.store' : 'login.store') }}" class="mt-6 grid gap-4">
                @csrf
                @if ($isRegistration)
                    <div class="grid gap-1.5">
                        <label for="name" class="text-sm font-semibold">Nama lengkap</label>
                        <input id="name" name="name" value="{{ old('name') }}" autocomplete="name" maxlength="120" placeholder="Nama Anda" class="cti-field" required>
                    </div>
                    <div class="grid gap-1.5">
                        <label for="organization_name" class="text-sm font-semibold">Nama organisasi</label>
                        <input id="organization_name" name="organization_name" value="{{ old('organization_name') }}" autocomplete="organization" maxlength="120" placeholder="Nama perusahaan" class="cti-field" required>
                    </div>
                @endif
                <div class="grid gap-1.5">
                    <label for="email" class="text-sm font-semibold">Email</label>
                    <input type="email" id="email" name="email" value="{{ old('email') }}" autocomplete="email" maxlength="255" placeholder="nama@perusahaan.id" class="cti-field" required>
                </div>
                <div class="grid gap-1.5">
                    <label for="password" class="text-sm font-semibold">Kata sandi</label>
                    <input type="password" id="password" name="password" autocomplete="{{ $isRegistration ? 'new-password' : 'current-password' }}" class="cti-field" @if ($isRegistration) minlength="12" aria-describedby="password-help" @endif required>
                    @if ($isRegistration)
                        <p id="password-help" class="text-xs text-muted">Minimal 12 karakter, maksimum 72 byte.</p>
                    @endif
                </div>
                @if ($isRegistration)
                    <div class="grid gap-1.5">
                        <label for="password_confirmation" class="text-sm font-semibold">Konfirmasi kata sandi</label>
                        <input type="password" id="password_confirmation" name="password_confirmation" autocomplete="new-password" minlength="12" class="cti-field" required>
                    </div>
                @endif
                <button type="submit" class="cti-primary mt-1">{{ $isRegistration ? 'Daftarkan organisasi' : 'Masuk' }} <x-cti-icon name="arrow" class="size-4"/></button>
            </form>

            <p class="mt-6 border-t border-line pt-5 text-sm text-muted">
                {{ $isRegistration ? 'Sudah punya akun?' : 'Belum punya workspace?' }}
                <a href="{{ route($isRegistration ? 'login' : 'register') }}" class="font-semibold text-signal hover:underline">{{ $isRegistration ? 'Masuk' : 'Daftarkan organisasi' }}</a>
            </p>
        </div>
    </section>
</main>
@endsection
