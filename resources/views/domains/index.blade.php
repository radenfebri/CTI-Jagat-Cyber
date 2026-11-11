@extends('domains.shell')

@section('title', 'Domain dan verifikasi')

@section('domain-content')
    <section class="cti-hero relative isolate flex min-h-44 items-center overflow-hidden rounded-2xl border border-[#284050] p-6 text-white sm:px-8">
        <x-cti-radar class="pointer-events-none absolute -right-12 -z-10 w-64 opacity-35 sm:right-4 sm:opacity-80"/>
        <div>
            <p class="cti-eyebrow text-[#8af1df]">Manajemen Aset</p>
            <h1 class="mt-2 text-2xl font-bold tracking-tight">Domain dan verifikasi</h1>
            <p class="mt-2 max-w-lg text-sm leading-6 text-[#c0d4e9]">Daftarkan domain organisasi dan verifikasi kepemilikan dengan record TXT di penyedia DNS yang Anda gunakan.</p>
        </div>
    </section>

    <div @class(['grid items-start gap-5', 'lg:grid-cols-[minmax(0,2fr)_minmax(16rem,1fr)]' => $canManage])>
        <section class="cti-panel min-w-0 overflow-hidden">
            <div class="flex items-center justify-between gap-3 border-b border-line p-5">
                <h2 class="font-bold">Domain terdaftar</h2>
                <span class="rounded-lg bg-raised px-2.5 py-1 text-xs font-semibold text-muted">{{ $domains->total() }} domain</span>
            </div>
            @forelse ($domains as $domain)
                <a href="{{ route('domains.show', [$workspace, $domain]) }}" class="flex items-center gap-3 border-b border-line px-5 py-4 last:border-b-0 hover:bg-raised">
                    <span class="grid size-10 shrink-0 place-items-center rounded-xl bg-signal-bg text-signal"><x-cti-icon name="globe"/></span>
                    <span class="min-w-0 grow">
                        <span class="block text-sm font-semibold wrap-break-word">{{ $domain->hostname }}</span>
                        <span class="mt-1 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-muted">
                            <span>{{ number_format($domain->subdomains_count) }} ditemukan</span>
                            <span aria-hidden="true" class="text-line">·</span>
                            <span class="text-signal">{{ number_format($domain->active_subdomains_count) }} responsif</span>
                        </span>
                        <span class="mt-1 block text-xs text-muted">{{ $domain->verified_at ? 'Terverifikasi' : 'Menunggu verifikasi' }} @if ($domain->web_ip) · {{ $domain->web_ip }} @endif</span>
                    </span>
                    <x-cti-icon name="chevron" class="size-4 text-muted"/>
                </a>
            @empty
                <p class="p-5 text-sm leading-6 text-muted">Belum ada domain terdaftar. {{ $canManage ? 'Tambahkan domain yang dapat Anda kelola di DNS.' : 'Pemilik atau admin dapat menambahkan domain.' }}</p>
            @endforelse
            @if ($domains->hasPages())
                <div class="border-t border-line p-4">{{ $domains->links() }}</div>
            @endif
        </section>

        @if ($canManage)
            <section class="cti-panel p-5">
                <p class="cti-eyebrow text-signal">Onboarding</p>
                <h2 class="mt-2 text-lg font-bold">Tambahkan domain</h2>
                <form method="post" action="{{ route('domains.store', $workspace) }}" class="mt-4 grid gap-3">
                    @csrf
                    <div class="grid gap-1.5">
                        <label for="hostname" class="text-sm font-semibold">Nama domain</label>
                        <input id="hostname" name="hostname" class="cti-field" placeholder="perusahaan.co.id" value="{{ old('hostname') }}" maxlength="253" autocapitalize="none" spellcheck="false" required>
                    </div>
                    <p class="text-xs leading-5 text-muted">Anda perlu akses untuk menambah record TXT pada DNS domain ini.</p>
                    <button class="cti-primary justify-self-start"><x-cti-icon name="plus" class="size-4"/> Tambahkan</button>
                </form>
            </section>
        @endif
    </div>
@endsection
