@extends('layouts.portal')

@section('title', 'Ringkasan')

@section('portal-content')
    <section class="cti-hero relative isolate flex min-h-56 items-center overflow-hidden rounded-2xl border border-[#284050] px-5 py-7 text-white sm:px-8">
        <x-cti-radar class="pointer-events-none absolute -right-12 -z-10 w-64 opacity-35 sm:right-4 sm:w-80 sm:opacity-80 xl:right-8 xl:w-96"/>
        <div class="min-w-0 max-w-2xl">
            <p class="cti-eyebrow flex items-center gap-2 text-[#8af1df]"><span class="size-1.5 rounded-full bg-current"></span> Pusat operasi keamanan</p>
            <h1 class="mt-3 text-3xl font-bold tracking-tight sm:text-[2.4rem]">Ringkasan keamanan</h1>
            <p class="mt-2 max-w-lg text-sm leading-6 text-[#c0d4e9]">Pantau akses, status, dan aktivitas organisasi dari satu workspace.</p>
            @if ($organization)
                <p class="mt-5 inline-flex max-w-full items-center gap-2 rounded-lg border border-white/15 bg-[#162a3d] px-3 py-2 text-sm font-medium">
                    <x-cti-icon name="organization" class="size-4 text-[#8af1df]"/> <span class="wrap-break-word">{{ $organization->name }}</span>
                </p>
            @endif
        </div>
    </section>

    @if ($organization)
        @php
            $roles = ['owner' => 'Pemilik', 'admin' => 'Admin', 'analyst' => 'Analis', 'viewer' => 'Pembaca'];
            $statuses = ['trial' => 'Masa uji coba', 'active' => 'Aktif', 'past_due' => 'Lewat jatuh tempo', 'suspended' => 'Ditangguhkan', 'cancelled' => 'Dibatalkan', 'expired' => 'Kedaluwarsa'];
        @endphp
        <div class="grid gap-3 sm:grid-cols-3 sm:gap-4">
            @foreach ([
                ['users', 'Anggota organisasi', $memberCount],
                ['shield', 'Peran Anda', $roles[$organization->pivot->role] ?? $organization->pivot->role],
                ['organization', 'Status langganan', $statuses[$organization->subscription_status] ?? $organization->subscription_status],
            ] as [$icon, $label, $value])
                <section class="cti-panel flex min-w-0 items-start gap-4 p-4 sm:flex-col xl:flex-row xl:p-5">
                    <div class="grid size-10 shrink-0 place-items-center rounded-xl bg-signal-bg text-signal"><x-cti-icon :name="$icon"/></div>
                    <div class="min-w-0">
                        <h2 class="text-xs font-medium text-muted">{{ $label }}</h2>
                        <p class="mt-1 text-xl font-bold wrap-break-word sm:text-2xl">{{ $value }}</p>
                    </div>
                </section>
            @endforeach
        </div>

        <div @class(['grid items-start gap-5', 'xl:grid-cols-[minmax(0,1.6fr)_minmax(0,1fr)]' => $canViewAudit])>
            @if ($canViewAudit)
                <section id="activity" class="cti-panel min-w-0 overflow-hidden">
                    <div class="flex items-start gap-3 border-b border-line p-5">
                        <div class="grid size-9 shrink-0 place-items-center rounded-lg bg-signal-bg text-signal"><x-cti-icon name="activity" class="size-4"/></div>
                        <div>
                            <h2 class="font-bold">Aktivitas organisasi</h2>
                            <p class="mt-1 text-xs text-muted">Hingga 10 kejadian terbaru dari audit log.</p>
                        </div>
                    </div>
                    @if ($activity->isEmpty())
                        <p class="px-5 py-8 text-sm text-muted">Belum ada aktivitas yang tercatat.</p>
                    @else
                        <table class="w-full table-fixed text-left text-sm">
                            <thead class="bg-raised text-xs text-muted">
                                <tr><th scope="col" class="px-5 py-3 font-semibold">Kejadian</th><th scope="col" class="w-[44%] px-3 py-3 font-semibold">Waktu (WIB)</th></tr>
                            </thead>
                            <tbody class="divide-y divide-line">
                                @foreach ($activity as $entry)
                                    @php($occurredAt = \Illuminate\Support\Carbon::parse($entry->created_at, 'UTC')->timezone('Asia/Jakarta'))
                                    <tr>
                                        <td class="px-5 py-4 font-medium wrap-break-word">{{ match ($entry->event) {
                                            'organization.created' => 'Organisasi dibuat',
                                            'domain.registered' => 'Domain didaftarkan',
                                            'domain.deleted' => 'Domain dihapus',
                                            'domain.web_enabled' => 'Pemeriksaan web diaktifkan',
                                            'domain.web_disabled' => 'Pemeriksaan web dihentikan',
                                            'asset.hidden' => 'Observasi aset disembunyikan',
                                            'asset.restored' => 'Observasi aset dipulihkan',
                                            'asset.deleted' => 'Observasi impor dihapus',
                                            'domain.challenge_rotated' => 'Token verifikasi domain diganti',
                                            'domain.passive_scope_approved' => 'Cakupan discovery pasif disetujui',
                                            'domain.passive_scope_revoked' => 'Izin discovery pasif dicabut',
                                            'domain.ct_enabled' => 'Pencarian sertifikat diaktifkan',
                                            'domain.ct_disabled' => 'Pencarian sertifikat dinonaktifkan',
                                        'domain.hostnames_imported' => 'Nama subdomain diimpor',
                                            'domain.tls_approved' => 'Cakupan TLS disetujui',
                                            'domain.tls_queued' => 'Pemeriksaan TLS dijadwalkan',
                                            'domain.tls_revoked' => 'Izin TLS dicabut',
                                            default => $entry->event,
                                        } }}</td>
                                        <td class="px-3 py-4 text-xs text-muted"><time datetime="{{ $occurredAt->toIso8601String() }}">{{ $occurredAt->format('d/m/Y · H:i') }}</time></td>
                                    </tr>
                                @endforeach
                            </tbody>
                        </table>
                    @endif
                </section>
            @endif

            <section id="organization" class="cti-panel min-w-0 p-5">
                <p class="cti-eyebrow text-signal">Akses workspace</p>
                <h2 class="mt-2 text-lg font-bold">Organisasi aktif</h2>
                <p class="mt-2 text-sm wrap-break-word text-muted">{{ $organization->name }}</p>
                @if ($organizations->count() > 1)
                    <form method="get" action="{{ route('dashboard') }}" class="mt-4 grid gap-2">
                        <label for="organization-choice" class="text-xs font-medium text-muted">Ganti organisasi</label>
                        <select name="organization" id="organization-choice" class="cti-field">
                            @foreach ($organizations as $option)
                                <option value="{{ $option->id }}" @selected($option->id === $organization->id)>{{ $option->name }}</option>
                            @endforeach
                        </select>
                        <button type="submit" class="cti-primary justify-self-start">Buka organisasi <x-cti-icon name="arrow" class="size-4"/></button>
                    </form>
                @endif
                <div class="mt-5 flex gap-2.5 border-t border-line pt-4 text-xs leading-5 text-muted">
                    <x-cti-icon name="lock" class="size-4 text-signal"/>
                    <p>Data dan izin mengikuti organisasi yang sedang dibuka.</p>
                </div>
            </section>
        </div>
    @else
        <section class="cti-panel p-6">
            <h2 class="text-lg font-bold">Belum ada organisasi</h2>
            <p class="mt-2 text-sm text-muted">Akun ini belum terdaftar sebagai anggota organisasi.</p>
        </section>
    @endif
@endsection
