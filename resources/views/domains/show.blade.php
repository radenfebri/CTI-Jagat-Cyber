@extends('domains.shell')

@section('title', $monitoredDomain->hostname)

@section('domain-content')
    @php
        $verified = $monitoredDomain->verified_at !== null;
        $expired = $monitoredDomain->verification_expires_at->isPast();
        $formatTime = fn ($time) => $time?->timezone('Asia/Jakarta')->format('d/m/Y H:i').' WIB';
    @endphp
    <section class="cti-hero rounded-2xl border border-[#284050] px-6 py-7 text-white">
        <p class="cti-eyebrow text-[#8af1df]">Manajemen aset · Detail domain</p>
        <h1 class="mt-2 text-2xl font-bold tracking-tight wrap-break-word">{{ $monitoredDomain->hostname }}</h1>
        <div class="mt-4 flex flex-wrap gap-2 text-xs">
            <span class="rounded-lg border border-white/15 bg-[#162a3d] px-2.5 py-1.5">{{ $verified ? 'Terverifikasi' : 'Belum terverifikasi' }}</span>
            @if ($canManage)
                <a href="#kelola-domain" class="inline-flex items-center gap-1.5 rounded-lg border border-white/15 bg-[#162a3d] px-2.5 py-1.5 hover:underline"><x-cti-icon name="settings" class="size-3.5"/> Kelola domain</a>
            @endif
        </div>
    </section>
    <div>
        <section class="cti-panel min-w-0 p-5">
            <p class="cti-eyebrow text-signal">01 · Kepemilikan</p>
            <h2 class="mt-2 text-base font-bold">Verifikasi DNS TXT</h2>
            @if ($verified)
                <p class="mt-2 text-sm text-muted">Terverifikasi pada {{ $formatTime($monitoredDomain->verified_at) }}. Pertahankan record TXT untuk pemeriksaan ulang.</p>
            @elseif ($canManage)
                <p class="mt-2 text-sm leading-6 text-muted">{{ $expired ? 'Token kedaluwarsa. Buat token baru untuk melanjutkan.' : 'Buat record TXT di pengaturan DNS domain Anda.' }}</p>
                @unless ($expired)
                    <dl class="mt-4 grid gap-3 rounded-xl border border-line bg-canvas p-3 text-sm">
                        <div><dt class="text-xs text-muted">Nama / host</dt><dd class="mt-1"><code class="wrap-anywhere">{{ $monitoredDomain->txtName() }}</code></dd></div>
                        <div><dt class="text-xs text-muted">Nilai TXT</dt><dd class="mt-1"><code class="wrap-anywhere">{{ $monitoredDomain->txtValue() }}</code></dd></div>
                    </dl>
                    <p class="mt-3 text-xs text-muted">Berlaku sampai {{ $formatTime($monitoredDomain->verification_expires_at) }}</p>
                @endunless
                <div class="mt-4 flex flex-wrap gap-2">
                    @if (! $expired && $workspace->allowsDiscovery())
                        <form method="post" action="{{ route('domains.verify', [$workspace, $monitoredDomain]) }}">
                            @csrf
                            <button class="cti-primary"><x-cti-icon name="shield" class="size-4"/> Periksa TXT</button>
                        </form>
                    @endif
                    <form method="post" action="{{ route('domains.challenge', [$workspace, $monitoredDomain]) }}">
                        @csrf
                        <button class="inline-flex min-h-11 items-center gap-2 rounded-xl border border-line px-3 text-sm font-medium hover:bg-raised"><x-cti-icon name="refresh" class="size-4"/> Buat token baru</button>
                    </form>
                </div>
                @if ($monitoredDomain->verification_status === 'not_found')
                    <p class="mt-3 text-sm text-muted">Nilai TXT belum ditemukan. Periksa host, nilai token, dan propagasi DNS.</p>
                @elseif ($monitoredDomain->verification_status === 'error')
                    <p class="mt-3 text-sm text-muted">Resolver DNS gagal. Pemeriksaan dapat dicoba kembali.</p>
                @endif
            @else
                <p class="mt-2 text-sm text-muted">Verifikasi dikelola oleh pemilik atau admin organisasi.</p>
            @endif
        </section>

        @if (false)
        <section class="cti-panel min-w-0 p-5">
            <p class="cti-eyebrow text-signal">02 · Cakupan</p>
            <h2 class="mt-2 text-base font-bold">Discovery pasif</h2>
            <p class="mt-2 text-sm leading-6 text-muted">Pemeriksaan berkala membaca record A, AAAA, dan CNAME dari hostname ini melalui resolver DNS.</p>
            @if (! $workspace->allowsDiscovery())
                <p class="mt-3 text-sm text-muted">Discovery dijeda karena status langganan organisasi.</p>
            @endif
            @if ($active || $policy?->last_status)
                <dl class="mt-4 grid gap-2 text-sm">
                    <div class="flex flex-wrap justify-between gap-2"><dt class="text-muted">Status terakhir</dt><dd>{{ $statusLabels[$policy->last_status] ?? 'Menunggu scheduler' }}</dd></div>
                    @if ($policy->last_success_at)
                        <div class="flex flex-wrap justify-between gap-2"><dt class="text-muted">Terakhir berhasil</dt><dd>{{ $formatTime($policy->last_success_at) }}</dd></div>
                    @endif
                    @if ($active && $workspace->allowsDiscovery() && $policy->next_run_at)
                        <div class="flex flex-wrap justify-between gap-2"><dt class="text-muted">Jadwal berikutnya</dt><dd>{{ $formatTime($policy->next_run_at) }}</dd></div>
                    @endif
                </dl>
            @endif

            @if ($active)
                <p class="mt-4 text-xs leading-5 text-muted">Discovery berjalan otomatis melalui worker dan akan diperbarui sesuai jadwal berikutnya.</p>
            @elseif ($canManage && $verified && $workspace->allowsDiscovery())
                <p class="mt-3 text-sm text-muted">Discovery otomatis akan dimulai setelah worker membaca verifikasi TXT.</p>
            @elseif (! $verified)
                <p class="mt-3 text-sm text-muted">Selesaikan verifikasi TXT sebelum menyetujui cakupan.</p>
            @endif
        </section>
        @endif
    </div>

    <div>
        @if (false)
        @include('domains.certificates')
        @endif
        <section class="cti-panel min-w-0 p-5">
            <p class="cti-eyebrow text-signal">Sumber inventaris</p>
            <h2 class="mt-2 text-base font-bold">Zona DNS dan daftar hostname</h2>
            <p class="mt-2 text-sm leading-6 text-muted">DNS publik dan sertifikat dapat digunakan dengan penyedia DNS apa pun. Untuk subdomain lain, impor ekspor zona DNS dalam format BIND atau masukkan daftar hostname.</p>
            <p class="mt-2 text-sm text-muted">
                {{ $zoneConfigured ? match ($monitoredDomain->zone_status) {
                    'complete' => 'Konektor opsional: sinkronisasi Cloudflare selesai.',
                    'unavailable' => 'Konektor opsional: Cloudflare belum dapat dibaca. Periksa Zone ID dan izin DNS Read.',
                    default => 'Konektor opsional: Cloudflare terhubung, menunggu discovery pasif.',
                } : 'Konektor Cloudflare opsional. Impor dan discovery publik tetap tersedia.' }}
            </p>
            @if ($canManage && $verified)
                <details class="mt-4 rounded-xl border border-line px-3 py-2" @if ($errors->hasAny(['zone_id', 'api_token'])) open @endif>
                    <summary class="cursor-pointer py-2 text-sm font-semibold">Konektor Cloudflare per domain</summary>
                    <p class="mt-1 text-xs leading-5 text-muted">Opsional. Gunakan Zone ID dan API Token dengan izin <code>Zone DNS Read</code>. Token disimpan terenkripsi untuk organisasi ini.</p>
                    <form class="mt-3 grid gap-2.5 pb-2" method="post" action="{{ route('domains.cloudflare.update', [$workspace, $monitoredDomain]) }}">
                        @csrf
                        @method('PATCH')
                        <input type="hidden" name="enabled" value="1">
                        <label for="cloudflare-zone-id" class="text-xs font-semibold">Zone ID</label>
                        <input id="cloudflare-zone-id" name="zone_id" class="cti-field" value="{{ old('zone_id', $monitoredDomain->cloudflare_zone_id) }}" maxlength="32" autocapitalize="none" spellcheck="false" placeholder="32 karakter heksadesimal">
                        @error('zone_id') <p class="text-xs text-red-300">{{ $message }}</p> @enderror
                        <label for="cloudflare-api-token" class="text-xs font-semibold">API Token</label>
                        <input id="cloudflare-api-token" name="api_token" type="password" class="cti-field" maxlength="4096" autocomplete="new-password" placeholder="{{ $monitoredDomain->cloudflare_api_token ? 'Token tersimpan · isi hanya jika ingin mengganti' : 'Token Cloudflare' }}">
                        @error('api_token') <p class="text-xs text-red-300">{{ $message }}</p> @enderror
                        <button class="cti-primary justify-self-start"><x-cti-icon name="lock" class="size-4"/> Simpan konektor</button>
                    </form>
                    @if ($zoneConfigured)
                        <form method="post" action="{{ route('domains.cloudflare.update', [$workspace, $monitoredDomain]) }}">
                            @csrf
                            @method('PATCH')
                            <input type="hidden" name="enabled" value="0">
                            <button class="inline-flex min-h-9 items-center gap-2 rounded-lg border border-line px-2.5 text-xs font-semibold hover:bg-raised"><x-cti-icon name="pause" class="size-3.5"/> Lepas konektor</button>
                        </form>
                    @endif
                </details>
                <details class="mt-4 rounded-xl border border-line px-3 py-2" @if ($errors->has('zone_file')) open @endif>
                    <summary class="cursor-pointer py-2 text-sm font-semibold">Impor file zona BIND</summary>
                    <form class="mt-2 grid gap-2.5 pb-2" method="post" enctype="multipart/form-data" action="{{ route('domains.zone-file.store', [$workspace, $monitoredDomain]) }}">
                        @csrf
                        <label for="zone-file" class="text-sm font-medium">File ekspor zona DNS</label>
                        <input id="zone-file" name="zone_file" type="file" required class="cti-field" aria-describedby="zone-file-hint">
                        <p id="zone-file-hint" class="text-xs text-muted">Maksimal 256 KB dan 1.000 nama. Hanya nama subdomain dalam zona ini yang disimpan.</p>
                        <button class="cti-primary justify-self-start"><x-cti-icon name="upload" class="size-4"/> Impor zona</button>
                    </form>
                </details>
                <details class="mt-3 rounded-xl border border-line px-3 py-2" @if ($errors->has('hostnames')) open @endif>
                    <summary class="cursor-pointer py-2 text-sm font-semibold">Impor daftar hostname</summary>
                    <form class="mt-2 grid gap-2.5 pb-2" method="post" action="{{ route('domains.hostnames.store', [$workspace, $monitoredDomain]) }}">
                        @csrf
                        <label for="hostnames" class="text-sm font-medium">Satu nama per baris</label>
                        <textarea id="hostnames" name="hostnames" rows="3" maxlength="64000" required class="cti-field" placeholder="{{ 'api.'.$monitoredDomain->hostname }}">{{ old('hostnames') }}</textarea>
                        <p class="text-xs text-muted">Masukkan nama lengkap atau satu label seperti api. Maksimal 250 nama.</p>
                        <button class="cti-primary justify-self-start"><x-cti-icon name="plus" class="size-4"/> Simpan hostname</button>
                    </form>
                </details>
            @else
                <p class="mt-3 text-xs text-muted">Pemilik atau admin dapat mengimpor nama setelah domain terverifikasi.</p>
            @endif
        </section>
    </div>

    @if (false)
    <div class="grid gap-5 xl:grid-cols-2">
    <section class="cti-panel grid gap-5 p-5 sm:p-6">
        <div class="flex items-start gap-3">
            <span class="grid size-11 shrink-0 place-items-center rounded-xl bg-signal-bg text-signal"><x-cti-icon name="globe"/></span>
            <div>
                <h2 class="text-base font-bold">Pemeriksaan web</h2>
                <p class="mt-1 text-sm leading-6 text-muted">Periksa respons halaman utama domain dan subdomain yang ditemukan. Inventaris menampilkan semua respons HTTP dalam 48 jam terakhir.</p>
                <p class="mt-1 text-xs leading-5 text-muted">Jika layanan publik dibatasi firewall, izinkan IP keluar server CTI agar pemeriksaan dapat menjangkaunya.</p>
            </div>
        </div>
        @if ($webRoot)
            <dl class="grid gap-3 rounded-xl border border-line bg-canvas p-4 text-sm sm:grid-cols-3">
                <div><dt class="text-xs text-muted">Respons domain utama</dt><dd class="mt-1 font-semibold">{{ $webRoot->status_code ? strtoupper($webRoot->scheme).' '.$webRoot->status_code : 'Tidak ada respons' }}</dd></div>
                <div><dt class="text-xs text-muted">IP publik</dt><dd class="mt-1 font-mono text-xs wrap-anywhere">{{ $webRoot->public_ip ?? '—' }}</dd></div>
                <div><dt class="text-xs text-muted">Terakhir diperiksa</dt><dd class="mt-1">{{ $formatTime($webRoot->checked_at) }}</dd></div>
            </dl>
        @elseif ($monitoredDomain->web_authorization_id)
            <p class="text-sm text-muted">Menunggu pemeriksaan pertama oleh cron.</p>
        @endif
        @if ($monitoredDomain->web_authorization_id)
            <p class="text-xs leading-5 text-muted">Pemeriksaan web berjalan otomatis melalui worker dan diperbarui berkala.</p>
        @elseif ($verified)
            <p class="text-sm text-muted">Pemeriksaan web akan aktif otomatis setelah scheduler memproses verifikasi TXT.</p>
        @elseif (! $monitoredDomain->web_authorization_id)
            <p class="text-sm text-muted">Pemeriksaan web menunggu verifikasi TXT domain.</p>
        @endif
    </section>

    @include('domains.tls-scope')
    </div>
    @endif

    <section id="inventaris" aria-labelledby="inventory-heading" class="cti-panel min-w-0 overflow-hidden">
        <header class="flex flex-wrap items-center justify-between gap-x-6 gap-y-4 border-b border-line px-4 py-5 sm:px-6">
            <div class="flex min-w-0 items-start gap-3.5">
                <span class="grid size-11 shrink-0 place-items-center rounded-xl border border-signal/15 bg-signal-bg text-signal"><x-cti-icon name="globe"/></span>
                <div class="min-w-0">
                    <div class="flex flex-wrap items-center gap-x-2.5 gap-y-1">
                        <h2 id="inventory-heading" class="text-base leading-5 font-bold">Subdomain teramati</h2>
                        <span class="rounded-full border border-line bg-raised px-2 py-0.5 text-xs font-semibold tabular-nums text-muted">{{ $assets->total() }} subdomain</span>
                    </div>
                    <p class="mt-1 text-sm leading-5 text-muted">Respons HTTP dalam 48 jam terakhir.</p>
                </div>
            </div>
            <div class="flex w-full flex-wrap items-center justify-between gap-3">
                <nav aria-label="Filter inventaris" class="inline-flex max-w-full flex-wrap items-center gap-1 rounded-xl border border-line bg-canvas p-1 text-xs font-semibold">
                    @foreach (['subdomains' => ['eye', 'Ditampilkan'], 'hidden' => ['eye-off', 'Disembunyikan']] as $filter => [$icon, $label])
                        <a href="{{ route('domains.show', [$workspace, $monitoredDomain, 'assets' => $filter, 'q' => $assetSearch]) }}#inventaris"
                            @if ($assetView === $filter) aria-current="true" @endif
                            @class(['inline-flex min-h-9 items-center gap-1.5 rounded-lg px-2.5 transition-colors sm:px-3', 'bg-signal-bg text-signal' => $assetView === $filter, 'text-muted hover:bg-raised hover:text-ink' => $assetView !== $filter])>
                            <x-cti-icon :name="$icon" class="size-4"/> {{ $label }}
                        </a>
                    @endforeach
                </nav>
                <form method="get" action="{{ route('domains.show', [$workspace, $monitoredDomain]) }}#inventaris" class="flex w-full max-w-xl items-center gap-2 sm:w-auto">
                    <input type="hidden" name="assets" value="{{ $assetView }}">
                    <label for="asset-search" class="sr-only">Cari subdomain</label>
                    <div class="relative min-w-0 flex-1 sm:w-64">
                        <x-cti-icon name="search" class="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-muted"/>
                        <input id="asset-search" name="q" value="{{ $assetSearch }}" class="cti-field pl-9" maxlength="100" placeholder="Cari subdomain">
                    </div>
                    <button class="cti-primary min-h-10 px-3 text-xs"><x-cti-icon name="search" class="size-4"/> Cari</button>
                </form>
            </div>
        </header>
        @if ($assets->isEmpty())
            <div class="grid justify-items-center gap-3 px-4 py-10 text-center">
                <span class="grid size-11 place-items-center rounded-xl bg-raised text-muted"><x-cti-icon :name="$assetView === 'hidden' ? 'eye-off' : 'globe'"/></span>
                <p class="text-sm text-muted">{{ $assetSearch !== '' ? 'Tidak ada subdomain yang cocok dengan pencarian.' : ($assetView === 'hidden' ? 'Belum ada subdomain tersembunyi dengan respons HTTP.' : 'Belum ada subdomain dengan respons HTTP dalam 48 jam terakhir.') }}</p>
            </div>
        @else
            <table class="w-full table-fixed text-left text-sm">
                <thead class="border-b border-line bg-canvas/55 text-[0.7rem] font-semibold tracking-wide text-muted">
                    <tr>
                        <th scope="col" class="py-3 pr-2 pl-4 sm:pl-6">Subdomain</th>
                        <th scope="col" class="hidden w-[20%] px-3 py-3 xl:table-cell">IP publik</th>
                        <th scope="col" class="hidden w-[20%] px-3 py-3 xl:table-cell">Sumber</th>
                        <th scope="col" class="w-24 py-3 text-right sm:w-32 sm:px-3 xl:text-left">Respons</th>
                        @if ($canManage)
                            <th scope="col" class="w-14 py-3 pr-4 text-right sm:w-30 sm:pr-6"><span class="sr-only sm:not-sr-only">Tindakan</span></th>
                        @endif
                    </tr>
                </thead>
                <tbody class="divide-y divide-line">
                    @foreach ($assets as $asset)
                        <tr class="transition-colors hover:bg-raised/45">
                            <td class="py-3.5 pr-2 pl-4 sm:pl-6">
                                <div class="flex min-w-0 items-center gap-3">
                                    <span class="hidden size-9 shrink-0 place-items-center rounded-lg border border-line bg-canvas text-muted sm:grid"><x-cti-icon name="globe" class="size-4"/></span>
                                    <div class="min-w-0">
                                        <span class="block leading-5 font-semibold wrap-anywhere">{{ $asset->value }}</span>
                                        <span class="mt-0.5 block text-xs leading-4 wrap-anywhere text-muted xl:hidden"><code>{{ $asset->public_ip }}</code> · {{ $asset->source_labels }}</span>
                                    </div>
                                </div>
                            </td>
                            <td class="hidden px-3 py-3.5 text-xs wrap-anywhere text-muted xl:table-cell"><code>{{ $asset->public_ip }}</code></td>
                            <td class="hidden px-3 py-3.5 xl:table-cell"><span class="inline-block rounded-md border border-line bg-canvas px-2 py-1 text-xs text-muted">{{ $asset->source_labels }}</span></td>
                            <td class="py-3.5 text-right sm:px-3 xl:text-left">
                                @php($status = (int) $asset->status_code)
                                <span @class([
                                    'inline-flex items-center gap-1 rounded-full px-2 py-1 text-[0.68rem] font-semibold whitespace-nowrap sm:px-2.5 sm:text-xs',
                                    'bg-signal-bg text-signal' => $status >= 200 && $status < 300,
                                    'bg-amber-500/15 text-amber-200' => $status >= 300 && $status < 400,
                                    'bg-red-500/15 text-red-200' => $status >= 400,
                                ])><x-cti-icon :name="$status >= 200 && $status < 300 ? 'check' : 'activity'" class="size-3.5"/> {{ strtoupper($asset->scheme) }} {{ $status }}</span>
                            </td>
                            @if ($canManage)
                                <td class="py-3.5 pr-4 text-right sm:pr-6">@include('domains.asset-actions', ['fromInventory' => false])</td>
                            @endif
                        </tr>
                    @endforeach
                </tbody>
            </table>
            @if ($assets->hasPages())
                <div class="border-t border-line px-4 py-3 sm:px-6">{{ $assets->links() }}</div>
            @endif
        @endif
    </section>

    @if ($canManage && $assets->isNotEmpty())
        <script>
            document.getElementById('inventaris').addEventListener('click', (event) => {
                const trigger = event.target.closest('[data-asset-dialog-open]');
                if (!trigger) return;

                const dialog = document.getElementById(trigger.getAttribute('aria-controls'));
                if (!(dialog instanceof HTMLDialogElement) || dialog.open) return;

                dialog.querySelectorAll('details[open]').forEach((details) => details.open = false);
                dialog.querySelectorAll('form').forEach((form) => form.reset());
                dialog.showModal();
            });
        </script>
    @endif

    @if ($canManage)
        <section id="kelola-domain" class="cti-panel border-red-500/35 p-5">
            <h2 class="text-base font-bold">Kelola domain</h2>
            <details class="mt-3" @if ($errors->has('delete_confirmation')) open @endif>
                <summary class="cursor-pointer text-sm font-semibold">Hapus domain</summary>
                <p class="mt-2 max-w-xl text-sm leading-6 text-muted">Penghapusan permanen menghentikan discovery dan menghapus observasi aset, jadwal, serta riwayat TLS untuk domain ini dari CTI Jagat Cyber.</p>
                <form class="mt-4 grid max-w-sm gap-2" method="post" action="{{ route('domains.destroy', [$workspace, $monitoredDomain]) }}">
                    @csrf
                    @method('DELETE')
                    <label for="delete-confirmation" class="text-sm font-semibold">Ketik <strong class="wrap-anywhere">{{ $monitoredDomain->hostname }}</strong> untuk konfirmasi</label>
                    <input id="delete-confirmation" name="delete_confirmation" class="cti-field" autocomplete="off" autocapitalize="none" spellcheck="false" maxlength="253" required>
                    <button class="inline-flex items-center gap-2 justify-self-start rounded-xl border border-red-500/45 px-3 py-2.5 text-sm font-semibold hover:bg-red-500/10"><x-cti-icon name="trash" class="size-4"/> Hapus domain permanen</button>
                </form>
            </details>
        </section>
    @endif
@endsection
