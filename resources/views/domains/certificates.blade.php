<section class="cti-panel min-w-0 p-5">
        <p class="cti-eyebrow text-signal">Discovery subdomain</p>
        <h2 class="mt-2 text-base font-bold">Certificate Transparency</h2>
        <p class="mt-2 text-sm leading-6 text-muted">Cert Spotter mencari nama subdomain dari sertifikat publik. Nama yang ditemukan masuk inventaris sebagai observasi sertifikat.</p>
        @if ($monitoredDomain->ct_authorization_id)
            <p class="mt-3 text-sm text-muted">{{ match ($monitoredDomain->ct_status) {
                'complete' => 'Sudah diperiksa. Sumber tidak memiliki halaman baru.',
                'page_saved' => 'Satu halaman tersimpan. Worker akan melanjutkan dari halaman berikutnya secara otomatis.',
                'unavailable' => 'Sumber sedang tidak tersedia. Discovery DNS tetap berjalan.',
                default => 'Aktif. Menunggu discovery pasif berikutnya.',
            } }}</p>
        @elseif ($verified && $active && $workspace->allowsDiscovery())
            <p class="mt-3 text-sm text-muted">Pencarian sertifikat publik akan aktif otomatis melalui scheduler.</p>
        @else
            <p class="mt-3 text-sm text-muted">Pemilik atau admin dapat mengaktifkannya setelah verifikasi TXT dan persetujuan discovery pasif.</p>
        @endif
    </section>
