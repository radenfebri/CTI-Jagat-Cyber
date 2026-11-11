<section id="tls" class="cti-panel min-w-0 p-5">
        <p class="cti-eyebrow text-signal">Pemeriksaan terotorisasi</p>
        <h2 class="mt-2 text-base font-bold">Sertifikat TLS · port 443</h2>
        <p class="mt-2 text-sm leading-6 text-muted">Periksa sertifikat yang dilihat pengunjung melalui WAF atau CDN, atau pilih IP langsung yang Anda kelola. Setiap pemeriksaan mencatat protokol, penerbit, dan masa berlaku sertifikat.</p>
        @if ($monitoredDomain->hasTlsScope())
            @if ($monitoredDomain->tls_scope === \App\Domain\Assets\TlsCheck::PUBLIC_ENDPOINT)
                <p class="mt-3 text-sm text-muted">Endpoint publik disetujui. Worker membaca DNS terbaru saat memeriksa hostname ini.</p>
            @else
                <p class="mt-3 text-sm text-muted">IP langsung yang disetujui <code>{{ $monitoredDomain->tls_approved_ip }}</code></p>
            @endif
            <p class="mt-4 text-xs leading-5 text-muted">Pemeriksaan TLS endpoint publik berjalan otomatis melalui worker.</p>
        @elseif ($canManage && $verified && $workspace->allowsDiscovery())
            <p class="mt-3 text-sm text-muted">Pemeriksaan TLS endpoint publik akan aktif otomatis setelah scheduler memproses verifikasi TXT.</p>
        @elseif ($verified && $canManage)
            <p class="mt-3 text-sm text-muted">Pemeriksaan TLS tersedia saat langganan organisasi aktif.</p>
        @else
            <p class="mt-3 text-sm text-muted">Izin TLS dikelola pemilik atau admin untuk domain terverifikasi.</p>
        @endif

        <div class="mt-5 border-t border-line pt-4">
            <h3 class="text-sm font-semibold">Pemeriksaan terakhir</h3>
            <ul class="mt-2 divide-y divide-line">
                @forelse ($tlsChecks as $check)
                    <li class="grid gap-1 py-2.5 text-xs">
                        <div class="flex flex-wrap justify-between gap-2">
                            <span class="font-semibold">{{ $statusLabels[$check->status] ?? $check->status }} · {{ $check->scopeLabel() }} @if ($check->ip_address) · {{ $check->ip_address }} @endif</span>
                            <span class="text-muted">{{ $formatTime($check->created_at) }}</span>
                        </div>
                        @if ($check->result)
                            <span class="text-muted">{{ $check->result['protocol'] ?? 'TLS' }} · {{ $check->result['issuer'] ?? 'Penerbit tidak tercatat' }} · Berlaku hingga {{ $formatTime(\Illuminate\Support\Carbon::createFromTimestamp($check->result['expires_at'], 'UTC')) }}</span>
                        @elseif ($check->reason)
                            <span class="text-muted">{{ match ($check->reason) {
                                'scope_or_queue_expired' => 'Izin tidak lagi berlaku atau job kedaluwarsa.',
                                'dns_proof_missing' => 'TXT verifikasi tidak ditemukan.',
                                'dns_ip_mismatch' => 'IP yang disetujui tidak lagi cocok dengan DNS atau hostname memakai alias.',
                                'dns_public_endpoint_missing' => 'DNS tidak menghasilkan alamat publik yang dapat diperiksa.',
                                'dns_lookup_failed' => 'Resolver DNS gagal membaca alamat.',
                                'tls_handshake_failed' => 'Koneksi atau validasi sertifikat gagal.',
                                default => 'Worker gagal menyelesaikan pemeriksaan.',
                            } }}</span>
                        @endif
                    </li>
                @empty
                    <li class="py-2.5 text-xs text-muted">Belum ada pemeriksaan TLS.</li>
                @endforelse
            </ul>
        </div>
    </section>
