# CTI Jagat Cyber — Phase 2

## Pendaftaran dan discovery

1. Masuk sebagai pemilik atau admin. Dari dashboard, buka **Domain & aset** dan tambahkan hostname yang dapat Anda kelola.
2. Pasang record TXT dengan nama dan nilai yang tertera di halaman domain. Jika penyedia DNS menambahkan nama zona secara otomatis, gunakan bagian nama relatif saja. Pilih **Periksa TXT** untuk memasukkan verifikasi ke antrean, atau tunggu pemeriksaan terjadwal.
3. Setelah terverifikasi, setujui cakupan discovery pasif. Worker memeriksa kembali token sebelum membaca record A, AAAA, dan CNAME untuk hostname tersebut.
4. Muat ulang halaman domain untuk melihat status job dan inventaris. Gunakan **Cabut izin** untuk menghentikan discovery berikutnya. Jika TXT hilang, verifikasi dibatalkan dan izin perlu disetujui kembali setelah domain terverifikasi.

Inventaris mencatat tipe, nilai, sumber, waktu pertama dan terakhir terlihat, dan kapan record tidak terlihat lagi. Nilai IP dan tujuan CNAME adalah observasi DNS. Lihat [Phase 3](PHASE-3.md) untuk pencarian subdomain dari sertifikat dan pemeriksaan TLS terbatas.

## Data dan batas akses

| Tabel MySQL | Fungsi |
| --- | --- |
| `monitored_domains` | Hostname unik per organisasi, tantangan TXT, masa berlaku, dan status verifikasi |
| `domain_scan_policies` | Persetujuan, ID izin, jadwal berikutnya, serta status job terakhir |
| `discovered_assets` | Inventaris DNS per domain, dengan deduplikasi berdasarkan tipe, nilai, dan sumber |
| `audit_logs` | Pendaftaran domain, rotasi token, persetujuan, dan pencabutan izin |

`organizations 1—* monitored_domains`, `monitored_domains 1—0..1 domain_scan_policies`, dan `monitored_domains 1—* discovered_assets`. Controller mengikat semua operasi pada membership. Hanya pemilik dan admin yang dapat mengubah domain. Job membawa ID organisasi dan domain, serta memeriksa kembali status langganan dan izin sebelum menulis hasil.

Backend ada di `app/Domain/Assets`, `app/Jobs`, dan `app/Policies/MonitoredDomainPolicy.php`. Rute web yang membutuhkan sesi dan CSRF berada di `/organizations/{organization}/domains`. Daftar aksi dapat dilihat melalui `php artisan route:list --path=organizations`.

## Menjalankan

```powershell
rtk php artisan migrate
rtk npm run build
```

Jalankan scheduler dan worker di proses terpisah. Keduanya harus tetap hidup agar pekerjaan berjalan saat dashboard ditutup.

```powershell
rtk php artisan schedule:work
rtk php artisan queue:work --queue=cti --timeout=60 --sleep=3
```

Di Linux, gunakan cron setiap menit untuk `php artisan schedule:run` dan jalankan queue worker di bawah Supervisor atau systemd dengan restart otomatis. Dispatcher hanya memasukkan pekerjaan ke antrean. MySQL menggunakan antrean `database`. Pertahankan `retry_after` di atas timeout worker, dan gunakan cache bersama jika ada beberapa proses atau server. Horizon membutuhkan Redis dan belum dikonfigurasi dalam setup lokal ini.

Default konfigurasi mencakup 20 domain per organisasi, token aktif 7 hari, verifikasi berkala setiap 10 menit, dan discovery pasif setiap 24 jam. Ubah `CTI_DOMAIN_LIMIT`, `CTI_VERIFICATION_TOKEN_DAYS`, `CTI_VERIFICATION_INTERVAL_MINUTES`, atau `CTI_PASSIVE_INTERVAL_HOURS` di `.env` sesuai kebutuhan.

## Pengujian

```powershell
rtk php artisan test --compact tests/Feature/Http/Controllers/MonitoredDomainControllerTest.php tests/Feature/Domain/DomainDiscoveryTest.php
```

Pengujian memakai DNS simulasi dan menguji penolakan akses antarorganisasi, persetujuan sebelum discovery, pencabutan izin saat job berjalan, penyimpanan inventaris, dan worker antrean.
