# Attack Surface dan otomasi pasif

Dari dashboard, buka **Manajemen Aset → Inventaris aset** untuk melihat domain terverifikasi, subdomain, observasi IP, perubahan, dan jadwal discovery pada organisasi aktif.

Buka **Attack Surface → Layanan TLS** untuk melihat riwayat pemeriksaan layanan pada port 443. Hasil berhasil memuat protokol, penerbit, masa berlaku sertifikat, dan IP yang diperiksa. Dari **Cakupan pemeriksaan**, pemilik atau admin memilih domain terverifikasi dan mengizinkan **Endpoint publik (WAF/CDN)** atau **IP langsung** yang dikelola. Pilih **Periksa TLS** untuk mengantrekan pemeriksaan. Mode endpoint publik memakai DNS saat job dijalankan dan memeriksa satu alamat dengan hostname asli, sehingga sertifikat yang dicatat adalah yang disajikan kepada pengunjung pada alamat tersebut. Inventaris subdomain tetap memakai discovery publik, konektor DNS, atau impor.

## Scan port penuh

Menu **Attack Surface → Kerentanan aset** menampilkan ringkasan domain, hostname, teknologi, dan port yang sudah diamati. Pemilik atau admin dapat memulai scan TCP port **1–65535** hanya setelah menyetujui cakupan **IP langsung**. Scan dibagi menjadi beberapa job worker, menyimpan port terbuka ke `port_scan_runs` dan `port_scan_results`, serta dapat dibatalkan dari halaman detail aset. Endpoint Cloudflare/WAF sengaja tidak dipindai sebagai origin karena alamat tersebut adalah edge bersama dan tidak mewakili port server pelanggan.

Pemeriksaan web juga menyimpan fingerprint pasif dari header dan HTML terbatas, seperti versi PHP dari `X-Powered-By`, server web, Bootstrap, jQuery, WordPress, Laravel, React, Vue, dan Angular bila bukti terlihat. Fingerprint tidak dianggap pasti; simpan sumber (`header`, `body`, atau `cookie`) agar tahap korelasi CVE dapat menilai kualitas buktinya.

## Menambahkan domain

1. Pilih **Manajemen Aset → Domain & verifikasi** dan tambahkan hostname yang dapat Anda kelola.
2. Pasang record TXT yang ditampilkan dan tunggu verifikasi. Pemilik atau admin dapat memilih **Periksa TXT** untuk mengantrekan pemeriksaan lebih awal.
3. Setujui discovery DNS pasif. Centang pilihan sertifikat jika organisasi juga mengizinkan pencarian subdomain melalui Cert Spotter. Untuk domain yang sudah aktif, gunakan **Aktifkan pencarian sertifikat** pada detail domain.
4. Worker menyimpan observasi A, AAAA, CNAME, dan nama subdomain dari Certificate Transparency ke `discovered_assets`. Perubahan muncul di `asset_observation_changes` ketika observasi baru muncul, hilang dari hasil DNS, atau terlihat kembali.

Discovery reguler berjalan setiap 24 jam secara default. Setelah pencarian sertifikat diaktifkan, scheduler mengantrekan pemeriksaan pada putaran berikutnya. Selama masih ada halaman sertifikat, worker menyimpan cursor dan melanjutkan setelah sekitar 15 menit. Atur interval dengan `CTI_PASSIVE_INTERVAL_HOURS` dan `CTI_CT_PAGE_INTERVAL_MINUTES`. Hasil sertifikat adalah nama yang tercatat di CT dan tidak membuktikan hostname masih aktif. [Dokumentasi API Cert Spotter](https://sslmate.com/help/reference/ct_search_api_v1)

Riwayat dimulai setelah migration terpasang. Observasi lama tetap terlihat di inventaris.

## Sumber daftar subdomain

Verifikasi TXT, discovery DNS publik, dan Certificate Transparency dapat dipakai dengan penyedia DNS mana pun. Record TXT tidak menyediakan daftar isi zona. Jika subdomain tidak muncul di sertifikat publik, buka detail domain terverifikasi dan gunakan **Impor file zona BIND** dari penyedia yang mendukung ekspor tersebut, atau **Impor daftar hostname** untuk nama per baris. Impor menyimpan nama konkret dalam cakupan domain, tanpa nilai record. Impor berikutnya menambah atau memperbarui observasi dan tidak menghapus nama dari impor sebelumnya. File BIND dibatasi 256 KB dan 1.000 nama per impor; direktif yang mengacu ke file lain atau menghasilkan record tidak didukung.

### Konektor Cloudflare opsional

Untuk sinkronisasi otomatis satu zona, buat token Cloudflare dengan izin `Zone → DNS → Read` yang dibatasi ke zona tersebut. Isi `CTI_CLOUDFLARE_DOMAIN_ID` dengan ID domain dari halaman detail aplikasi, `CTI_CLOUDFLARE_ZONE_ID` dengan Zone ID Cloudflare, dan `CTI_CLOUDFLARE_TOKEN` dengan token baca di `.env`. Muat ulang konfigurasi dan worker. Discovery pasif berikutnya hanya menyimpan nama dalam cakupan domain terverifikasi. Integrasi menyimpan nama dari daftar zona tanpa konten record, melewati wildcard dan record private routing, serta menandai penghapusan hanya setelah daftar lengkap berhasil dibaca. [Cloudflare List DNS Records](https://developers.cloudflare.com/api/resources/dns/subresources/records/methods/list/)

## Cron lewat URL

Untuk aaPanel atau layanan cron web, buat tugas **Access URL / GET** setiap menit. Gunakan alamat HTTPS tempat CTI Jagat Cyber dihosting dan salin token dari `CTI_CRON_TOKEN` di `.env`.

```text
https://HOST_APLIKASI/api/cron/cti?token=TOKEN_CRON
```

Gunakan `QUEUE_CONNECTION=database` dan cache yang mendukung lock, seperti `CACHE_STORE=database`. Jika token belum diisi pada server, isi dengan 64 karakter heksadesimal acak. Jalankan `rtk php artisan config:clear` jika konfigurasi dicache. Atur timeout pemanggil URL sekitar 60 detik dan simpan URL sebagai rahasia. Jika panel atau reverse proxy mencatat URL, sembunyikan parameter `token` di log.

Setiap panggilan memproses maksimal satu job dari antrean `cti`. Saat antrean kosong, endpoint mengantrekan pekerjaan yang jatuh tempo. Respons `tick_completed` berarti panggilan cron selesai. Periksa hasil discovery atau TLS di dashboard. Gunakan metode URL ini sebagai satu-satunya scheduler bila layanan hanya mendukung cron web.

## Windows Task Scheduler

Jalankan dari direktori proyek. Pastikan MySQL aktif, PHP CLI tersedia, dan akun task dapat membaca proyek serta menulis ke `storage/logs`. Jalankan migration dan build sebelum mendaftarkan task.

```powershell
rtk php artisan migrate
rtk npm run build
rtk powershell -NoProfile -File deploy/windows/Register-CtiTasks.ps1 -WhatIf
rtk powershell -NoProfile -File deploy/windows/Register-CtiTasks.ps1
```

Script mendaftarkan task `CTI-Jagat-Cyber-Scheduler` dan `CTI-Jagat-Cyber-Worker`. Keduanya dijadwalkan setiap menit. Scheduler hanya mengantrekan job yang jatuh tempo. Worker menguras antrean `cti` dan berhenti jika kosong. Task Scheduler mengabaikan pemanggilan baru bila instans sebelumnya masih berjalan. Output disimpan per hari di `storage/logs/cti-scheduler-YYYY-MM-DD.log` dan `storage/logs/cti-worker-YYYY-MM-DD.log`. [Microsoft Task Scheduler](https://learn.microsoft.com/en-us/powershell/module/scheduledtasks/register-scheduledtask)

Secara default task memakai sesi pengguna Windows yang sedang masuk. Untuk berjalan setelah sign-out, gunakan akun task yang punya akses proyek, database, dan jaringan, lalu jalankan PowerShell sebagai administrator bila diperlukan.

```powershell
.\deploy\windows\Register-CtiTasks.ps1 -Credential (Get-Credential)
```

Hentikan proses `schedule:work` dan `queue:work` manual untuk proyek ini setelah kedua task terdaftar. Periksa **Last Run Result** di Task Scheduler dan cek log aplikasi untuk kegagalan job.

## Linux dan aaPanel

Gunakan template [cron](../deploy/linux/cti-jagat-cyber.cron.example) dan [unit systemd](../deploy/linux/cti-jagat-worker.service). Sesuaikan direktori, executable PHP, dan akun sistem dengan instalasi Anda. Pasang cron sebagai `/etc/cron.d/cti-jagat-cyber` dan unit sebagai `/etc/systemd/system/cti-jagat-worker.service`, lalu jalankan `systemctl daemon-reload` dan `systemctl enable --now cti-jagat-worker`.

Pilih metode ini jika server Anda menyediakan cron dan systemd. Untuk tugas aaPanel yang hanya menerima URL, gunakan bagian **Cron lewat URL**.
