# CTI Jagat Cyber — Phase 3

Dari **Domain & aset**, buka hostname yang sudah terverifikasi. Halaman domain menampilkan klasifikasi IP dan menyediakan pencarian subdomain pasif, izin pemeriksaan TLS, dan riwayat pemeriksaan.

## Subdomain dari sertifikat publik

Setelah izin discovery pasif aktif, pemilik atau admin dapat mengaktifkan pencarian Certificate Transparency. Worker mengirim hostname ke API Cert Spotter pada discovery berikutnya, lalu menyimpan nama yang berada di bawah hostname tersebut. Cursor menyimpan posisi halaman terakhir sehingga setiap discovery dapat melanjutkan pencarian. Nama wildcard dan nama di luar cakupan dibuang. Subdomain yang ditemukan tetap tercatat sebagai observasi sertifikat.

Kegagalan API atau batas kuota ditampilkan di panel Certificate Transparency. Inventaris DNS tetap diperbarui. Permintaan tanpa API key tersedia secara terbatas untuk penggunaan pribadi atau evaluasi. Konfigurasikan `CTI_CERTSPOTTER_TOKEN` untuk produksi sesuai ketentuan provider. [Dokumentasi Cert Spotter](https://sslmate.com/help/reference/ct_search_api_v1)

## Klasifikasi IP dan pemeriksaan TLS

Inventaris membandingkan IP dengan daftar rentang resmi Cloudflare yang diambil pada 8 November 2026. Aset lain dibedakan menjadi IP nonpublik dan IP publik dengan kepemilikan yang belum dikonfirmasi. [Rentang IP Cloudflare](https://www.cloudflare.com/ips/)

Pemeriksaan TLS port 443 dijalankan manual oleh pemilik atau admin. Pilih satu IP publik dari inventaris DNS dan nyatakan bahwa organisasi berwenang memeriksanya. Sistem mengecualikan rentang Cloudflare yang dikenali, alamat nonpublik, dan hostname yang memakai CNAME. Worker memeriksa ulang membership, izin, langganan, token TXT, dan kecocokan IP dengan DNS. Koneksi diarahkan ke IP yang disetujui dan sertifikat divalidasi menggunakan hostname terdaftar. Pemeriksaan menyimpan protokol, penerbit, waktu kedaluwarsa, dan sidik jari SHA-256.

`monitored_domains` menyimpan pilihan CT dan izin TLS yang berlaku. `discovered_assets` menyimpan hasil CT dengan sumber `certspotter`. `tls_checks` menyimpan job, alasan dilewati atau gagal, dan hasil pemeriksaan. Semua operasi memakai cakupan organisasi. Pencabutan izin membatalkan job TLS yang belum selesai. Jika TXT hilang, izin CT, discovery pasif, dan TLS perlu disetujui ulang setelah verifikasi.

## Menjalankan

```powershell
rtk php artisan migrate
rtk npm run build
rtk php artisan test --compact
```

Muat ulang worker `cti` setelah update kode atau konfigurasi. Lihat [Attack Surface dan otomasi](ATTACK-SURFACE.md) untuk menjalankan scheduler serta worker secara permanen. Uji integrasi memakai resolver DNS, respons Cert Spotter, dan transport TLS simulasi agar tidak membuka koneksi ke target sungguhan. Penjadwalan pemeriksaan aktif, pemindai port dan kerentanan, CVE, dan IOC belum termasuk di fase ini.
