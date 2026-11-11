# CTI Jagat Cyber — Phase 1

Laravel memakai MySQL dan database `jagat-cyber`. Registrasi membuat empat record dalam satu transaksi. Jika salah satu penyimpanan gagal, seluruh transaksi dibatalkan.

| Tabel | Isi | Kapan bertambah |
| --- | --- | --- |
| `users` | Akun pengguna dengan hash kata sandi | Pengguna mendaftar |
| `organizations` | Workspace dan status langganan | Pengguna mendaftar atau membuat organisasi baru |
| `memberships` | Hubungan akun dengan organisasi, termasuk perannya | Pemilik ditetapkan saat organisasi dibuat |
| `audit_logs` | Riwayat kejadian dan akun pelakunya | Organisasi dibuat |
| `sessions` | Sesi aplikasi | Pengguna mengakses atau masuk ke aplikasi |
| `password_reset_tokens` | Token untuk alur reset kata sandi | Alur reset meminta token. Fitur reset belum tersedia di Phase 1 |

`memberships.user_id` terhubung ke `users.id`. Kolom `organization_id` di `memberships` dan `audit_logs` terhubung ke `organizations.id`. Kolom `audit_logs.actor_id` menunjuk ke akun pelaku.

Workspace mengecek membership setiap kali pengguna membuka organisasi. Laravel membatasi pembacaan dan penulisan audit pada organisasi yang sesuai dan pada peran pemilik atau admin. Migration RLS lama masih kompatibel dengan PostgreSQL dan hanya menambahkan indeks pada MySQL.

## Menjalankan

Pastikan layanan MySQL aktif dan `.env` menunjuk ke `jagat-cyber`. Gunakan `php artisan migrate` untuk membuat tabel yang belum ada dan `php artisan migrate:status` untuk memeriksa statusnya.

```powershell
rtk npm run build
rtk php artisan serve
```

Buka `/login` untuk masuk, `/register` untuk membuat akun dan organisasi, dan `/dashboard` untuk melihat ringkasan. Pengujian standar memakai SQLite in-memory. Untuk pengujian MySQL, gunakan database tes yang terpisah dari `jagat-cyber`.

Lihat [Phase 2](PHASE-2.md) untuk pendaftaran domain, verifikasi, dan inventaris DNS. Temuan pemindaian aktif dan IOC masuk fase berikutnya.
