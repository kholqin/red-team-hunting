# Changelog

Semua perubahan penting pada proyek ini dicatat di dokumen ini.

## [0.1.0] - 2026-09-01

### Ditambahkan

- CLI `redhunt` dan `python -m redhunt` dengan pesan Bahasa Indonesia.
- Validasi URL/hostname dan scope enforcement berbasis `scope.json`.
- Reconnaissance DNS/IP, HTTP security header audit, endpoint discovery, serta API documentation discovery.
- Pemeriksaan CORS wildcard yang aman dan tidak destruktif.
- Static reverse analysis untuk tipe file, hash MD5/SHA1/SHA256/SHA512, strings, dan indikator secret.
- Ekspor JSON, CSV, TXT, Markdown, dan HTML.
- SQLite scan history pada `~/.redhunt/redhunt.db`.
- Dependency doctor dengan pemisahan dependency inti dan opsional secara jujur.
- README, LICENSE, DISCLAIMER, Makefile, dan installer Linux/macOS/Termux/Windows.

### Batasan yang diketahui

- Integrasi Nmap, Nuclei, Subfinder, Amass, FFUF, Gobuster, Jadx, Apktool, dan Radare2 belum dieksekusi otomatis.
- Belum semua target 50 fitur bug bounty, 50 OSINT, dan 20 reverse engineering tersedia; fitur yang belum ada tidak ditampilkan sebagai hasil palsu.
- Rate limit dan concurrency konfigurasi telah disiapkan, tetapi versi awal menjalankan pipeline secara terbatas dan serial untuk menjaga keselamatan.

## [Unreleased]

### Diubah

- Menegaskan bahwa tool tidak menyediakan demo output, dummy output, hasil hardcoded, atau fake finding.
- `vuln` kini menyimpan evidence respons aktual, status `DETECTED`, `NOT DETECTED`, atau `INCONCLUSIVE`, dan tidak membuat finding ketika request gagal.
- Menambahkan finding berbasis observasi aktual untuk security header yang hilang serta CORS wildcard yang benar-benar diterima.

## [Unreleased]

### Ditambahkan

- Modul nyata TLS audit, certificate transparency pasif, robots/sitemap parsing, technology fingerprinting, cookie audit, CORS OPTIONS audit, dan bounded TCP port discovery.
- Enumerasi subdomain berbasis wordlist dengan batas 10.000 kandidat dan hasil resolusi DNS aktual.
- Reverse static analysis tambahan untuk entropy Shannon, magic header, URL/IP extraction, import/export indicators, dan hash.
- Reporting dari file JSON serta `scan list` dari SQLite.
- Interactive mode kini menerima target pengguna dan menjalankan pipeline nyata dengan scope enforcement.
- HTTP engine kini memiliki retry terbatas dengan exponential backoff untuk status/transient error tertentu.
