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

## [Unreleased]

### Ditambahkan

- Plugin `http_methods` dengan pemeriksaan OPTIONS nyata dan evidence response aktual.
- Output tabel terminal sebagai format default.
- Status agregat scan membedakan penyelesaian dan kondisi inconclusive akibat error pemeriksaan.
- Pemeriksaan marker refleksi aman dan observasi redirect eksternal untuk parameter query yang memang tersedia.

## [Unreleased]

### Ditambahkan

- Adapter subprocess aman untuk Nmap, Nuclei, Subfinder, Amass, FFUF, Gobuster, Masscan, Jadx, Apktool, dan Radare2 dengan `shell=False`, timeout, capture output, dan status `SKIPPED/FAILED` yang jujur.
- Dukungan template `scope.yaml.example`, `docker-compose.yml`, launcher root `redhunt.py`, dan parsing scope YAML sederhana.
- Cache TTL, plugin loader dengan validasi class `Plugin.run`, cloud fingerprint, passive OSINT, TLS audit, port discovery, reverse static analysis, dan safe web indicators.

## [Unreleased]

### Ditambahkan

- API document analyzer untuk OpenAPI/Swagger dan observasi GraphQL GET dengan evidence respons aktual.
- JWT analyzer read-only yang mendekode header/claims tanpa memverifikasi, memalsukan, atau mengirim token.
- Launcher root diperbaiki agar `python redhunt.py` berjalan dari checkout tanpa konflik nama package.

## [Unreleased]

### Diubah

- Schema SQLite diperluas untuk entitas project, target, domain, subdomain, IP, port, service, technology, endpoint, parameter, finding, evidence, OSINT, reverse result, job, dan log.

## [Unreleased]

### Ditambahkan

- Command `redhunt source --path` untuk static source analysis lintas puluhan bahasa dan format.
- Language detection berbasis ekstensi dan file manifest/dependency.
- Deteksi import/use, symbol, embedded secret dengan redaction, dangerous execution, unsafe deserialization, weak cryptography, dynamic SQL, insecure TLS/HTTP, unsafe HTML sink, serta smart-contract indicators.
- Evidence source-code menyertakan path, nomor baris, rule ID, severity, confidence, snippet tersanitasi, dan remediation.
- Test untuk ekstensi Python, TypeScript, Solidity, Rust, SQL, secret redaction, dan unknown language.

## [Unreleased]

### Ditambahkan

- Katalog terstruktur untuk seluruh 50 bug bounty, 50 OSINT, dan 20 reverse engineering dengan ID unik, executor, safety class, dan status yang dapat diaudit.
- Command `redhunt features` dengan filter kategori untuk meninjau coverage dan mencegah klaim fitur yang belum memiliki backend.
- Test katalog memastikan jumlah 120 fitur dan keunikan ID.

## [Unreleased]

### Ditambahkan

- Executor `osint_run` untuk seluruh 50 modul OSINT dengan ID `OS-01` sampai `OS-50`.
- Normalisasi output setiap modul ke `id`, `name`, `status`, `data`, dan `evidence`.
- Collector nyata untuk DNS/IP/PTR, CT, TLS, GitHub public search, historical URL, technology/CMS/JS/WAF/CDN/cloud, email, URL/graph, API documentation, security.txt, robots, dan sitemap.
- Status `SKIPPED`, `NOT TESTED`, dan `INCONCLUSIVE` untuk sumber yang memerlukan input atau provider tambahan, sehingga tidak berubah menjadi finding palsu.
- Integration test yang mengeksekusi dan memvalidasi 50 executor OSINT.
