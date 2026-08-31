# Matriks Implementasi RED TEAM HUNTING

Dokumen ini menjadi sumber kebenaran status fitur. Sebuah fitur hanya diberi status **AKTIF** apabila implementasinya memanggil pemeriksaan nyata, menghasilkan evidence yang dapat dilacak, memiliki error state, dan telah diuji pada fixture lokal. Fitur dengan dependency eksternal diberi status **AKTIF BERSYARAT** apabila binary tersebut tersedia; jika tidak, hasilnya `SKIPPED`, bukan `BERHASIL`.

## Aturan status

| Status | Arti |
|---|---|
| AKTIF | Dapat dijalankan dengan dependency inti dan evidence berasal dari proses nyata. |
| AKTIF BERSYARAT | Dapat dijalankan jika dependency atau akses yang disebutkan tersedia. |
| INCONCLUSIVE | Pemeriksaan berjalan tetapi bukti belum cukup untuk menyimpulkan. |
| SKIPPED | Tidak dijalankan karena dependency, izin, atau input yang dibutuhkan tidak tersedia. |
| NOT AVAILABLE | Belum tersedia pada rilis ini dan tidak boleh dipresentasikan sebagai hasil. |

## Batas keselamatan

Toolkit hanya mendukung reconnaissance pasif, request HTTP berkecepatan terbatas, pemeriksaan metadata, static analysis, dan verifikasi non-destruktif. Toolkit menolak destructive request, brute force, credential attack, perubahan database, persistence, malware execution, dan denial-of-service behavior. Fitur vulnerability assessment hanya boleh menggunakan marker aman, baseline comparison, dan input yang tidak mengubah data.

## Core dan orchestration

| Komponen | Status target | Evidence yang diwajibkan |
|---|---|---|
| Target Manager | AKTIF | Jenis target, normalized value, dan error validasi. |
| Scope Manager | AKTIF | Rule yang cocok atau alasan penolakan. |
| Config Manager | AKTIF | File konfigurasi, nilai efektif, dan validasi. |
| Structured Logger | AKTIF | Event bertimestamp dengan secret redaction. |
| HTTP Engine | AKTIF | Method, URL, status, latency, header terpilih, dan error. |
| Async/rate/concurrency engine | AKTIF BERSYARAT | Counter request, delay, timeout, cancellation, dan retry. |
| Cache | AKTIF BERSYARAT | Key, timestamp, TTL, hit/miss. |
| SQLite database | AKTIF | Scan, target, endpoint, finding, evidence, dan log. |
| Output engine | AKTIF | Table, JSON, CSV, TXT, Markdown, HTML. |
| Plugin loader | AKTIF BERSYARAT | Metadata plugin, isolated validation, hasil plugin. |

## Reconnaissance dan web security

| No. | Modul | Kriteria finding nyata |
|---:|---|---|
| 01 | Subdomain enumeration | DNS/CT/passive response yang benar-benar memuat hostname. |
| 02 | DNS enumeration | Record aktual A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, SRV. |
| 03 | WHOIS | Respons WHOIS aktual atau `SKIPPED` jika layanan tidak tersedia. |
| 04 | ASN discovery | Data ASN aktual dari resolver/API yang dikonfigurasi. |
| 05 | IP discovery | Resolusi hostname aktual. |
| 06 | Reverse DNS | PTR response aktual. |
| 07 | Certificate enumeration | Sertifikat TLS yang diterima saat koneksi. |
| 08 | Certificate Transparency | Record CT aktual dari sumber pasif. |
| 09 | Technology fingerprinting | Header, body marker, asset, atau TLS evidence aktual. |
| 10 | HTTP header analyzer | Header aktual dari response. |
| 11 | HTTP status mapper | Status aktual setiap endpoint yang diuji. |
| 12 | Directory discovery | Hanya wordlist yang diberikan pengguna dan request rate-limited. |
| 13 | Endpoint discovery | Link/script/robots/sitemap yang benar-benar diekstrak. |
| 14 | robots analyzer | robots.txt aktual dan directive yang diparsing. |
| 15 | sitemap analyzer | sitemap aktual dan URL hasil parsing. |
| 16 | JavaScript extraction | JavaScript aktual yang diambil dari target berizin. |
| 17 | Parameter discovery | Parameter aktual dari URL/form/script. |
| 18 | Security header audit | Header yang hilang/bermasalah berdasarkan response aktual. |
| 19 | Cookie audit | Set-Cookie aktual dan atribut yang teramati. |
| 20 | CORS analyzer | Header CORS aktual dari response/preflight aman. |

## Vulnerability assessment aman

| No. | Modul | Batas implementasi |
|---:|---|---|
| 21 | Reflected XSS | Marker inert, satu request terkontrol, hanya reflection evidence. |
| 22 | Stored XSS indicator | Hanya indikator form dan hasil observasi; tidak melakukan penyimpanan otomatis. |
| 23 | SQLi detection | Baseline/differential konservatif; tidak ada query destructive atau credential access. |
| 24 | NoSQL indicator | Analisis parameter dan response signal tanpa operator destructive. |
| 25 | SSTI | Marker aritmetika aman hanya bila endpoint/input eksplisit diizinkan. |
| 26 | Open redirect | Redirect observation memakai marker eksternal yang tidak berbahaya. |
| 27 | SSRF indicator | Identifikasi parameter URL; callback hanya endpoint milik pengguna. |
| 28 | LFI indicator | Marker path non-destructive dan tidak membaca file rahasia. |
| 29 | Path traversal | Pemeriksaan bounded terhadap fixture/endpoint berizin. |
| 30 | IDOR candidate | Perbandingan resource yang disediakan pengguna; tidak mencoba akun pihak lain. |

## API, network, cloud, OSINT, dan reverse

Modul API mengurai OpenAPI/Swagger/GraphQL yang benar-benar ditemukan dan mendeteksi pola autentikasi tanpa brute force. Network scanning dibatasi CIDR/host yang diizinkan, port eksplisit, timeout, dan concurrency. Cloud/OSINT hanya memakai sumber publik yang sah serta tidak mengambil kredensial atau data privat. Reverse engineering tetap static-only: file type, hash, strings, entropy, headers, metadata, symbols, URL/IP extraction, dan secret indicator dengan redaction.

## Definition of done proyek

Rilis dianggap siap ketika setiap command yang terdaftar memiliki backend nyata atau secara jujur menghasilkan `NOT AVAILABLE/SKIPPED`; tidak ada menu yang mengembalikan hasil hardcoded; evidence dapat ditelusuri; test lokal tidak menyerang internet; `redhunt --help`, `doctor`, `interactive`, recon, web, vuln, osint, reverse, reporting, database, scope, rate limiting, dan error handling dapat diverifikasi.
