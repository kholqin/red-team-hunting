# RED TEAM HUNTING

**M4zk1pL4y Scurity**

Toolkit CLI lintas platform untuk reconnaissance, analisis HTTP/API, pemeriksaan indikasi keamanan non-destruktif, analisis file statis, dan pelaporan terhadap target yang memang berada dalam scope pengujian.

> Tool ini bukan alat untuk akses tanpa izin. Pengguna bertanggung jawab memastikan otorisasi tertulis, scope, rate limit, dan hukum yang berlaku sebelum menjalankan pemeriksaan.

## Status implementasi

Versi awal ini memprioritaskan modul yang benar-benar bekerja dan tidak memalsukan hasil: validasi target, scope enforcement, DNS/IP discovery, HTTP header audit, endpoint discovery berbasis respons, API documentation discovery, pemeriksaan CORS wildcard, analisis file reverse statis, JSON/CSV/TXT/Markdown/HTML export, SQLite scan history, dan doctor dependency check. Integrasi eksternal seperti Nmap/Nuclei tidak dijalankan otomatis dan hanya menjadi dependency opsional yang terdeteksi oleh `doctor`.

| Area | Status |
|---|---|
| CLI dan error Bahasa Indonesia | Tersedia |
| Scope enforcement | Tersedia melalui `scope.json` |
| Safe mode dan User-Agent transparan | Tersedia |
| DNS, HTTP, endpoint, API discovery | Tersedia |
| Vulnerability checks | Terbatas pada indikasi aman, tanpa eksploitasi |
| Reverse static analysis | Tersedia: tipe, hash, strings, indikator secret ter-redaksi |
| SQLite scan history | Tersedia |
| Plugin/external adapters | Belum diaktifkan pada rilis awal; dependency dideteksi secara jujur |
| 100+ test dan seluruh 120 modul | Belum; tidak diklaim selesai |

## Instalasi

Membutuhkan Python 3.11 atau lebih baru.

```bash
python -m venv .venv
# Linux/macOS/Termux
. .venv/bin/activate
# Windows PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -e .
```

Linux/macOS/Termux dapat menggunakan `install.sh`, sedangkan Windows PowerShell menggunakan `install.ps1`. macOS dapat memasang Python melalui Homebrew; Arch Linux dapat menggunakan paket Python sistem atau virtual environment. Tool tidak memerlukan root, systemd, atau path `/usr/bin` tertentu.

## Quick start

```bash
redhunt --help
redhunt doctor
redhunt recon example.com --output json --out recon.json
redhunt web https://example.com --output md --out report.md
redhunt api https://example.com
redhunt vuln https://example.com
redhunt reverse sample.apk --output json
redhunt full example.com --output html --out report.html
```

Perintah HTTP hanya mengirim request yang terbatas, mengikuti timeout, dan menggunakan User-Agent `Red-Team-Hunting/0.1.0`. Tidak ada brute force, credential attack, destructive SQL, persistence, atau denial-of-service behavior.

## Scope

Jika `scope.json` tersedia, enforcement aktif secara default dan target di luar daftar akan ditolak. Wildcard subdomain didukung.

```json
{
  "allowed": ["example.com", "*.example.com"],
  "excluded": ["admin.example.com"]
}
```

Untuk target produksi, sesuaikan aturan scope dengan izin tertulis. Jangan mematikan enforcement kecuali memahami risikonya.

## Konfigurasi

Konfigurasi opsional disimpan di `~/.redhunt/config.json` atau direktori yang ditentukan `REDHUNT_HOME`.

```json
{
  "safe_mode": true,
  "scope_enforcement": true,
  "timeout": 10,
  "rate_limit": 5,
  "concurrency": 10
}
```

## Output dan database

`--output` mendukung `json`, `csv`, `txt`, `md`, dan `html`. `--out FILE` menyimpan hasil ke file. Riwayat scan disimpan pada `~/.redhunt/redhunt.db` menggunakan SQLite. Data hasil harus diperlakukan sebagai data sensitif; tool tidak dimaksudkan untuk menyimpan token atau password secara plaintext.

## Development dan testing

```bash
make install
make test
make lint
make format
make build
make clean
```

Test tidak mengakses target internet secara otomatis. Fokus pengujian unit adalah parsing target, scope, reverse hashing, dan format output.

## Disclaimer

Lihat [DISCLAIMER.md](DISCLAIMER.md). Dengan menjalankan tool ini, pengguna menyatakan memiliki kewenangan untuk menguji target yang dipilih dan menerima tanggung jawab penuh atas penggunaan, dampak, kepatuhan, serta perlindungan data yang terkait.

## Provenance finding

Perintah `redhunt vuln TARGET` hanya membuat finding apabila pemeriksaan aktual memperoleh evidence dari target, misalnya header HTTP yang benar-benar tidak ada atau nilai CORS yang benar-benar diterima dalam respons. Jika request gagal, hasilnya `INCONCLUSIVE` dan tidak ada finding yang dibuat. Jika tidak ada indikator, statusnya `NOT DETECTED`. Tidak tersedia mode demo, data contoh, hasil hardcoded, atau fake finding.

Gunakan hanya pada target yang berada dalam scope dan telah memperoleh izin. Contoh berikut melakukan pemeriksaan nyata terhadap target yang Anda miliki:

```bash
redhunt vuln https://target-berizin.example --output json --out findings.json
```

## Plugin yang tersedia

Plugin `plugins/http_methods` memeriksa method yang diiklankan melalui respons `OPTIONS` aktual. Plugin manager menemukannya melalui `plugin.yaml`; plugin tidak dijalankan otomatis terhadap target dan harus diintegrasikan oleh operator setelah scope dan izin dikonfirmasi.

## Source-code analyzer lintas bahasa

Gunakan `redhunt source --path FILE_ATAU_DIREKTORI` untuk menganalisis source code secara statis. Engine mendeteksi puluhan bahasa dan format, termasuk Java, JavaScript, TypeScript, PHP/Laravel, C/C++, C#, Python, Ruby, Go, Rust, Kotlin, Swift, Dart, R, MATLAB, Lua, Perl, Objective-C, Scala, Elixir, Haskell, Erlang, Julia, Fortran, COBOL, Assembly, SQL, PL/SQL, T-SQL, PL/pgSQL, Solidity, GDScript, Visual Basic, F#, Zig, D, Ada, Nim, Lisp, Clojure, OCaml, Move, Vyper, dan Cairo.

```bash
redhunt source --path ./src --output json --out source-findings.json
redhunt source --path ./Contract.sol --output html --out contract-report.html
```

Analyzer menghasilkan language detection, SHA-256, import/use, symbol, secret indicator dengan redaction, dangerous execution/deserialization, weak crypto, dynamic SQL, insecure HTTP/TLS, unsafe HTML sink, dan smart-contract risk indicators. Hasil adalah **static indicator** dengan path dan nomor baris, bukan klaim exploitability. Kode target tidak dijalankan.

## Katalog 120 fitur

Gunakan `redhunt features` untuk melihat seluruh 50 fitur bug bounty, 50 fitur OSINT, dan 20 fitur reverse engineering beserta executor dan status implementasinya. Filter kategori tersedia melalui `redhunt features BUG_BOUNTY`, `redhunt features OSINT`, atau `redhunt features REVERSE`. Status katalog bersifat audit-able: `AVAILABLE` berarti executor nyata tersedia; `PLANNED` berarti belum boleh dianggap sebagai hasil scan dan tidak menghasilkan finding palsu.

## 50 OSINT executor aktif

Command `redhunt osint TARGET --output json --out osint.json` kini menjalankan seluruh 50 executor OSINT dan mengembalikan satu record ter-normalisasi untuk setiap ID `OS-01` sampai `OS-50`. Collector yang membutuhkan input khusus atau provider berizin mengembalikan `SKIPPED` dengan alasan eksplisit; collector yang dapat memakai target dan respons aktual mengembalikan evidence/provenance aktual. Tidak ada credential harvesting, breach-data retrieval, brute-force profile search, atau klaim bahwa status `SKIPPED` adalah finding.

## Bug bounty executor

Command `redhunt bugbounty TARGET --output json --out bugbounty.json` menjalankan aggregator untuk 50 fitur bug bounty. Modul yang dapat melakukan observasi aman akan mengumpulkan evidence aktual dari DNS, CT, TLS, HTTP, API, CORS, cookie, cloud, endpoint, atau port input. Modul yang memerlukan dua identitas, provider, path, atau persetujuan khusus akan mengembalikan `SKIPPED` atau `NOT TESTED` dan tidak membuat finding palsu.

## Tampilan CLI neon

Mode `redhunt interactive` menggunakan banner ASCII dengan branding `RED TEAM HUNTING` dan `M4zk1pL4y Scurity`, tabel menu bernomor untuk seluruh 120 fitur, indikator status `AVAILABLE/PLANNED`, serta shortcut kategori. Warna otomatis dinonaktifkan ketika output bukan terminal interaktif atau ketika environment `NO_COLOR` tersedia, sehingga tetap aman dipakai pada Windows CMD, CI/CD, Termux, dan redirect file.

## Runner paralel bug bounty dan OSINT

Skrip `scripts/parallel_scan.py` menjalankan command `bugbounty` dan `osint` secara paralel untuk setiap target yang tercantum pada file target. Scope JSON wajib diberikan sehingga target di luar domain yang diizinkan ditolak sebelum job dimulai. Runner juga membatasi jumlah worker, timeout setiap modul, jumlah target, dan mendukung pembatalan melalui `Ctrl-C` atau SIGTERM.

Contoh konfigurasi dan eksekusi:

```bash
cat > scope.json <<'JSON'
{"allowed": ["example.com", "*.owned.example.net"]}
JSON

cat > targets.txt <<'EOF'
https://example.com
https://app.owned.example.net
EOF

python3 scripts/parallel_scan.py \
  --targets targets.txt \
  --scope scope.json \
  --workers 2 \
  --module-timeout 180 \
  --output-dir reports/parallel
```

Runner membuat satu file JSON per kombinasi target/modul dan `manifest.json` yang memuat status, return code, elapsed time, stdout/stderr terbatas, dan lokasi laporan. Nilai exit code `0` berarti seluruh job selesai; nilai `1` berarti ada job gagal, timeout, atau tidak selesai; nilai `2` berarti input atau scope ditolak. Runner tidak melakukan eksploitasi, brute force, credential collection, atau bypass kontrol akses.

## Menjalankan fitur individual

Setiap feature ID memiliki jalur dispatch individual melalui command `feature`. Untuk bug bounty dan OSINT, berikan URL melalui `--input`; untuk reverse engineering, berikan file melalui `--path`.

```bash
redhunt feature BB-18 --input https://target-berizin.example --output json
redhunt feature OS-07 --input https://target-berizin.example --output json
redhunt feature RE-02 --path ./sample.bin --output json
```

Dispatcher memvalidasi ID terhadap katalog, menjalankan executor kategori yang sesuai, dan mengembalikan evidence aktual. Fitur yang tidak dapat disimpulkan dari input yang tersedia tetap mengembalikan `INCONCLUSIVE`, `SKIPPED`, atau `NOT TESTED`; status tersebut tidak pernah diubah menjadi finding atau sukses palsu.

## Fixture lab lokal untuk memenuhi prasyarat

Direktori `lab/` berisi fixture HTTP yang hanya bind ke `127.0.0.1:18080`. Fixture ini menyediakan response aktual untuk header audit, cookie, CORS OPTIONS, robots.txt, sitemap.xml, OpenAPI, GraphQL GET, security.txt, JavaScript endpoint, debug marker, dan reflected marker. Jalankan `python3 lab/fixture_server.py`, lalu pindai hanya alamat lokal tersebut. Fixture dipakai untuk memverifikasi jalur executor; finding yang muncul berlaku untuk fixture, bukan otomatis untuk sistem produksi.

## Scan profiles

CLI kini menerima profile `passive`, `safe`, `standard`, `aggressive`, dan `deep`. Profile mengatur timeout, rate limit, concurrency, kedalaman crawling, dan apakah active testing diizinkan. Profile `aggressive` memperluas discovery dan recursive workflow, tetapi tetap memaksa `safe_mode` dan tidak mengizinkan DROP, DELETE, TRUNCATE, ALTER, UPDATE, INSERT, credential stuffing, password spraying, denial-of-service, persistence, malware deployment, atau penghancuran data.

```bash
python3 redhunt.py full https://target-berizin.example --profile aggressive --output json --out report.json
python3 redhunt.py full https://target-berizin.example --profile deep --output html --out report.html
```

Profile tidak mengubah status evidence menjadi sukses. Jika target tidak merespons, dependency tidak tersedia, atau bukti tidak cukup, output tetap menunjukkan kegagalan atau status `INCONCLUSIVE`.

## Layout CLI bergaya Termux

Mode interactive kini menggunakan layout terminal mobile yang lebih dekat dengan referensi: ASCII art besar berwarna, tiga kolom kategori, ID fitur dalam format `[BB-01]`, `[OS-01]`, `[RE-01]`, footer shortcut, serta status Safe Mode dan scope enforcement. Semua 120 entry benar-benar dirender dari katalog runtime; pengujian memverifikasi 50 Bug Bounty, 50 OSINT, dan 20 Reverse Engineering. Warna dan clear-screen otomatis dinonaktifkan pada non-TTY atau ketika `NO_COLOR`/`REDHUNT_NO_CLEAR` digunakan.

## Status katalog 120 fitur

Katalog kini tidak lagi menggunakan label `PLANNED`. Seluruh 120 entry berstatus `AVAILABLE` karena masing-masing memiliki jalur executor yang dapat dipanggil melalui dispatcher. Status hasil runtime tetap ditentukan oleh evidence: `DETECTED`, `NOT DETECTED`, `SKIPPED`, `NOT TESTED`, atau `INCONCLUSIVE`. Dengan demikian, `AVAILABLE` berarti implementasi dapat dipanggil, bukan bahwa setiap target pasti memiliki kerentanan.

## Memilih fitur dari menu interactive

Perintah `python redhunt.py interactive` sekarang menampilkan menu utama tiga kolom seperti referensi. Pengguna memilih ID, bukan hanya melihat daftar. Untuk `BB-*` dan `OS-*`, menu meminta target URL/domain lalu memeriksa scope sebelum executor dijalankan. Untuk `RE-*`, menu meminta path file/source/binary. Setelah executor selesai, hasil evidence dan status ditampilkan sebelum pengguna kembali ke menu.

Contoh alur:

```text
Pilih ID fitur (BB-01/OS-01/RE-01), atau 0 untuk keluar: BB-18
Target URL/domain berizin: https://target-berizin.example
[hasil security header aktual]
Tekan Enter untuk kembali ke menu...
```

Pilihan `0`, `q`, `x`, `exit`, atau `keluar` menutup interactive mode dengan bersih.

## Peluncuran langsung ke menu

Mulai versi ini, menjalankan `python redhunt.py` tanpa subcommand langsung membuka menu interaktif 120 fitur. Pengguna memilih feature ID terlebih dahulu; setelah itu tools meminta URL/domain untuk Bug Bounty atau OSINT, dan path file untuk Reverse Engineering, lalu menjalankan executor yang sesuai.

```bash
python redhunt.py
```

Perintah administratif tetap tersedia secara eksplisit, misalnya `python redhunt.py doctor`, `python redhunt.py features`, dan `python redhunt.py --help`.

## Header menu utama

Saat tools dibuka, urutan tampilan sekarang adalah banner besar **M4zk1pLay Hunting**, blok **DISCLAIMER**, label kecil **red_team Tools**, indikator Safe Mode dan scope enforcement, kemudian menu tiga kolom berisi 120 pilihan fitur. Pengguna baru diminta memilih fitur setelah seluruh disclaimer dan menu terlihat.

## Automatic target-aware engine pipeline

Command `full` kini menggunakan pipeline target-aware. Engine menentukan apakah input merupakan file, domain, URL, IP URL, atau tipe lain yang belum didukung, kemudian memilih engine yang sesuai. Untuk domain/URL, aggregator Bug Bounty dan OSINT dijalankan satu kali agar tidak membuat request duplikat. Untuk file, seluruh reverse executor dijalankan terhadap file aktual. Setiap hasil membawa `target_kind`, `profile`, `engine`, feature ID, status, dan evidence.

```bash
python3 redhunt.py full https://target-berizin.example --profile standard --output json --out full.json
python3 redhunt.py full ./sample.apk --profile safe --output json --out reverse.json
```

Pipeline tidak menganggap semua target sebagai website dan tidak membuat finding untuk tipe target yang belum memiliki adapter. Hasil yang tidak dapat diverifikasi tetap menggunakan status `SKIPPED`, `NOT TESTED`, atau `INCONCLUSIVE`.

## Verifikasi dan Bahasa Indonesia

Engine pemeriksaan HTTP kini menyimpan fingerprint response pertama dan pengulangan untuk mengurangi false positive. Finding header hanya berstatus terdeteksi pada hasil agregat bila hasil pengulangan konsisten; jika response berubah atau pengulangan gagal, status menjadi belum konklusif. Nilai status dan label field pada output JSON, CSV, Markdown, HTML, dan tabel diterjemahkan ke Bahasa Indonesia untuk pembacaan operator, sementara feature ID tetap dipertahankan agar dapat diotomatisasi.

## Verifikasi multi-pass

Untuk meningkatkan keandalan hasil, pemeriksaan vulnerability HTTP dapat dijalankan beberapa kali. Engine menyimpan fingerprint dan daftar indikator pada setiap pass. Finding hanya berstatus `TERDETEKSI` ketika indikator konsisten; perubahan response menghasilkan `BELUM KONKLUSIF`.

```bash
python3 redhunt.py vuln https://target-berizin.example \
  --verify-passes 3 \
  --verify-delay 1 \
  --output json \
  --out laporan-verifikasi.json
```

`--verify-passes` dibatasi 2 sampai 5 pass dan `--verify-delay` dibatasi maksimal 30 detik. Pengulangan ini hanya memakai request pemeriksaan yang aman dan tidak melakukan mutasi data.

## Katalog CVE nyata dan korelasi evidence

RED TEAM HUNTING kini memiliki katalog CVE lokal yang bersumber dari **NVD JSON 2.0** dan penanda eksploitasi dari **CISA Known Exploited Vulnerabilities (KEV)**. Sistem menyimpan record asli, deskripsi, CVSS, CWE, vendor, product, versi, CPE, referensi, dan status KEV ke SQLite. Sistem tidak membuat template CVE sintetis dan tidak mengubah kandidat menjadi verified hanya karena nama teknologi terlihat mirip.

Inisialisasi atau pembaruan satu tahun:

```bash
python3 redhunt.py cve --cve-action sync --cve-year 2025
```

Sinkronisasi seluruh feed dari 2002 hingga tahun yang dipilih:

```bash
python3 redhunt.py cve --cve-action sync --cve-all-years --cve-year 2025
```

Melihat statistik katalog dan mencari CVE:

```bash
python3 redhunt.py cve --cve-action stats
python3 redhunt.py cve --cve-action search nginx --cve-limit 20 --output json
```

Korelasi harus menggunakan evidence product dan versi yang benar-benar teramati, misalnya dari inventaris software resmi atau hasil fingerprint yang tervalidasi:

```bash
python3 redhunt.py cve --cve-action correlate \
  --cve-product nginx \
  --cve-version 1.24.0 \
  --cve-limit 20 \
  --output json
```

Kecocokan versi eksplisit dapat berstatus `DETECTED` sebagai korelasi CVE, sedangkan product cocok tetapi versi belum cocok hanya menjadi `INCONCLUSIVE`. Jika evidence product tidak tersedia, hasilnya `NOT TESTED`. Korelasi CVE bukan bukti exploitability; temuan tetap memerlukan verifikasi non-destruktif dan pemeriksaan kondisi yang tercantum pada record CVE.

Sumber data resmi: [NVD Vulnerability API](https://nvd.nist.gov/developers/vulnerabilities), [NVD Data Feeds](https://nvd.nist.gov/vuln/data-feeds), [CISA KEV Catalog](https://www.cisa.gov/resources-tools/resources/kev-catalog), dan [CVE JSON Record Format](https://cveproject.github.io/cve-schema/schema/docs/).
