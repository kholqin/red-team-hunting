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
