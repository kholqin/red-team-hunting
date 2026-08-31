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
