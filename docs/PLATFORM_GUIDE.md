# Panduan Platform Red Team Hunting

## Prinsip penggunaan

Red Team Hunting adalah CLI untuk security research yang berizin. Sebelum melakukan pemeriksaan, operator harus memastikan domain, URL, IP, CIDR, aplikasi, atau file berada dalam scope dan memiliki otorisasi tertulis. Profile yang lebih agresif hanya memperluas discovery secara bounded; profile tersebut tidak mengizinkan penghancuran data, credential abuse, persistence, malware deployment, atau denial-of-service.

## Termux

Instal Termux dari sumber resmi, lalu jalankan:

```bash
pkg update -y && pkg upgrade -y
pkg install -y git python openssl curl

git clone https://github.com/kholqin/red-team-hunting.git
cd red-team-hunting
chmod +x install-termux.sh
./install-termux.sh
. .venv/bin/activate
python redhunt.py doctor
python redhunt.py
```

Tanpa subcommand, CLI langsung membuka menu utama 120 fitur. Gunakan `0` atau `q` untuk keluar. Jika terminal tidak merender warna/clear-screen, gunakan `REDHUNT_NO_CLEAR=1`.

## Kali Linux

```bash
sudo apt update
sudo apt install -y git python3 python3-venv python3-pip openssl curl nmap

git clone https://github.com/kholqin/red-team-hunting.git
cd red-team-hunting
chmod +x install.sh
./install.sh
. .venv/bin/activate
python3 redhunt.py doctor
python3 redhunt.py
```

Tool eksternal seperti Nuclei, FFUF, Subfinder, Amass, Gobuster, JADX, Apktool, dan Radare2 bersifat opsional. Doctor memeriksa executable aktual dan tidak menganggap dependency tersedia hanya karena tercantum di katalog.

## macOS

```bash
xcode-select --install
brew install git python openssl curl nmap

git clone https://github.com/kholqin/red-team-hunting.git
cd red-team-hunting
chmod +x install.sh
./install.sh
. .venv/bin/activate
python3 redhunt.py doctor
python3 redhunt.py
```

Jika Homebrew belum tersedia, pasang Homebrew dari situs resminya terlebih dahulu. Python virtual environment digunakan agar dependency proyek tidak mengubah instalasi Python sistem.

## Scope dan target

Buat scope secara eksplisit sebelum active testing:

```bash
cat > scope.json <<'JSON'
{"allowed":["example.com","*.owned.example.net"],"excluded":["admin.example.com"]}
JSON
```

Perintah individual:

```bash
python3 redhunt.py recon https://example.com --profile safe --output json --out recon.json
python3 redhunt.py bugbounty https://example.com --profile standard --output json --out bounty.json
python3 redhunt.py osint example.com --profile passive --output json --out osint.json
python3 redhunt.py full https://example.com --profile deep --output html --out report.html
python3 redhunt.py feature BB-18 --input https://example.com --output json
python3 redhunt.py feature RE-02 --path ./sample.bin --output json
```

## Parallel runner

Runner paralel membutuhkan file target dan scope. Concurrency dibatasi agar tidak membanjiri target:

```bash
python3 scripts/parallel_scan.py \
  --targets targets.txt \
  --scope scope.json \
  --workers 2 \
  --module-timeout 180 \
  --output-dir reports/parallel
```

## Local lab

Gunakan fixture lokal untuk acceptance test tanpa target internet:

```bash
python3 lab/fixture_server.py
```

Pada terminal kedua:

```bash
python3 redhunt.py bugbounty http://127.0.0.1:18080 --output json --out lab-bugbounty.json
python3 redhunt.py osint http://127.0.0.1:18080 --output json --out lab-osint.json
```

## Output dan status

Output JSON/HTML/Markdown menyimpan evidence, timestamp, module, status response, dan confidence bila dapat dihitung. `DETECTED` berarti indikator ditemukan dari evidence aktual; `NOT DETECTED` berarti pemeriksaan selesai tanpa indikator; `SKIPPED` berarti dependency/policy tidak mengizinkan pemeriksaan; `NOT TESTED` berarti input khusus belum diberikan; dan `INCONCLUSIVE` berarti evidence belum cukup. Tidak satu pun status tersebut boleh ditafsirkan sebagai jaminan keamanan total.

## Troubleshooting

Gunakan `python3 redhunt.py doctor` untuk memeriksa runtime. Bila command `redhunt` tidak dikenal, gunakan `python3 redhunt.py` dari root repository atau aktifkan virtual environment. Bila dependency opsional tidak tersedia, gunakan fallback internal yang tersedia dan dokumentasikan status `SKIPPED` pada laporan.
