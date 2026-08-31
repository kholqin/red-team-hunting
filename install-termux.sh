#!/data/data/com.termux/files/usr/bin/sh
set -eu

printf '%s\n' '[1/4] Memperbarui repositori Termux'
pkg update -y

printf '%s\n' '[2/4] Memasang dependency dasar dan yang tersedia di repositori'
pkg install -y git python openssl curl nmap || true

# Tool tambahan hanya dipasang bila tersedia pada channel Termux aktif.
# Kegagalan paket opsional tidak diubah menjadi sukses palsu.
printf '%s\n' '[3/4] Mencoba paket opsional Termux'
for package in ffuf radare2 golang; do
  if pkg install -y "$package"; then
    printf '%s\n' "[OK] $package terpasang"
  else
    printf '%s\n' "[SKIPPED] $package tidak tersedia pada repositori aktif"
  fi
done

printf '%s\n' '[4/4] Membuat virtualenv dan memasang redhunt'
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .

cat <<'EOF'
Instalasi Termux selesai.
Gunakan: . .venv/bin/activate && python redhunt.py doctor
Tool eksternal yang tidak tersedia pada repositori Termux tetap dilaporkan sebagai OPSIONAL TIDAK TERSEDIA.
Jangan menjalankan scanner pada target tanpa izin tertulis.
EOF
