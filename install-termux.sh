#!/data/data/com.termux/files/usr/bin/sh
set -eu
pkg install -y python || true
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
printf '%s\n' 'Instalasi Termux selesai; tidak memerlukan root.'
