#!/usr/bin/env sh
set -eu
PYTHON="${PYTHON:-python3}"
"$PYTHON" -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e .
printf '%s\n' 'Instalasi selesai. Aktifkan dengan: . .venv/bin/activate'
