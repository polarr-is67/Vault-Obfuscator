#!/usr/bin/env sh
# Vault-Obf installer for POSIX shells (Linux/macOS/WSL).
#
# Sets up a virtual environment, installs the package in editable mode with
# the optional 'web' extras, and prints a usage summary.
set -eu

cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "error: Python 3 executable '$PYTHON' not found" >&2
    exit 1
fi

VENV_DIR="${VENV_DIR:-.venv}"

echo "==> creating virtualenv at $VENV_DIR"
"$PYTHON" -m venv "$VENV_DIR"

if [ -d "$VENV_DIR/Scripts" ]; then
    PIP="$VENV_DIR/Scripts/python"
else
    PIP="$VENV_DIR/bin/python"
fi

echo "==> installing vault-obf (editable, with web extras)"
"$PIP" -m pip install --upgrade pip
"$PIP" -m pip install -e ".[web]"

echo
echo "installed. quick start:"
echo
echo "  Vault-Obf CLI:"
echo "    $VENV_DIR/bin/vault-obf examples/smoke.lua -o out.lua -p medium --verify --stats"
echo
echo "  Web service - GUI at http://127.0.0.1:8000 :"
echo "    $VENV_DIR/bin/python -m web --port 8000"
echo
echo "  Tests:"
echo "    $VENV_DIR/bin/python -m pytest tests -q"
echo
echo "Optionally set the VAULT_LUA env var to a lua5.1 compatible binary"
echo "to unlock --check-lua verification of the emitted scripts."