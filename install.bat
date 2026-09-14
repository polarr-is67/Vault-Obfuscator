@echo off
rem Vault-Obf installer for Windows.
rem Creates a virtual environment, installs the package (editable, with the
rem optional 'web' extras) and prints a short usage summary.
setlocal
cd /d "%~dp0"

set "PYTHON=python"
where python >nul 2>nul
if errorlevel 1 (
    echo error: 'python' was not found on PATH. Install Python 3.10+ first.
    exit /b 1
)

set "VENV_DIR=.venv"
echo ==^> creating virtualenv at %VENV_DIR%
"%PYTHON%" -m venv "%VENV_DIR%"
if errorlevel 1 exit /b 1

set "PY=%VENV_DIR%\Scripts\python.exe"

echo ==^> installing vault-obf (editable, with web extras)
"%PY%" -m pip install --upgrade pip
"%PY%" -m pip install -e ".[web]"

echo.
echo installed. quick start:
echo.
echo   CLI: %VENV_DIR%\Scripts\vault-obf examples\smoke.lua -o out.lua -p medium --verify --stats
echo   Web service: %VENV_DIR%\Scripts\python -m web --port 8000
echo   Tests:       %VENV_DIR%\Scripts\python -m pytest tests -q
echo.
echo Optionally set the VAULT_LUA env var to a Lua 5.1 compatible binary
echo to unlock --check-lua verification of the emitted scripts.
endlocal