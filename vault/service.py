"""Windows service hosting the Vault-Obf web API.

Requires the optional ``vault-obf[service]`` extra (``pywin32``).  The
service runs the FastAPI app with uvicorn on the loopback interface and is
managed from the main CLI with ``vault-obf service <command>``, which
delegates to this module:

    python -m vault.service install|start|stop|remove|restart|debug

Host/port may be overridden with ``var/service.json`` (gitignored) or the
``VAULT_API_HOST``/``VAULT_API_PORT`` environment variables.  Without
pywin32 the module still starts the API in the foreground, which is useful
for debugging.
"""

from __future__ import annotations

import json
import os
import threading
import time

try:
    import win32serviceutil as _win32serviceutil

    _ServiceFramework = _win32serviceutil.ServiceFramework
    _HAS_PYWIN32 = True
except ImportError:  # pragma: no cover - optional dependency
    _win32serviceutil = None
    _ServiceFramework = object
    _HAS_PYWIN32 = False

SRV_NAME = "VaultObfWeb"
SRV_DISPLAY = "Vault-Obf Web API"
SRV_DESCRIPTION = "Serves the Vault-Obf obfuscation API on the local machine."


def _repo_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _settings_path() -> str:
    return os.path.join(_repo_root(), "var", "service.json")


def load_settings() -> dict:
    """Read host/port overrides from ``var/service.json`` (if present)."""
    try:
        with open(_settings_path(), "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


def _uvicorn_config():
    """Build the uvicorn server configuration for the web API."""
    from web.app import create_app

    import uvicorn

    settings = load_settings()
    host = settings.get("host", os.environ.get("VAULT_API_HOST", "127.0.0.1"))
    port = int(settings.get("port", os.environ.get("VAULT_API_PORT", "8000")))
    return uvicorn.Config(
        create_app(),
        host=host,
        port=port,
        log_level="warning",
        access_log=False,
    )


class VaultWebService(_ServiceFramework):  # type: ignore[misc]
    """Runs the FastAPI app as a Windows service."""

    _svc_name_ = SRV_NAME
    _svc_display_name_ = SRV_DISPLAY
    _svc_description_ = SRV_DESCRIPTION

    def __init__(self, args) -> None:
        if _HAS_PYWIN32:
            _win32serviceutil.ServiceFramework.__init__(self, args)
        self._server = None

    def SvcDoRun(self) -> None:
        import win32service  # noqa: PLC0415

        import uvicorn

        server = uvicorn.Server(_uvicorn_config())
        self._server = server
        threading.Thread(target=server.run, daemon=True).start()
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        while not server.should_exit:
            time.sleep(1)
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)

    def SvcStop(self) -> None:
        import win32service  # noqa: PLC0415

        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self._server is not None:
            self._server.should_exit = True


def run_foreground() -> None:
    """Entry point for ``python -m vault.service`` when pywin32 is absent."""
    import uvicorn

    uvicorn.run(_uvicorn_config())


if __name__ == "__main__":
    if _HAS_PYWIN32:
        import sys

        _win32serviceutil.HandleCommandLine(VaultWebService, sys.argv[1:])
    else:
        run_foreground()