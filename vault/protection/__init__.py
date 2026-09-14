"""Protection plugins: integrity, anti-debugging and watchdog guards."""

from vault.protection.anti_debug import build_anti_debug
from vault.protection.anti_tamper import build_watchdog
from vault.protection.integrity import build_load_checks

__all__ = ["build_anti_debug", "build_watchdog", "build_load_checks"]