"""Protection plugins: integrity, anti-debugging and watchdog guards."""

from vault.protection.anti_debug import build_anti_debug
from vault.protection.anti_tamper import build_watchdog, build_watchdog_head
from vault.protection.env import build_env_sanity
from vault.protection.integrity import build_load_checks
from vault.protection.selfcheck import build_self_check, self_source_hash
from vault.protection.state import build_state_validation

__all__ = [
    "build_anti_debug",
    "build_watchdog",
    "build_watchdog_head",
    "build_env_sanity",
    "build_load_checks",
    "build_self_check",
    "self_source_hash",
    "build_state_validation",
]