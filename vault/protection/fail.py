"""Shared security-failure body generation.

Every security abort (integrity, version mismatch, debug-hook detection,
environment or state corruption) ends in one of two forms chosen at build
time:

* ``controlled_failures`` -- raise the build-specific sentinel via ``@KILL@``;
  the outer invocation wrapper maps it to a single clean opaque error.
* otherwise -- raise the load-time integrity message directly (the classic
  behaviour, kept for presets that leave controlled failures off).
"""

from __future__ import annotations

from typing import Any, Dict


def failure_body(name_map: Dict[str, str], preset_config) -> str:
    """Return the Lua source that aborts execution on a security failure."""
    n = dict(name_map)
    if preset_config.get("controlled_failures", False):
        return f"{n['KILL']}()"
    return f"{n['ER']}(({n['EMT']}[1] or 'integrity check failed'))"