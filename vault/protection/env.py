"""Environment sanity checks.

Generates the ``@@ENVS@@`` load-time fragment.  The VM captures every
standard function it depends on from the real environment at startup; if a
sandbox stripped one of them, execution would fail later with a confusing
internal error.  This probe runs right after the payload loader and aborts
through the build's security failure path when any dependency is missing.

The probe only tests the exact functions the runtime actually uses, and is
tolerant of the Lua-5.1 vs Luau library split (``unpack`` on 5.1 vs
``table.unpack`` on 5.2+/Luau).
"""

from __future__ import annotations

from typing import Any, Dict

from vault.protection.fail import failure_body


def build_env_sanity(name_map: Dict[str, str], preset_config) -> str:
    """Build the ``@@ENVS@@`` environment-sanity fragment."""
    n = dict(name_map)
    if not preset_config.get("env_sanity", False):
        return f"-- env sanity disabled (preset={preset_config.get('name', 'low')})"
    body = failure_body(n, preset_config)
    env = n["ENV"]
    return (
        "do\n"
        f"local e0={env}\n"
        "local ok0=true\n"
        "if not (e0.type and e0.tostring and e0.select and e0.error and "
        "e0.setmetatable and e0.getmetatable and e0.rawget and e0.rawset and "
        "e0.pcall) then ok0=false end\n"
        "if not (e0.unpack or (e0.table and e0.table.unpack)) then ok0=false end\n"
        "if not (e0.string and e0.string.char and e0.math and e0.math.floor) "
        "then ok0=false end\n"
        f"if not ok0 then {body} end\n"
        "end"
    )