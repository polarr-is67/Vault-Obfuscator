"""Runtime watchdog: periodic integrity re-checks inside the interpreter.

Generates two fragments:

* ``@@WKHEAD@@`` -- the ``@@WK@@`` preamble placed inside ``@RUN@`` before the
  dispatch loop.  It defines the build-time helper functions referenced by the
  in-loop check (bytecode re-checksum function, unexpected debug-hook probe)
  once, so the loop itself only pays the cost of a call.
* ``@@WK@@`` -- the in-loop body.  Every ``watchdog_threshold`` dispatches a
  derived region is re-verified; region selection advances deterministically
  so different regions are visited as the program runs.  A single corrupted
  byte fails the first re-check that touches the affected region.

When the ``bytecode_integrity`` option is enabled the watchdog also
re-hashes a proto's decoded instruction stream against its stored checksum
(so edits made *after* the payload has been decoded are caught), and when
``unexpected_hook_detection`` is enabled it re-probes ``debug.gethook`` for a
hook installed while the program was already running.
"""

from __future__ import annotations

from typing import Any, Dict

from vault.protection.fail import failure_body


def build_watchdog_head(name_map: Dict[str, str], preset_config, meta=None) -> str:
    """Build the ``@@WKHEAD@@`` helper preamble for the watchdog."""
    n = dict(name_map)
    parts: list = []
    meta = meta or {}

    if preset_config.get("bytecode_integrity", False):
        xmul = int(meta.get("xsum_mul", 3))
        xadd = int(meta.get("xsum_add", 1))
        body = failure_body(n, preset_config)
        # NOTE: no `do ... end` wrapper here.  The watchdog body (`@@WK@@`)
        # calls this function later in the same `@RUN@` scope, so it must be
        # a directly visible local, not a block-scoped one.
        parts.append(
            f"local function {n['BXC']}(cd2,xs)\n"
            f"  local c=0\n"
            f"  for i2=1,#cd2 do c=(c*{xmul}+cd2[i2]+{xadd})%{n['MN']} end\n"
            f"  if c~=xs then {body} end\n"
            "end"
        )

    if preset_config.get("unexpected_hook_detection", False):
        body = failure_body(n, preset_config)
        parts.append(
            f"local function {n['HOOK']}()\n"
            f"  local dbx={n['ENV']}.debug\n"
            "  if dbx and dbx.gethook then\n"
            f"    local a1,b1={n['PC']}(dbx.gethook)\n"
            f"    if a1 and {n['TY']}(b1)=='function' then {body} end\n"
            "  end\n"
            "end"
        )

    if not parts:
        return "-- watchdog helpers disabled"
    return "\n".join(parts)


def build_watchdog(name_map: Dict[str, str], preset_config, meta=None) -> str:
    """Build the ``@@WK@@`` in-loop watchdog body."""
    n = dict(name_map)
    nregions = int(preset_config.get("integrity_regions", 3))
    if not preset_config.get("watchdog", False):
        return f"-- watchdog disabled (preset={preset_config.get('name', 'low')})"
    thr = int(preset_config.get("watchdog_threshold", 0))
    step = int(preset_config.get("watchdog_step", 2))
    if thr <= 0:
        return "-- watchdog threshold disabled"

    lines = [
        f"{n['WDOG']}={n['WDOG']}+1",
        f"if {n['WDOG']}>={thr} then",
        f"  {n['WDOG']}=0",
        f"  {n['WDOGN']}={n['WDOGN']}+1",
        f"  {n['VERONE']}(({n['WDOGN']}*{step})%{nregions},{n['Q']})",
    ]
    if preset_config.get("unexpected_hook_detection", False):
        lines.append(f"  if {n['WDOGN']}%2==0 then {n['HOOK']}() end")
    if preset_config.get("bytecode_integrity", False):
        # `pr` and `cd` are the dispatch-loop locals in scope at @@WK@@.
        lines.append(f"  if {n['WDOGN']}%3==0 then {n['BXC']}(cd,pr.xs or 0) end")
    lines.append("end")
    return "\n".join(lines)