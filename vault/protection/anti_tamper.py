"""Runtime watchdog: periodic integrity re-checks inside the interpreter.

Generates the ``@@WK@@`` fragment placed inside the main dispatch loop.  Every
``watchdog_threshold`` dispatches a derived region is re-verified; region
selection advances deterministically so different regions are visited as the
program runs.  A single corrupted byte fails the first re-check that touches
the affected region.
"""

from __future__ import annotations

from typing import Any, Dict


def build_watchdog(name_map: Dict[str, str], preset_config) -> str:
    n = dict(name_map)
    nregions = int(preset_config.get("integrity_regions", 3))
    if not preset_config.get("watchdog", False):
        return f"-- watchdog disabled (preset={preset_config.get('name', 'low')})"
    thr = int(preset_config.get("watchdog_threshold", 0))
    step = int(preset_config.get("watchdog_step", 2))
    if thr <= 0:
        return "-- watchdog threshold disabled"
    return (
        f"{n['WDOG']}={n['WDOG']}+1\n"
        f"if {n['WDOG']}>={thr} then\n"
        f"  {n['WDOG']}=0\n"
        f"  {n['WDOGN']}={n['WDOGN']}+1\n"
        f"  {n['VERONE']}(({n['WDOGN']}*{step})%{nregions},{n['Q']})\n"
        f"end"
    )