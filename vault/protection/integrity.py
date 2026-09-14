"""Load-time integrity verification.

Generates the ``@@CKL@@`` fragment: one ``VERONE`` call per region that must
be verified at load time, immediately halting with an opaque error when a
byte of the produced payload differs from the expected checksum.
"""

from __future__ import annotations

from typing import Any, Dict


def build_load_checks(name_map: Dict[str, str], preset_config) -> str:
    n = dict(name_map)
    nregions = int(preset_config.get("load_verify_regions", 3))
    lines = ["do", f"local V={n['VERONE']}", f"local QX={n['Q']}"]
    # `VERONE` reference used via `V`/`QX` to keep the calls terse.
    # (loops avoided inside the fragment; regions are few and build-known)
    for r in range(nregions):
        lines.append(f"V({r},QX)")
    lines.append("end")
    return "\n".join(lines)