"""Optional VM-state validation.

Generates the ``@@SV@@`` in-loop fragment.  When enabled it maintains a
build-known sample counter and, on every Nth dispatch, checks structural
invariants of the running interpreter:

* the instruction pointer stays within the decoded instruction stream of the
  current prototype,
* the frame stack still addresses the frame the dispatch loop is executing.

Corruption of either invariant aborts execution through the build's security
failure path.  The whole fragment is optional and disabled by default so
presets that do not ask for it pay nothing.
"""

from __future__ import annotations

from typing import Any, Dict

from vault.protection.fail import failure_body


def build_state_validation(name_map: Dict[str, str], preset_config, meta=None) -> str:
    """Build the ``@@SV@@`` state-validation fragment (''disabled'' default)."""
    n = dict(name_map)
    if not preset_config.get("vm_state_validation", False):
        return f"-- vm state validation disabled (preset={preset_config.get('name', 'low')})"
    meta = meta or {}
    thr = max(16, int(meta.get("sv_threshold", 200)))
    body = failure_body(n, preset_config)
    return (
        f"{n['SVC']}={n['SVC']}+1\n"
        f"if {n['SVC']}>={thr} then\n"
        f"  {n['SVC']}=0\n"
        f"  if I[{n['KI']}]<1 or I[{n['KI']}]>#cd then {body} end\n"
        f"  if #cd~=pr.nb then {body} end\n"
        f"  if pr.params<0 or pr.maxstack<1 then {body} end\n"
        f"  if sk[#sk]~=I then {body} end\n"
        "end"
    )