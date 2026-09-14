"""Anti-debugging probes.

Generates the ``@@ADB@@`` fragment evaluated at load time.  A debugger hook
installed by instrumentation (``debug.gethook`` returning a function) is
treated as hostile and aborts execution with an opaque error.
"""

from __future__ import annotations

from typing import Any, Dict


def build_anti_debug(name_map: Dict[str, str], preset_config) -> str:
    n = dict(name_map)
    if not preset_config.get("anti_debug", False):
        return "-- anti-debug disabled (preset=%s)" % preset_config.get("name", "low")
    pc = n["PC"]
    env = n["ENV"]
    ty = n["TY"]
    er = n["ER"]
    emt = n["EMT"]
    frag = [
        "do",
        f"local fp={pc}(function()",
        f"local f0={env}.getfenv",
        "if f0 then",
        f"local e0,f1={pc}(f0,0)",
        "if e0 then",
        "local d0=f1 and f1.debug",
        "if d0 and d0.gethook then",
        f"local h0={pc}(d0.gethook)",
        "if h0 then return h0 end",
        "end",
        "end",
        "end",
        "end)",
        f"if fp and fp~=false and {ty}(fp)=='function' then",
        f"{er}({emt}[11])",
        "end",
        "end",
    ]
    return "\n".join(frag)