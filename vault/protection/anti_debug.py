"""Anti-debugging probes.

Generates the ``@@ADB@@`` fragment evaluated at load time.  A debugger hook
installed by instrumentation (``debug.gethook`` returning a function) is
treated as hostile.  Enabled presets abort through the build's security
failure path; when ``controlled_failures`` is off the classic opaque message
is used instead.

While the program runs, ``unexpected_hook_detection`` (see
:mod:`vault.protection.anti_tamper`) re-probes for a hook installed after
load.
"""

from __future__ import annotations

from typing import Any, Dict

from vault.protection.fail import failure_body


def build_anti_debug(name_map: Dict[str, str], preset_config) -> str:
    n = dict(name_map)
    if not preset_config.get("anti_debug", False):
        return "-- anti-debug disabled (preset=%s)" % preset_config.get("name", "low")
    pc = n["PC"]
    env = n["ENV"]
    ty = n["TY"]
    body = failure_body(n, preset_config)
    frag = [
        "do",
        f"local fp={pc}(function()",
        f"  local f0={env}.getfenv",
        "  if f0 then",
        f"    local e0,f1={pc}(f0,0)",
        "    if e0 then",
        "      local d0=f1 and f1.debug",
        "      if d0 and d0.gethook then",
        f"        local h0={pc}(d0.gethook)",
        f"        if h0 and h0~=false and {ty}(h0)=='function' then",
        f"          {body}",
        "        end",
        "      end",
        "    end",
        "  end",
        "end)",
        "end",
    ]
    return "\n".join(frag)