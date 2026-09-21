"""Best-effort self-source verification (``@@SELFCHK@@``).

When ``self_file_check`` is enabled the script hashes its own on-disk source
and compares the result to a build-embedded literal.  This catches edits made
to the emitted file *after* the build, complementing the payload integrity
checks (which catch edits to the embedded bytecode image).

The probe is strictly capability-gated: it runs only when the host exposes
``io`` and ``debug`` *and* the running chunk came from a real file.  Everywhere
else -- Roblox/Luau, ``loadstring``/``load`` of a string, stdin, ``-e`` -- it
silently does nothing.  The hash is an FNV-style multiply/add over the file
bytes, kept exact in doubles by reducing modulo ``2**31 - 1`` with a small
prime.

To make build-time and run-time hashes comparable, the emitted file carries the
hash as a prefixed literal (``VAULTx<8 hex>``); the emitter first lays down the
sentinel ``VAULTx00000000``, hashes that text, then substitutes the real hash.
At run time the probe reconstructs the sentinel text by replacing the literal
it holds back with the sentinel before hashing.
"""

from __future__ import annotations

from typing import Any, Dict

from vault.protection.fail import failure_body

#: Hash state constants, mirrored exactly by :func:`self_source_hash`.
HASH_BASIS = 2166136261
HASH_PRIME = 65599
HASH_PREFIX = "VAULTx"
HASH_SENTINEL = "VAULTx00000000"


def self_source_hash(text: str) -> str:
    """Return the 8-hex self-source digest for ``text`` (ASCII/UTF-8 bytes)."""
    mod = (1 << 31) - 1
    h = HASH_BASIS % mod
    for byte in text.encode("utf-8"):
        h = (h * HASH_PRIME + byte) % mod
    return "%08x" % h


def build_self_check(name_map: Dict[str, str], preset_config) -> str:
    """Build the ``@@SELFCHK@@`` fragment (''disabled'' when not requested)."""
    n = dict(name_map)
    if not preset_config.get("self_file_check", False):
        return "-- self-source check disabled"
    body = failure_body(n, preset_config)
    shp = n["SHP"]
    return (
        "do\n"
        f"  local {shp}=@@SELFHASH@@\n"
        f"  local _S={n['ENV']}.string\n"
        f"  local _io={n['ENV']}.io\n"
        f"  local _dbg={n['ENV']}.debug\n"
        "  if _S and _io and _io.open and _dbg and _dbg.getinfo then\n"
        # Walk a few stack levels: the direct call sees the main chunk at
        # level 1, but a guarded ``pcall(getinfo, ...)`` adds a C frame, and
        # the chunk we want is the first frame whose source names a real file.
        "    local _src\n"
        f"    for _lvl=1,4 do\n"
        f"      local _ok,_inf={n['PC']}(_dbg.getinfo,_lvl,'S')\n"
        "      local _s=_ok and _inf and _inf.source\n"
        "      if _s and _S.sub(_s,1,1)=='@' then _src=_s break end\n"
        "    end\n"
        "    if _src then\n"
        "      local _f=_io.open(_S.sub(_src,2),'rb')\n"
        "      if _f then\n"
        "        local _d=_f:read('*a')\n"
        "        _f:close()\n"
        "        if _d then\n"
        "          _d=_S.gsub(_d,'\\r\\n','\\n')\n"
        f"          _d=_S.gsub(_d,{shp},'{HASH_SENTINEL}')\n"
        f"          local _h={HASH_BASIS}%{n['MN']}\n"
        f"          for _i=1,#_d do _h=(_h*{HASH_PRIME}+_S.byte(_d,_i))%{n['MN']} end\n"
        "          if _S.format('%08x',_h)~=_S.sub("
        f"{shp},{len(HASH_PREFIX) + 1}) then {body} end\n"
        "        end\n"
        "      end\n"
        "    end\n"
        "  end\n"
        "end"
    )
