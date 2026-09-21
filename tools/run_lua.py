"""Run Lua source through an in-process Lua runtime.

Used by the test suite as a stand-in Lua interpreter when no real ``lua``
binary is on PATH (see ``tests/conftest.py``).  Supports the two call forms
used by the tests, mirroring ``lua``:

    python tools/run_lua.py SCRIPT.lua
    python tools/run_lua.py -e "SOURCE"

The runtime is Lua 5.5 via ``lupa``.  Lua 5.5 keeps a separate integer type and
formats integral floats as ``42.0``, whereas Lua 5.1 (and Luau, the VM's
targets) have only doubles and format them as ``42``.  The shim normalises the
stringification paths the semantic oracle relies on (``print``, ``tostring``,
``io.write`` and ``table.concat``) to the Lua 5.1 form, so dialect differences
between the reference program and the obfuscated build cancel out.
"""

from __future__ import annotations

import sys
from pathlib import Path

try:
    import lupa
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(f"run_lua.py: lupa not installed: {exc}\n")
    sys.exit(3)


def _l51_ify(v):
    """Format a Lua value the way Lua 5.1's ``print``/``tostring`` would.

    Lua 5.3+ distinguishes integers from floats and prints an integral
    float as ``42.0``; Lua 5.1 (and Luau) formats it as ``42``.  The VM
    targets those dialects, so the shim surfaces values in that form too.
    """
    if v is None:
        return "nil"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, float) and v.is_integer() and abs(v) < 2**53:
        return str(int(v))
    return str(v)


def _lua_print(*args) -> None:
    sys.stdout.write("\t".join(_l51_ify(a) for a in args) + "\n")


def _lua_write(*args) -> None:
    sys.stdout.write("".join(_l51_ify(a) for a in args))


# Lua 5.1's table.concat formats numbers with "%.14g"; Lua 5.5 prints an
# integral float as "2.0".  Re-implement concat on top of the patched
# ``tostring`` so the oracle matches Lua 5.1 output.
_CONCAT_SHIM = """
do
  local orig = table.concat
  local ts = tostring
  table.concat = function(t, sep, i, j)
    local n = #t
    local first = i or 1
    local last = j or n
    local out = {}
    for k = first, last do
      local v = t[k]
      local tv = type(v)
      if tv == 'number' then
        out[#out + 1] = ts(v)
      elseif tv == 'string' then
        out[#out + 1] = v
      else
        error("invalid value (at index " .. k .. ") in table for 'concat'", 2)
      end
    end
    return orig(out, sep or '')
  end
end
"""


def _wrap_callable(lua, pyfn) -> "object":
    """Expose a Python callable as a native Lua ``function``.

    lupa surfaces Python callables as ``userdata`` values; real VM semantics
    (and Lua 5.1) expect library functions to be ``type() == 'function'``.
    Wrapping them in a Lua closure fixes that.
    """
    wrap = lua.eval("function(py) return function(...) return py(...) end end")
    return wrap(pyfn)


def _main() -> int:
    argv = sys.argv[1:]
    if len(argv) == 2 and argv[0] == "-e":
        source = argv[1]
    elif len(argv) == 1:
        path = Path(argv[0])
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            sys.stderr.write(f"run_lua.py: {exc}\n")
            return 2
    else:
        sys.stderr.write("usage: run_lua.py SCRIPT | -e SOURCE\n")
        return 2

    lua = lupa.LuaRuntime(unpack_returned_tuples=True)
    g = lua.globals()
    g.print = _wrap_callable(lua, _lua_print)
    g.tostring = _wrap_callable(lua, lambda v: _l51_ify(v))
    io = g["io"]
    if io:
        io.write = _wrap_callable(lua, _lua_write)
    lua.execute(_CONCAT_SHIM)
    try:
        lua.execute(source)
    except lupa.LuaError as exc:
        sys.stderr.write(f"lua: {exc}\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(_main())