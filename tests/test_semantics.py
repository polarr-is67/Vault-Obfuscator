"""End-to-end semantic tests: the VM output must behave like the input.

These tests skip cleanly when no Lua interpreter is available (set
``VAULT_LUA`` or install one of: lua5.1/lua53/lua54).
"""

from __future__ import annotations

import pytest

from conftest import PRESETS, SEMANTIC_PROGRAMS

_PROGRAM_IDS = list(SEMANTIC_PROGRAMS)


@pytest.mark.parametrize("name", _PROGRAM_IDS, ids=_PROGRAM_IDS)
def test_program_matches_reference(name, lua_interp, assert_matches_reference):
    if lua_interp is None:
        pytest.skip("no Lua interpreter available (set VAULT_LUA or install lua)")
    assert_matches_reference(SEMANTIC_PROGRAMS[name], lua_interp)


@pytest.mark.parametrize("preset", PRESETS)
def test_interp_presets_run(lua_interp, run_lua, build, preset):
    """Each preset produces a runnable program with correct output."""
    if lua_interp is None:
        pytest.skip("no Lua interpreter available (set VAULT_LUA or install lua)")
    src = "local function f(n) return n * 2 end\nprint(f(6))\n"
    out = build(src, preset=preset, seed=11, verify=True)
    proc = run_lua(lua_interp, out)
    assert proc.returncode == 0, proc.stderr[:400]
    assert proc.stdout == "12\n"