"""Frontend coverage tests for Luau syntax and Lua 5.1 correctness fixes.

The obfuscated output is always Lua 5.1-compatible, so Luau-only sources are
compiled for the ``luau`` target and the *output* is executed on the available
Lua runtime.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from vault import VaultError  # noqa: E402
from vault.compiler.pipeline import obfuscate  # noqa: E402


def _run(lua_interp, text: str):
    if lua_interp.endswith((".py", ".pyw")):
        cmd = [sys.executable, lua_interp, "-e", text]
    else:
        cmd = [lua_interp, "-e", text]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=60)


def _build_run(lua_interp, src: str, *, target: str, expected: str):
    if lua_interp is None:
        pytest.skip("no Lua interpreter available")
    out = obfuscate(src, seed=13, target=target, preset="low", verify=True).output
    proc = _run(lua_interp, out)
    assert proc.returncode == 0, proc.stderr[:300]
    assert proc.stdout == expected, (proc.stdout, expected)


def test_continue_in_numeric_for(lua_interp):
    src = (
        "local s = 0\n"
        "for i = 1, 10 do\n"
        "  if i % 2 == 0 then continue end\n"
        "  s = s + i\n"
        "end\n"
        "print(s)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="25\n")


def test_continue_in_while(lua_interp):
    src = (
        "local i, s = 0, 0\n"
        "while i < 10 do\n"
        "  i = i + 1\n"
        "  if i % 2 == 0 then continue end\n"
        "  s = s + i\n"
        "end\n"
        "print(s)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="25\n")


def test_continue_in_repeat(lua_interp):
    src = (
        "local i, s = 0, 0\n"
        "repeat\n"
        "  i = i + 1\n"
        "  if i % 2 == 0 then continue end\n"
        "  s = s + i\n"
        "until i >= 10\n"
        "print(s)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="25\n")


def test_continue_in_generic_for(lua_interp):
    src = (
        "local s = 0\n"
        "for _, v in ipairs({1, 2, 3, 4}) do\n"
        "  if v == 3 then continue end\n"
        "  s = s + v\n"
        "end\n"
        "print(s)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="7\n")


def test_concat_compound_assignment(lua_interp):
    src = "local s = 'a'\ns ..= 'b'\ns ..= 3\nprint(s)\n"
    _build_run(lua_interp, src, target="luau", expected="ab3\n")


def test_not_equal_alias(lua_interp):
    src = "print(1 ~= 2, 1 != 2, 2 != 2)\n"
    _build_run(lua_interp, src, target="luau", expected="true\ttrue\tfalse\n")


def test_lua51_parentheses_truncate_multi_values(lua_interp):
    src = (
        "local function two() return 1, 2 end\n"
        "local a, b = (two())\n"
        "print(a, b)\n"
    )
    _build_run(lua_interp, src, target="lua51", expected="1\tnil\n")


def test_lua51_hex_literal_at_eof_is_not_a_crash(lua_interp):
    _build_run(lua_interp, "print(0x1F)\n", target="lua51", expected="31\n")


@pytest.mark.parametrize(
    "src",
    [
        "local x: number = 1\nprint(x)\n",
        "local f: (number) -> number = function(a) return a end\nprint(f(4))\n",
        "local function g(a: number, b: string): number return a end\nprint(g(7, 'z'))\n",
        "local function h(...: number) return select('#', ...) end\nprint(h(1, 2, 3))\n",
        "local y: {[string]: number} = {}\ny.a = 2\nprint(y.a)\n",
        "local z: number? = nil\nprint(z)\n",
        "local u: string | number = 3\nprint(u)\n",
    ],
)
def test_luau_type_annotations_compile(src):
    out = obfuscate(src, seed=1, target="luau", preset="low", verify=True).output
    assert out


@pytest.mark.parametrize(
    "src",
    [
        "local x: number = 1\n",
        "local s = 'a'\ns ..= 'b'\n",
        "print(1 != 2)\n",
    ],
)
def test_luau_only_syntax_rejected_on_lua51(src):
    with pytest.raises(VaultError):
        obfuscate(src, seed=1, target="lua51", preset="low", verify=True)
