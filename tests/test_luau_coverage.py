"""Frontend coverage tests for Luau syntax and Lua 5.1 correctness fixes.

The obfuscated output is always Lua 5.1-compatible, so Luau-only sources are
compiled for the ``luau`` target and the *output* is executed on the available
Lua runtime.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from vault import VaultError  # noqa: E402
from vault.compiler.pipeline import obfuscate  # noqa: E402


def _run(lua_interp, text: str):
    # Windows caps the command line (~32k); strong builds dwarf that, so long
    # payloads go through a temp file instead of -e argv.
    if len(text) > 30000:
        fd, path = tempfile.mkstemp(suffix=".lua", prefix="vault_coverage_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(text)
            if lua_interp.endswith((".py", ".pyw")):
                cmd = [sys.executable, lua_interp, path]
            else:
                cmd = [lua_interp, path]
            return subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        finally:
            os.unlink(path)
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


# ---------------------------------------------------------------------------
# Luau semantic extensions (interpolation, if-exprs, const, floor division,
# generalized iteration).  Everything compiles to 5.1-compatible output, so
# behaviour is verified by running the obfuscated program.
# ---------------------------------------------------------------------------

def test_interp_basic(lua_interp):
    src = (
        "local x, y = 3, 'woo'\n"
        "print(`v={x} y={y} f={x + 2}`)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="v=3 y=woo f=5\n")


def test_interp_tostring_numeric_dot(lua_interp):
    _build_run(
        lua_interp,
        "local n = 1.25\nprint(`n={n}`)\n",
        target="luau",
        expected="n=1.25\n",
    )


def test_interp_truncates_multiple_values(lua_interp):
    src = (
        "local function two() return 42, 'x' end\n"
        "print(`{two()}`)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="42\n")


def test_interp_expression_depth_all_levels(lua_interp):
    src = "local t = {a = 3}\nprint(`deep={t.a * 2}`)\n"
    _build_run(lua_interp, src, target="luau", expected="deep=6\n")


def test_interp_escape_backtick_and_brace(lua_interp):
    _build_run(lua_interp, "print(`x\\`y \\{z\\}`)" + "\n", target="luau", expected="x`y {z}\n")


def test_interp_unescaped_double_brace_rejected():
    with pytest.raises(VaultError):
        obfuscate("print(`a{{b}`)", seed=1, target="luau", preset="low")


def test_const_lowers_to_local(lua_interp):
    src = (
        "const greeting = 'hi'\n"
        "const function add(a, b) return a + b end\n"
        "print(greeting, add(2, 3))\n"
    )
    _build_run(lua_interp, src, target="luau", expected="hi\t5\n")


def test_ifexpr_basic(lua_interp):
    src = (
        "local r = if 3 > 2 then 'yes' else 'no'\n"
        "print(r)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="yes\n")


def test_ifexpr_elseif_chain(lua_interp):
    src = (
        "local n = 5\n"
        "local r = if n == 1 then 'one' elseif n == 5 then 'five' else 'other'\n"
        "print(r)\n"
        "local q = if n == 9 then 'nine' elseif n == 8 then 'eight' else 'fallback'\n"
        "print(q)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="five\nfallback\n")


def test_ifexpr_single_value_nesting(lua_interp):
    src = (
        "local function pair() return 7, 8 end\n"
        "local r = if true then pair() else nil\n"
        "print(r)\n"
        "local s = if false then 'a' else if false then 'b' else 'c'\n"
        "print(s)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="7\nc\n")


def test_ifexpr_used_in_expression(lua_interp):
    src = (
        "local n = 4\n"
        "print((if n % 2 == 0 then 'even' else 'odd') .. '!')\n"
    )
    _build_run(lua_interp, src, target="luau", expected="even!\n")


def test_floor_division_and_compound(lua_interp):
    src = (
        "local a = 7 // 2\n"
        "local b = -7 // 2\n"
        "local c = 10\n"
        "c //= 3\n"
        "print(a, b, c)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="3\t-4\t3\n")


def test_unicode_escape(lua_interp):
    _build_run(
        lua_interp,
        r"print('\u{48}\u{65}\u{79}')" + "\n",
        target="luau",
        expected="Hey\n",
    )


def test_zero_escape(lua_interp):
    src = "local s = 'a\\z\n" "   b'\n" "print(s)\n"
    _build_run(lua_interp, src, target="luau", expected="ab\n")


def test_generic_for_over_table(lua_interp):
    src = (
        "local t = {10, 20, 30}\n"
        "local s = 0\n"
        "for _, v in t do\n"
        "  s = s + v\n"
        "end\n"
        "print(s)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="60\n")


def test_generic_for_over_table_string_keys(lua_interp):
    src = (
        "local t = {a = 1, b = 2, c = 3}\n"
        "local vs = 0\n"
        "for k, v in t do\n"
        "  vs = vs + v\n"
        "  assert(k == 'a' or k == 'b' or k == 'c')\n"
        "end\n"
        "print(vs)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="6\n")


def test_generic_for_over_string(lua_interp):
    src = (
        "local out = ''\n"
        "for ch in 'hey' do\n"
        "  out = out .. ch .. '-'\n"
        "end\n"
        "print(out)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="h-e-y-\n")


def test_generic_for_over_empty_string(lua_interp):
    src = (
        "local n = 0\n"
        "for ch in '' do\n"
        "  n = n + 1\n"
        "end\n"
        "print(n)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="0\n")


def test_generic_for_multiple_string_loops(lua_interp):
    src = (
        "local function count(s)\n"
        "  local n = 0\n"
        "  for ch in s do n = n + 1 end\n"
        "  return n\n"
        "end\n"
        "print(count('abcd'), count('x'))\n"
    )
    _build_run(lua_interp, src, target="luau", expected="4\t1\n")


def test_generic_for_expression_result(lua_interp):
    src = (
        "local smell = ''\n"
        "for c in string.gsub('lua', 'u', 'OO') do\n"
        "  smell = smell .. c\n"
        "end\n"
        "print(smell)\n"
    )
    _build_run(lua_interp, src, target="luau", expected="lOOa\n")


def test_luau_only_syntax_rejected_on_lua51_2025():
    rejects = [
        ("local r = if true then 1 else 2\n", "if"),
        ("const x = 3\n", "const"),
        ("print(9 // 2)\n", "floor"),
    ]
    for src, frag in rejects:
        try:
            obfuscate(src, seed=1, target="lua51", preset="low")
        except VaultError as exc:
            assert frag in str(exc).lower(), str(exc)
        else:
            raise AssertionError(f"expected rejection for: {src!r}")


FEATURE_SRC = (
    "const base = 4\n"
    "local s = `v={base} n={base * 2}`\n"
    "local r = if base > 3 then 'hi' elseif base == 3 then 'mid' else 'lo'\n"
    "local acc = 0\n"
    "for ch in 'ab' do acc = acc + 1 end\n"
    "for _, v in {7, 8} do acc = acc + v end\n"
    "local q = 17\n"
    "q //= 3\n"
    "acc = acc + q\n"
    "print(s, r, acc)\n"
)
FEATURE_EXPECT = "v=4 n=8\thi\t22\n"


@pytest.mark.parametrize("preset", ["low", "medium", "strong"])
def test_luau_features_run_in_all_presets(lua_interp, preset):
    if lua_interp is None:
        pytest.skip("no Lua interpreter available")
    out = obfuscate(FEATURE_SRC, seed=31337, target="luau", preset=preset, verify=True).output
    proc = _run(lua_interp, out)
    assert proc.returncode == 0, proc.stderr[:300]
    assert proc.stdout == FEATURE_EXPECT, (proc.stdout, FEATURE_EXPECT)


def test_luau_features_deterministic():
    src = (
        "const x = 3\n"
        "local s = `interp {x}`\n"
        "local r = if x > 2 then 'big' else 'smol'\n"
        "for c in 'ab' do print(c) end\n"
        "print(s, r, 10 // 3)\n"
    )
    a = obfuscate(src, seed=99, target="luau", preset="strong", verify=True).output
    b = obfuscate(src, seed=99, target="luau", preset="strong", verify=True).output
    assert a == b
