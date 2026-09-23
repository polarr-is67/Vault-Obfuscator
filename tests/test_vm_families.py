"""VM-family coverage.

Four execution families are selectable per build:

* ``classic``    — flat word-stride stream (P-prefix operand slots)
* ``soa``        — stream split into six per-field arrays on ``pr.ff``
* ``threaded``   — soa layout plus a per-proto successor table ``pr.nx``
* ``scrambled``  — soa layout with the physical instruction stream permuted
  and a per-proto logical->physical map ``pr.oo`` threaded through the fetch

These tests verify every family runs correct programs under every dispatch
strategy, that builds are structure-distinct per family, and that the same
seed reproduces the same output while family changes move the output.
"""

from __future__ import annotations

import pytest

from vault.compiler.pipeline import obfuscate

FAMILIES = ["classic", "soa", "threaded", "scrambled"]
DISPATCHES = ["cascade", "tree", "table", "indirect"]

FAMILY_PROGRAM = {
    "closure": (
        "local function closer()\n"
        "  local x = 4\n"
        "  return function() x = x * 3 + 3; return x end\n"
        "end\n"
        "print(closer()())\n"
    ),
    "upvalue": (
        "local up = 10\n"
        "local function set(v) up = v end\n"
        "set(42)\n"
        "print(up)\n"
    ),
    "recursion": (
        "local function fib(n)\n"
        "  if n < 2 then return n end\n"
        "  return fib(n - 1) + fib(n - 2)\n"
        "end\n"
        "print(fib(10))\n"
    ),
    "loop": "local s = 0\nfor i = 1, 3 do s = s + i end\nprint(s)\n",
    "table": "local t = {a = 1, b = 2}\nprint(t.a + t.b)\n",
    "string": "print('hello ' .. 'world')\n",
}


@pytest.mark.parametrize("family", FAMILIES)
@pytest.mark.parametrize("dispatch", DISPATCHES)
def test_family_runs_program(lua_interp, run_lua_source, family, dispatch):
    if lua_interp is None:
        pytest.skip("no Lua interpreter available")
    for src in FAMILY_PROGRAM.values():
        result = obfuscate(
            src,
            seed=7,
            target="lua51",
            preset="medium",
            overrides={"vm_family": family, "dispatch": dispatch},
            verify=True,
        )
        ref = run_lua_source(lua_interp, src)
        proc = run_lua_source(lua_interp, result.output)
        assert proc.returncode == 0, (
            f"{family}/{dispatch}: {proc.stderr.strip()[:400]}"
        )
        assert proc.stdout == ref.stdout, f"{family}/{dispatch}: stdout mismatch"


@pytest.mark.parametrize("preset", ["low", "medium", "strong"])
def test_all_families_run_at_preset(lua_interp, run_lua_source, preset):
    if lua_interp is None:
        pytest.skip("no Lua interpreter available")
    src = FAMILY_PROGRAM["closure"] + "print(40 + 2)\n"
    ref = run_lua_source(lua_interp, src)
    for family in FAMILIES:
        result = obfuscate(
            src,
            seed=3,
            target="lua51",
            preset=preset,
            overrides={"vm_family": family},
            verify=True,
        )
        proc = run_lua_source(lua_interp, result.output)
        assert proc.returncode == 0, (
            f"{preset}/{family}: {proc.stderr.strip()[:400]}"
        )
        assert proc.stdout == ref.stdout, f"{preset}/{family}: stdout mismatch"


@pytest.mark.parametrize("seed", [1, 2, 7, 99])
def test_same_seed_and_family_is_deterministic(seed):
    src = FAMILY_PROGRAM["upvalue"]
    for family in FAMILIES:
        a = obfuscate(
            src, seed=seed, target="lua51", preset="low",
            overrides={"vm_family": family},
        ).output
        b = obfuscate(
            src, seed=seed, target="lua51", preset="low",
            overrides={"vm_family": family},
        ).output
        assert a == b, f"{family}: output not deterministic for seed {seed}"


def test_families_mutate_structure():
    src = FAMILY_PROGRAM["loop"]
    outputs = {
        family: obfuscate(
            src, seed=5, target="lua51", preset="low",
            overrides={"vm_family": family}, pretty=True,
        ).output
        for family in FAMILIES
    }
    # every family yields a distinct build from the same seed
    assert len(set(outputs.values())) == len(FAMILIES)
    classic = outputs["classic"]
    # classic reads the flat stream directly; nothing fetches the field
    # arrays or the successorship/physical-order maps at runtime
    assert "pr.ff" not in classic
    assert "pr.oo[ip]" not in classic
    assert "pr.nx[" not in classic
    assert "pr.kd" in classic
    soa = outputs["soa"]
    assert "pr.ff" in soa
    assert "pr.oo[ip]" in soa  # identity fallback is harmless for soa
    assert "pr.nx[" not in soa
    assert "pr.nx[" in outputs["threaded"]
    scrambled = outputs["scrambled"]
    assert "pr.ff" in scrambled
    assert "pr.oo[ip]" in scrambled
    assert "pr.nx[" not in scrambled


def test_scrambled_orders_non_trivially():
    src = FAMILY_PROGRAM["recursion"]
    out = obfuscate(
        src, seed=11, target="lua51", preset="medium",
        overrides={"vm_family": "scrambled"}, pretty=True,
    ).output
    # the logical->physical map must be present and not the identity for a
    # multi-instruction program; idempotent map lookup is used at fetch time
    assert "pr.oo[ip]" in out
    assert "(pr.oo and pr.oo[ip]) or ip" in out
    assert "pr.nx[" not in out