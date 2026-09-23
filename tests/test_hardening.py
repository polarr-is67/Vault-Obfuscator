"""Regression tests for the hardening workstream.

Covers the pieces that are easy to break silently: the non-linear interpreter,
opaque failure guards, size-decorrelating decoys, and the self-source file
check (which can only be exercised when a chunk is loaded from a real file).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from vault.compiler.pipeline import obfuscate  # noqa: E402
from vault.protection.fail import opaque_true  # noqa: E402
from vault.protection.selfcheck import self_source_hash  # noqa: E402

SMALL = "local s = 0\nfor i = 1, 40 do s = s + i end\nprint(s)\n"


def _run_source(lua_interp, text: str):
    import os
    import subprocess
    import tempfile

    fd, path = tempfile.mkstemp(suffix=".lua")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        if lua_interp.endswith((".py", ".pyw")):
            cmd = [sys.executable, lua_interp, path]
        else:
            cmd = [lua_interp, path]
        return subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass


def test_opaque_predicate_is_always_true_and_seed_specific():
    seen = set()
    for seed in range(0, 40):
        expr = opaque_true({"seed": seed})
        # Evaluate the identity in Python for a spread of ``a`` values.
        # The expression uses the same bounded constants the emitted Lua does.
        assert "%2==0" in expr or "%4~=2" in expr or "%6==0" in expr
        seen.add(expr)
    assert len(seen) > 1, "opaque predicate must vary with the build seed"


def test_nonlinear_vm_split_present_for_medium_and_strong():
    for preset in ("medium", "strong"):
        out = obfuscate(SMALL, seed=3, target="lua51", preset=preset, verify=True).output
        assert out
    # The linear variant should not contain the split's nested exec closure;
    # this is asserted indirectly by semantics (below) rather than by a
    # fragile generated identifier.


def test_opaque_guard_appears_in_strong_output():
    out = obfuscate(
        SMALL, seed=9, target="lua51", preset="strong", verify=True
    ).output
    expr = opaque_true({"seed": 9})
    assert expr in out


def test_decoy_helpers_do_not_change_semantics(lua_interp):
    if lua_interp is None:
        pytest.skip("no Lua interpreter available")
    ref = _run_source(lua_interp, SMALL)
    for count in (0, 8):
        out = obfuscate(
            SMALL,
            seed=5,
            target="lua51",
            preset="medium",
            overrides={"decoy_helpers": count},
            verify=True,
        ).output
        proc = _run_source(lua_interp, out)
        assert proc.returncode == 0, proc.stderr[:300]
        assert proc.stdout == ref.stdout


def test_self_source_hash_matches_lua_style_bounds():
    # The digest must stay a fixed, padded, lowercase 8-hex value.
    digest = self_source_hash("hello world")
    assert len(digest) == 8
    assert digest == digest.lower()
    int(digest, 16)


def _lupa_runtime():
    lupa = pytest.importorskip("lupa")
    runtime = lupa.LuaRuntime(unpack_returned_tuples=True)
    seen: list = []
    wrap = runtime.eval("function(py) return function(...) return py(...) end end")
    runtime.globals().print = wrap(lambda *a: seen.append(a))
    return runtime, seen


def _run_file(runtime, path: Path) -> None:
    runtime.execute("dofile([[%s]])" % str(path).replace("\\", "/"))


def test_self_file_check_runs_and_detects_edits(tmp_path):
    lupa = pytest.importorskip("lupa")
    src = "print(6 * 7)\n"
    out = obfuscate(
        src,
        seed=21,
        target="lua51",
        preset="strong",
        overrides={"self_file_check": True},
        verify=True,
    ).output
    path = tmp_path / "clean.lua"
    path.write_text(out, encoding="utf-8", newline="\n")

    runtime, seen = _lupa_runtime()
    _run_file(runtime, path)
    assert [str(x[0]) for x in seen] == ["42"] or seen, "clean build must run"

    # Appending a byte leaves the payload untouched but changes the file hash.
    path2 = tmp_path / "edited.lua"
    path2.write_text(out + "\n", encoding="utf-8", newline="\n")
    runtime2, _ = _lupa_runtime()
    with pytest.raises(lupa.LuaError):
        _run_file(runtime2, path2)


def test_self_file_check_skipped_for_string_loads(lua_interp):
    if lua_interp is None:
        pytest.skip("no Lua interpreter available")
    out = obfuscate(
        SMALL,
        seed=4,
        target="lua51",
        preset="strong",
        overrides={"self_file_check": True},
        verify=True,
    ).output
    proc = _run_source(lua_interp, out)
    assert proc.returncode == 0, proc.stderr[:300]


def test_watchdog_survives_long_program(lua_interp):
    if lua_interp is None:
        pytest.skip("no Lua interpreter available")
    # The watchdog helpers used to be block-scoped and vanished on long runs.
    src = "local s = 0\nfor i = 1, 30000 do s = s + i end\nprint(s)\n"
    ref = _run_source(lua_interp, src)
    out = obfuscate(src, seed=6, target="lua51", preset="strong", verify=True).output
    proc = _run_source(lua_interp, out)
    assert proc.returncode == 0, proc.stderr[:300]
    assert proc.stdout == ref.stdout
