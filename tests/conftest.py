"""Shared fixtures for the Vault-Obf test suite."""

from __future__ import annotations

import itertools
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault.compiler.pipeline import obfuscate  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent

PRESETS = ["low", "medium", "strong"]
TARGETS = ["lua51", "luau"]

#: Small, dependency-free programs whose raw (unprotected) output must be
#: byte-identical to the VM-generated output. Each key is the program name.
SEMANTIC_PROGRAMS = {
    "arith": (
        "local function add(a, b) return a + b end\n"
        "print(add(21, 21))\n"
        "print(2 ^ 10, 17 % 5, 10 / 4, 3 * 7)\n"
    ),
    "recursion": (
        "local function fact(n)\n"
        "  if n <= 1 then return 1 end\n"
        "  return n * fact(n - 1)\n"
        "end\n"
        "print(fact(10))\n"
    ),
    "closure_upvalue": (
        "local function mk(x)\n"
        "  local function inc() x = x + 1; return x end\n"
        "  return inc\n"
        "end\n"
        "local f = mk(10)\n"
        "print(f(), f(), f())\n"
    ),
    "varargs": (
        "local function t(...) return select('#', ...) end\n"
        "print(t(1, 'a', 4))\n"
        "local function u(a, ...) local r = {...}\n"
        "return #r + select('#', ...) end\n"
        "print(u(1, 2, 3))\n"
    ),
    "loops": (
        "for i = 1, 10, 3 do io.write(i, ' ') end\nprint('')\n"
        "local i = 0\n"
        "while i < 3 do io.write(i) i = i + 1 end\nprint('')\n"
        "repeat io.write('r') i = i + 1 until i >= 6\n"
        "print('')\n"
    ),
    "tables": (
        "local t = {1, 2; ['k'] = 'v'}\n"
        "t.x = 5\n"
        "print(#t, t.k, t.x + t[1] + t[2])\n"
        "local a, b = t[1], t[2]\n"
        "print(a, b)\n"
    ),
    "strings": (
        "local s = 'hello'\n"
        "print(s:upper(), s:sub(1, 3))\n"
        "print('a' .. 1 .. 'z')\n"
        "print(#s)\n"
    ),
    "logic": (
        "local function both(a, b) return a and b end\n"
        "print(both(1, 2), both(1, nil), not nil, not 0)\n"
        "if not nil then io.write('t') end\n"
        "print('')\n"
    ),
    "metamethods": (
        "local mt = {__add = function(a, b) return a.x + b.x end,\n"
        "  __index = function(t, k) return 42 end}\n"
        "local a = setmetatable({x = 10}, mt)\n"
        "local b = setmetatable({x = 5}, mt)\n"
        "print(a + b, a.anything)\n"
    ),
    "multireturn": (
        "local function two(a) return a, a * 2 end\n"
        "local x, y = two(3)\n"
        "io.write(x, y)\n"
        "local t = {two(4)}\n"
        "print(#t)\n"
    ),
}


@pytest.fixture(scope="session")
def project_root() -> Path:
    return PROJECT_ROOT


def _env_lua() -> str | None:
    """Resolve a Lua interpreter for end-to-end run tests.

    Preference: ``VAULT_LUA`` env var, then well-known interpreter names on
    PATH.  When none is available the lupa-backed shim
    ``tools/run_lua.py`` is used if ``lupa`` is installed in the current
    environment.  Returns ``None`` when nothing is available (tests then
    skip).
    """
    from_env = os.environ.get("VAULT_LUA")
    if from_env and Path(from_env).is_file():
        return from_env
    for name in ("lua", "lua51", "lua5.1", "lua53", "lua5.3", "lua54", "lua5.4"):
        path = shutil.which(name)
        if path:
            return path
    shim = PROJECT_ROOT / "tools" / "run_lua.py"
    if shim.is_file():
        try:
            import lupa  # noqa: PLC0415

            return str(shim)
        except ImportError:
            pass
    return None


def _lua_cmd(interp: str) -> list:
    """Build the argv prefix to run an interpreter (shim scripts need a
    python prefix)."""
    if interp.endswith((".py", ".pyw")):
        return [sys.executable, interp]
    return [interp]


@pytest.fixture(scope="session")
def lua_interp():
    return _env_lua()


@pytest.fixture(scope="session")
def run_lua():
    def _run(interp: str, path: Path, timeout: int = 60) -> subprocess.CompletedProcess:
        return subprocess.run(
            _lua_cmd(interp) + [str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    return _run


@pytest.fixture(scope="session")
def run_lua_source(tmp_path_factory):
    """Run ``text`` through an interpreter.

    The script is materialized to a temp file before execution so it is not
    passed on the command line — obfuscated output routinely exceeds
    Windows' 32767-byte argv limit.
    """

    root = tmp_path_factory.mktemp("run_source")
    counter = itertools.count()

    def _run(interp: str, source: str, timeout: int = 60) -> subprocess.CompletedProcess:
        path = root / f"chunk_{next(counter)}.lua"
        path.write_text(source, encoding="utf-8", newline="\n")
        return subprocess.run(
            _lua_cmd(interp) + [str(path)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    return _run


@pytest.fixture
def build(tmp_path):
    """Build an obfuscated script and materialize it to a file.

    Returns a callable ``(src, *, target, preset, seed, verify) -> Path``.
    """

    def _build(
        src: str,
        *,
        target: str = "lua51",
        preset: str = "low",
        seed: int = 123,
        verify: bool = True,
        pretty: bool = False,
    ) -> Path:
        result = obfuscate(
            src,
            seed=seed,
            target=target,
            preset=preset,
            verify=verify,
            pretty=True if pretty else None,
        )
        assert result.output, "obfuscation produced empty output"
        out = tmp_path / f"{preset}_{seed}.lua"
        out.write_text(result.output, encoding="utf-8")
        return out

    return _build


@pytest.fixture
def assert_matches_reference(run_lua_source):
    """Build every preset and compare stdout against the raw program."""

    def _check(src: str, interp: str) -> None:
        ref = run_lua_source(interp, src)
        for preset in PRESETS:
            result = obfuscate(src, seed=7, target="lua51", preset=preset, verify=True)
            assert result.output, f"{preset}: empty output"
            proc = run_lua_source(interp, result.output)
            assert proc.returncode == ref.returncode, (
                f"{preset}: return code {proc.returncode} != {ref.returncode}: "
                f"{proc.stderr.strip()[:400]}"
            )
            assert proc.stdout == ref.stdout, f"{preset}: stdout mismatch"

    return _check