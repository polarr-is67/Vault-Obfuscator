"""Tests for the printable-string payload encoding.

Numeric payload arrays are embedded as opaque printable strings (decoded by
the VM at load time) rather than bare number tables.  These tests cover the
codec round-trip, the exact-representability guard, and the property that a
normal build no longer emits long runs of bare integers.
"""

from __future__ import annotations

import random
import re

import pytest

from vault.compiler.pipeline import obfuscate
from vault.utils.luaval import (
    BLOB_RADIX,
    LuaRaw,
    build_blob_alphabet,
    can_blob,
    encode_int_blob,
    lua_value,
)
from vault.utils.random import DeterministicRandom


def _decode_blob(s: str, alphabet: str):
    """Reference decoder mirroring the runtime's Lua implementation."""
    radix = BLOB_RADIX
    rev = {ch: i for i, ch in enumerate(alphabet)}
    out = []
    i, n = 0, len(s)
    while i < n:
        acc, mul = 0, 1
        while True:
            pos = rev[s[i]]
            i += 1
            digit = pos % radix
            acc += digit * mul
            if pos < radix:
                break
            mul *= radix
        out.append(acc // 2 if acc % 2 == 0 else -(acc + 1) // 2)
    return out


def _alphabet():
    return build_blob_alphabet(DeterministicRandom("test-seed"))


def test_alphabet_shape():
    alpha = _alphabet()
    assert len(alpha) == 2 * BLOB_RADIX
    assert len(set(alpha)) == len(alpha)  # all distinct
    for ch in alpha:
        assert 33 <= ord(ch) < 127
        assert ch not in ('"', "\\", "@")


def test_alphabet_is_deterministic_per_seed():
    a = build_blob_alphabet(DeterministicRandom("seed-1"))
    b = build_blob_alphabet(DeterministicRandom("seed-1"))
    c = build_blob_alphabet(DeterministicRandom("seed-2"))
    assert a == b
    assert a != c


@pytest.mark.parametrize(
    "values",
    [
        [],
        [0],
        [1, 2, 3],
        [-1, -2, -3],
        [0, -1, 1, -2, 2],
        [44, 45, 46, 89, 90, 91],  # radix boundaries
        [131071, 131072, 262143],
        [(1 << 52) - 1, -((1 << 52) - 1)],
        list(range(-50, 50)),
    ],
)
def test_roundtrip_crafted(values):
    alpha = _alphabet()
    assert _decode_blob(encode_int_blob(values, alpha), alpha) == values


def test_roundtrip_fuzz():
    alpha = _alphabet()
    rnd = random.Random(20240917)
    for _ in range(2000):
        n = rnd.randint(0, 40)
        vals = [rnd.randint(-(1 << 51), (1 << 51) - 1) for _ in range(n)]
        assert _decode_blob(encode_int_blob(vals, alpha), alpha) == vals


def test_can_blob_guard():
    assert can_blob([0, 1, -1, (1 << 52) - 1, -((1 << 52) - 1)])
    assert not can_blob([1, 2.5])          # non-integer float
    assert not can_blob([1 << 52])         # too large (loses double precision)
    assert not can_blob([-(1 << 52)])      # too negative
    assert not can_blob([True])            # booleans are not payload integers


def test_luaraw_is_emitted_verbatim():
    assert lua_value(LuaRaw('D"abc"')) == 'D"abc"'
    # and it survives nesting inside a table
    assert lua_value([1, LuaRaw('D"xy"'), 2]) == '{1,D"xy",2}'


SAMPLE = (
    "local function fib(n)\n"
    "  if n < 2 then return n end\n"
    "  return fib(n - 1) + fib(n - 2)\n"
    "end\n"
    "local t = {}\n"
    "for i = 1, 10 do t[i] = fib(i) end\n"
    "print(t[10], 'done', 3 * 7)\n"
)


@pytest.mark.parametrize("preset", ["low", "medium", "strong"])
def test_output_has_no_long_integer_runs(preset):
    """A normal build embeds no bare '{123,123,123,...}' number lists."""
    out = obfuscate(SAMPLE, seed=2024, preset=preset, verify=True).output
    # No table containing three or more consecutive bare integers.
    assert re.search(r"\{\d+,\d+,\d+", out) is None
    # And it does contain at least one decoder-call blob string.
    assert re.search(r'[A-Za-z_][A-Za-z0-9_]*"[!-~]{4,}"', out) is not None
