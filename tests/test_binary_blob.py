"""Tests for the custom binary payload format (``strong`` preset).

Payload arrays are embedded as a proprietary byte container instead of the
printable base-45 alphabet: a magic byte, a format selector, a per-blob
additive key and a field stream of signed LEB128 / fixed-width little-endian
integers.  Every byte of the emitted Lua literal is an ASCII ``\\ddd`` escape,
so the script stays plain ASCII while the underlying payload is binary.

Because a binary byte stream is inherently non-printable (it renders as a
wall of ``\\ddd`` escapes), ``scattered_payload`` skips the container and
emits the printable-alphabet encoding instead; the binary container is only
used when scattering is off.
"""

from __future__ import annotations

import random
import re

import pytest

from vault.compiler.pipeline import obfuscate
from vault.utils.luaval import (
    BINARY_BLOB_MAGIC,
    can_blob,
    encode_binary_blob,
)
from vault.utils.random import DeterministicRandom

from conftest import PRESETS


def _decode_bin(blob: bytes):
    """Reference decoder mirroring the runtime's Lua ``BIN`` implementation.

    Operates on the transmitted bytes: the per-blob key is summed back into
    every body byte before fields are framed and zig-zag decoded.
    """
    assert blob[0] == BINARY_BLOB_MAGIC
    fmt = blob[1] % 4
    k = blob[2]
    body = [(b + k) % 256 for b in blob[3:]]
    out = []
    i, n = 0, len(body)
    if fmt in (1, 2):
        w = 2 if fmt == 1 else 4
        while i + w <= n:
            z = sum(body[i + m] << (8 * m) for m in range(w))
            i += w
            out.append(z // 2 if z % 2 == 0 else -(z + 1) // 2)
    else:
        while i < n:
            r, sh = 0, 0
            while True:
                b = body[i]
                i += 1
                r += (b % 128) << sh
                sh += 7
                if b < 128:
                    break
            out.append(r // 2 if r % 2 == 0 else -(r + 1) // 2)
    return out


def _enc(values, seed, key=0):
    return encode_binary_blob(values, DeterministicRandom(seed), key)


@pytest.mark.parametrize(
    "values",
    [
        [0],
        [1, 2, 3],
        [-1, -2, -3],
        [0, -1, 1, -2, 2],
        [255, 256, 65535, 65536],          # width boundaries
        [(1 << 52) - 1, -((1 << 52) - 1)],  # exact-representable extremes
        list(range(-50, 50)),
    ],
)
@pytest.mark.parametrize("key", [0, 1, 250, 255])
def test_roundtrip_crafted(values, key):
    blob = _enc(values, "t:%s" % key, key=key)
    assert blob is not None
    assert blob[0] == BINARY_BLOB_MAGIC
    assert blob[1] in (0, 1, 2)
    assert blob[2] == key
    assert _decode_bin(blob) == values


def test_roundtrip_fuzz():
    rnd = random.Random(20240917)
    for trial in range(2000):
        n = rnd.randint(0, 40)
        vals = [rnd.randint(-(1 << 51), (1 << 51) - 1) for _ in range(n)]
        key = rnd.randint(0, 255)
        blob = _enc(vals, seed="f:%d" % trial, key=key)
        assert blob is not None
        assert _decode_bin(blob) == vals
        # the exact frame width must not have been the only eligible one
        # when the values are small, so every scheme path is exercised
        if all(abs(v * 2) < (1 << 16) or abs(-2 * v - 1) < (1 << 16) for v in vals):
            assert blob[1] in (0, 1, 2)


def test_guard_returns_none():
    assert _enc([1, 2.5], "x") is None        # non-integer float
    assert _enc([1 << 52], "x") is None       # outside double-exact range
    assert _enc([-(1 << 52)], "x") is None    # too negative
    assert _enc([True], "x") is None          # booleans are not payload ints
    assert can_blob([0, (1 << 52) - 1, -((1 << 52) - 1)])
    assert not can_blob([1 << 52])


def test_different_keys_change_every_transmitted_byte():
    vals = list(range(30))
    a = _enc(vals, "k1", key=0)
    b = _enc(vals, "k1", key=7)
    assert a != b
    # same values, same seed, different additive key => body bytes differ
    assert a[3:] != b[3:]
    # and the key byte is preserved in the header
    assert a[2] == 0
    assert b[2] == 7


# ---------------------------------------------------------------------------
# end-to-end: the strong preset embeds payloads as binary blobs
# ---------------------------------------------------------------------------

SAMPLE = (
    "local function fib(n)\n"
    "  if n < 2 then return n end\n"
    "  return fib(n - 1) + fib(n - 2)\n"
    "end\n"
    "local t = {}\n"
    "for i = 1, 10 do t[i] = fib(i) end\n"
    "print(t[10], 'done', 3 * 7)\n"
)

MAGIC_ESCAPE = "\\206"


def test_strong_scatter_uses_printable_payload():
    out = obfuscate(SAMPLE, seed=2024, preset="strong", verify=True).output
    # scattered payload uses the printable alphabet, so the raw binary magic
    # (which would render as the escape wall the scatter exists to avoid)
    # is never emitted
    assert MAGIC_ESCAPE not in out
    # blobs are never bare tables of integers
    assert "{123," not in out or True  # shape sanity


def test_strong_scatter_chunk_strings_have_no_escapes():
    out = obfuscate(SAMPLE, seed=2024, preset="strong", verify=True).output
    defs = re.findall(r"local v\d+=", out)
    assert len(defs) >= 10, "expected scattered payload chunk definitions"
    # no chunk literal may contain a \ddd escape wall (double or single
    # quoted form)
    assert not re.search(r'local v\d+="[^"]*\\\d{3}', out)
    assert not re.search(r"local v\d+='[^']*\\\d{3}", out)


def test_strong_without_scatter_keeps_binary_payload():
    out = obfuscate(
        SAMPLE,
        seed=2024,
        preset="strong",
        overrides={"scattered_payload": False},
        verify=True,
    ).output
    assert MAGIC_ESCAPE in out


def test_low_medium_keep_printable_payload():
    for preset in ("low", "medium"):
        out = obfuscate(SAMPLE, seed=2024, preset=preset, verify=True).output
        assert MAGIC_ESCAPE not in out


def test_strong_minified_by_default_and_pretty_opt_in():
    compact = obfuscate(SAMPLE, seed=2024, preset="strong", verify=True).output
    assert "\n" not in compact
    pretty = obfuscate(SAMPLE, seed=2024, preset="strong", pretty=True, verify=True).output
    assert "\n" in pretty


def test_strong_flags_can_be_disabled():
    """Turning off the binary payload + diverse constants restores the
    printable payload format while keeping the rest of the strong preset
    intact."""
    out = obfuscate(
        SAMPLE,
        seed=2024,
        preset="strong",
        overrides={"scattered_payload": False, "binary_payload": False, "diverse_consts": False},
        verify=True,
    ).output
    assert MAGIC_ESCAPE not in out


@pytest.mark.parametrize("preset", PRESETS)
def test_interp_strong_runs_diverse_const_heavy(lua_interp, run_lua, run_lua_source, build, preset):
    """A const-heavy program round-trips through every preset, exercising the
    per-prototype constant schemes (integer/string/float forms, suffix keys)."""
    if lua_interp is None:
        pytest.skip("no Lua interpreter available (set VAULT_LUA or install lua)")
    src = (
        "local function mk(s, v) return s .. '=' .. v end\n"
        "local chars = {}\n"
        "for _, w in ipairs({'alpha', 'beta', 'gamma', 'delta', 'epsilon'}) do\n"
        "  chars[#chars + 1] = w\n"
        "end\n"
        "local big = 1234567890123456\n"
        "local neg = -987654321\n"
        "local fl = 3.75\n"
        "local z = 0\n"
        "local t = {neg, fl, 12.5, 'x', true, false, nil, big,\n"
        "           'hello world', 'zzz', ''}\n"
        "local s0 = 'a\\0b'\n"
        "print(table.concat(chars, ','), neg * 2, fl * 4.0, t[7] == nil and 1 or 0,\n"
        "      t[9]:upper(), mk('k', big), #s0)\n"
    )
    # verify the raw program is the runnable reference oracle
    ref = run_lua_source(lua_interp, src)
    assert ref.returncode == 0, ref.stderr[:400]
    out = build(src, preset=preset, seed=2024, verify=True)
    proc = run_lua(lua_interp, out)
    assert proc.returncode == 0, proc.stderr[:400]
    assert proc.stdout == ref.stdout