"""Rendering of Python values as Lua literals."""

from __future__ import annotations

import math


class LuaRaw(str):
    """A pre-rendered Lua expression, emitted verbatim by :func:`lua_value`.

    Wrapping a string in ``LuaRaw`` tells the renderer the text is already a
    valid Lua expression (for example ``D"..."``) and must not be re-quoted
    as a string literal.
    """

    __slots__ = ()


#: Radix of the printable-string integer encoding.  Each character carries one
#: base-``BLOB_RADIX`` digit plus a "more digits follow" continuation flag, so
#: the alphabet holds exactly ``2 * BLOB_RADIX`` characters.
BLOB_RADIX = 45


def build_blob_alphabet(rng) -> str:
    """Return a deterministic 90-character alphabet for the blob encoding.

    The characters are drawn from printable ASCII, excluding the quote and
    backslash (which would need escaping inside a Lua string literal) and
    ``@`` (reserved by the runtime template's substitution markers).  The
    order is shuffled by ``rng`` so each build's payload strings look
    different while remaining reproducible for a given seed.
    """
    candidates = [chr(c) for c in range(33, 127) if c not in (34, 92, 64)]
    rng.shuffle(candidates)
    return "".join(candidates[: 2 * BLOB_RADIX])


def can_blob(values) -> bool:
    """Whether ``values`` can be exactly round-tripped by the blob encoding.

    The encoding only carries integers whose magnitude stays below ``2**52``,
    which keeps every decoded value exactly representable as a Lua number
    (an IEEE-754 double).  Any float, boolean, or out-of-range integer forces
    the caller to fall back to a plain table literal so correctness is never
    traded for a prettier payload.
    """
    limit = 1 << 52
    for v in values:
        if isinstance(v, bool):
            return False
        if not isinstance(v, int):
            return False
        if v <= -limit or v >= limit:
            return False
    return True


def encode_int_blob(values, alphabet: str) -> str:
    """Encode a list of integers as a printable string using ``alphabet``.

    Each value is zig-zag mapped to a non-negative integer (so negatives cost
    no more than positives) and then emitted as base-``BLOB_RADIX`` digits,
    least-significant first, with a continuation flag folded into every
    character.  The result contains no separators and no bare numbers; it is
    decoded by the runtime's blob decoder back into the identical integers.
    """
    radix = BLOB_RADIX
    out = []
    for x in values:
        z = x * 2 if x >= 0 else (-x) * 2 - 1
        while True:
            digit = z % radix
            z //= radix
            if z:
                out.append(alphabet[radix + digit])
            else:
                out.append(alphabet[digit])
                break
    return "".join(out)


def lua_quote_string(value: str) -> str:
    """Render a Python string as a Lua 5.1 double-quoted literal.

    Produces a valid Lua 5.1 string literal that decodes back to ``value``.
    All bytes are output as escaped ASCII so the emitted script is plain
    ASCII regardless of the original encoding.
    """
    out = ['"']
    for ch in value:
        code = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == "\\":
            out.append("\\\\")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ch == "\a":
            out.append("\\a")
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\v":
            out.append("\\v")
        elif 32 <= code < 127:
            out.append(ch)
        else:
            out.append("\\%d" % code)
    out.append('"')
    return "".join(out)


def lua_number(value: float) -> str:
    """Render a Python float as a valid Lua numeric literal."""
    if math.isnan(value):
        return "(0/0)"
    if math.isinf(value):
        return "((1/0))" if value > 0 else "((-1/0))"
    if value == int(value) and abs(value) < (1 << 60):
        return repr(int(value))
    text = repr(value)
    # Python sometimes renders floats in a form Lua 5.1 accepts; adjust
    # exponent separators if needed (Python uses 'e', Lua accepts 'e').
    return text


def lua_value(value) -> str:
    """Render a Python value as a Lua expression."""
    if isinstance(value, LuaRaw):
        return str(value)
    if value is None:
        return "nil"
    if value is False:
        return "false"
    if value is True:
        return "true"
    if isinstance(value, float):
        return lua_number(value)
    if isinstance(value, int):
        return repr(value)
    if isinstance(value, str):
        return lua_quote_string(value)
    if isinstance(value, (list, tuple)):
        return lua_table(list(value))
    raise TypeError(f"cannot render {type(value).__name__} as Lua literal")


def lua_table(values, *, numpy_ok: bool = False) -> str:
    """Render a list as a Lua table literal with 1-based indices."""
    if not values:
        return "{}"
    parts = []
    for v in values:
        parts.append(lua_value(v))
    return "{" + ",".join(parts) + "}"


def lua_table_keyed(keys, values) -> str:
    """Render keys+values as a Lua table literal (both lists, 1-aligned)."""
    if not values:
        return "{}"
    parts = []
    for k, v in zip(keys, values):
        parts.append(f"[{lua_value(k)}]={lua_value(v)}")
    return "{" + ",".join(parts) + "}"