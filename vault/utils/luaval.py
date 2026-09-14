"""Rendering of Python values as Lua literals."""

from __future__ import annotations

import math


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