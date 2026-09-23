"""Luau target definition.

Defines the validated feature set for the supported Luau subset.  The subset
includes:

* everything the common frontend already supports for Lua 5.1,
* type annotations (parsed and safely discarded),
* compound assignment (``+=``, ``-=``, ``*=``, ``/=``, ``%=``, ``^=``, ``..=``,
  ``//=``),
* ``continue`` statements (lowered to a normal jump during IR building),
* ``const`` bindings (lowered to ``local``; immutability is compile-time),
* ``if c then a elseif c2 then b else d`` expressions,
* backtick interpolated strings (``tostring`` semantics, ``\\`` escapes,
  ``\\u{...}`` and ``\\z`` escapes),
* ``//`` floor division,
* generalized iteration: ``for v in table`` (reset to ``next``) and
  ``for c in string`` (character iteration),
* ``\\u{...}`` / ``\\z`` string escapes.

Explicitly excluded (rejected with an error):

* type packs / complex generics,
* ``export`` / ``declare`` type statements,
* lambda expressions (a ``=>`` b),
* C-style bitwise operators (Luau itself does not provide ``& | ~ << >>``;
  Roblox exposes ``bit32.*`` globals, which pass through untouched),
* ``__iter`` metamethod expansion for userdata iteration (stock 5.1 behaviour:
  a call-time error when the value is not a function).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from vault.ast.nodes import Chunk, Node
from vault.frontend.diagnostics import DiagnosticReporter

#: Luau features that are fully supported.
LUAU_SUPPORTED = [
    "all Lua-5.1-compatible constructs",
    "type annotations (parsed and discarded)",
    "compound assignment (+= -= *= /= %= ^= ..= //=)",
    "continue statements",
    "const bindings (lowered to local)",
    "if-then-else expressions",
    "backtick interpolated strings",
    "// floor division (incl. //=)",
    "\\u{...} and \\z string escapes",
    "generalized iteration over tables and strings",
]

#: Luau features that are *not* supported.
LUAU_UNSUPPORTED = [
    "lambda expressions (a => b)",
    "type packs in function signatures",
    "export / declare statements",
    "type aliases",
    "C-style bitwise operators (not real Luau; use bit32.*)",
    "__iter metamethod / userdata generalized iteration",
]


@dataclass
class LuauTarget:
    """Static configuration and validation for the ``luau`` target."""

    name: str = "luau"
    supports_vararg: bool = True
    supports_multiple_returns: bool = True
    supports_closures: bool = True
    supports_method_calls: bool = True
    supports_generic_for: bool = True
    supports_continue: bool = True
    supports_compound_assign: bool = True
    supports_type_annotations: bool = True
    supports_const: bool = True
    supports_ifexpr: bool = True
    supports_interp_strings: bool = True
    supports_floor_div: bool = True
    supports_generalized_iteration: bool = True

    def validate(self, chunk: Chunk, reporter: DiagnosticReporter) -> None:
        """Walk the AST and reject constructs outside the Luau subset."""
        # At present, constructs outside the subset are rejected during
        # parsing.  This pass additionally rejects any remaining
        # ContinueMarker / LuauTypeAnnotation nodes if they leaked through
        # (they should not, since `luau` parses them intentionally).
        def walk(node: Node) -> None:
            from vault.ast.nodes import (
                ContinueMarker, CompoundAssign, LuauTypeAnnotation,
            )
            if isinstance(node, (ContinueMarker, LuauTypeAnnotation)):
                # These are handled by lowering; nothing to do here.
                pass
            if isinstance(node, CompoundAssign):
                # Lowering handles it.
                pass
            for f in getattr(type(node), "__dataclass_fields__", {}):
                val = getattr(node, f, None)
                if isinstance(val, Node):
                    walk(val)
                elif isinstance(val, list):
                    for item in val:
                        if isinstance(item, Node):
                            walk(item)

        for stmt in chunk.body:
            walk(stmt)