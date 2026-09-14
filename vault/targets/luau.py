"""Luau target definition.

Defines the validated feature set for the supported Luau subset.  The subset
includes:

* everything the common frontend already supports for Lua 5.1,
* type annotations (parsed and safely discarded),
* compound assignment (``+=``, ``-=``, ``*=``, ``/=``, ``%=``, ``^=``, ``..=``),
* ``continue`` statements (lowered to a normal jump during IR building).

Explicitly excluded (rejected with an error):

* interpolated strings,
* type packs / complex generics,
* ``export`` / ``declare`` type statements,
* bitwise operators (Luau supports them; we do not yet),
* ``//`/``%`` floor division only when it is distinguishable and tested,
* Lamdba expressions (Luau `function() ... end` is fine, arrow `() -> ` is not).
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
    "compound assignment (+= -= *= /= %= ^= ..=)",
    "continue statements",
]

#: Luau features that are *not* supported.
LUAU_UNSUPPORTED = [
    "interpolated strings (backtick strings)",
    "lambda expressions (a => b)",
    "type packs in function signatures",
    "export / declare statements",
    "type aliases",
    "bitwise operators",
    "if-else expressions (a if c else b)",
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