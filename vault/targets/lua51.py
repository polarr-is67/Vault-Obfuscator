"""Lua 5.1 target definition.

Defines the validated feature set for Lua 5.1 and the post-parse validation
pass that rejects unsupported constructs with clear diagnostics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List

from vault.ast.nodes import Chunk, Node
from vault.frontend.diagnostics import DiagnosticReporter

#: Lua 5.1 features that are fully supported.
LUA51_SUPPORTED = [
    "local variables",
    "global variables",
    "assignment",
    "numeric literals",
    "string literals",
    "boolean literals",
    "nil",
    "arithmetic (+ - * / % ^)",
    "unary operators (- not #)",
    "comparisons (== ~= < <= > >=)",
    "boolean operators (and or)",
    "string concatenation (..)",
    "parentheses",
    "local functions",
    "global functions",
    "anonymous functions",
    "function calls",
    "method calls",
    "table constructors",
    "index access",
    "field access",
    "table assignment",
    "if / elseif / else",
    "while",
    "repeat ... until",
    "numeric for",
    "generic for",
    "break",
    "return",
    "varargs",
    "multiple returns",
    "closures/upvalues",
    "recursion",
    "comments",
]

#: Lua 5.1 features that are *not* supported.
LUA51_UNSUPPORTED = [
    "goto / labels (Lua 5.2+)",
    "bitwise operators (Lua 5.3+)",
    "integer subtype (Lua 5.3+)",
    "unicode escapes in strings (Lua 5.3+)",
]


@dataclass
class Lua51Target:
    """Static configuration and validation for the ``lua51`` target."""

    name: str = "lua51"
    supports_vararg: bool = True
    supports_multiple_returns: bool = True
    supports_closures: bool = True
    supports_method_calls: bool = True
    supports_generic_for: bool = True
    unsupported_nodes: List[str] = field(default_factory=list)

    def validate(self, chunk: Chunk, reporter: DiagnosticReporter) -> None:
        """Walk the AST and reject Luau-only nodes.

        Any node type that cannot be expressed in Lua 5.1 is rejected here,
        before IR lowering.
        """
        # Walk the tree looking for continuations, compound assignments
        # and Luau-only annotations, which should never survive a lua51 parse.
        def walk(node: Node) -> None:
            from vault.ast.nodes import (
                ContinueMarker, CompoundAssign, LuauTypeAnnotation, Chunk as ChunkN
            )
            if isinstance(node, ContinueMarker):
                loc = node.loc or (1, 1)
                raise reporter.unsupported(
                    "continue statements are not supported by Lua 5.1 target.",
                    loc[0], loc[1], "lua51",
                    suggestion="rewrite the loop body to avoid continue.",
                )
            if isinstance(node, CompoundAssign):
                loc = node.loc or (1, 1)
                raise reporter.unsupported(
                    "compound assignment is Luau-only syntax.",
                    loc[0], loc[1], "lua51",
                    suggestion="expand to `a = a OP b`.",
                )
            if isinstance(node, LuauTypeAnnotation):
                loc = node.loc or (1, 1)
                raise reporter.unsupported(
                    "Luau type annotations are not supported by Lua 5.1 target.",
                    loc[0], loc[1], "lua51",
                    suggestion="remove the annotation.",
                )
            # Recurse generically over dataclass fields.
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