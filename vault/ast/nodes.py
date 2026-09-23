"""AST node definitions for Vault-Obf.

Design notes
------------
Nodes are plain dataclass values.  A node carries an optional source location
(``(line, column)``) so diagnostics can point at the exact spot.

Node inventory (Lua 5.1 core):
    Chunk, Literal, Name, Vararg, Table, TableEntry,
    BinaryOp, UnaryOp, Call, Index, Field,
    FunctionDef, Assignment, Local, LocalFunction, GlobalFunction,
    If/IfBranch, While, Repeat, NumericFor, GenericFor, Return, Break

Luau-only extensions (parsed then discarded or rejected):
    LuauTypeAnnotation, CompoundAssign (currently parsed and lowered
    when the target is Luau; parsed-and-rejected for Lua 5.1).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union


Location = Optional[Tuple[int, int]]


@dataclass
class Node:
    """Base class for all AST nodes.

    ``loc`` is keyword-only so that subclass positional construction like
    ``Literal(3)`` works regardless of dataclass inheritance ordering.
    """

    loc: Location = field(default=None, kw_only=True)


@dataclass
class Chunk(Node):
    """A compilation unit (main function body)."""

    body: List["Node"] = field(default_factory=list)


@dataclass
class Literal(Node):
    """Numeric, string, boolean or nil literal.

    Attributes:
        value: The literal's Python value.  ``None`` for ``nil``,
            ``bool`` for booleans, ``float`` for numbers, ``str`` for strings.
    """

    value: object = None


@dataclass
class Name(Node):
    """Identifier reference (variable load)."""

    name: str = ""


@dataclass
class Vararg(Node):
    """The ``...`` expression."""

    pass


@dataclass
class TableEntry(Node):
    """One entry in a table constructor.

    ``key`` is ``None`` for array-style entries.
    """

    key: Optional["Node"] = None
    value: "Node" = None


@dataclass
class Table(Node):
    """Table constructor ``{ [k]=v, v, k=v }``."""

    entries: List[TableEntry] = field(default_factory=list)


@dataclass
class BinaryOp(Node):
    """Binary operator expression.

    Operators: ``+ - * / % ^ .. == ~= < <= > >= and or``
    """

    op: str = ""
    left: Node = None
    right: Node = None


@dataclass
class UnaryOp(Node):
    """Unary operator expression.

    Operators: ``- not #``
    """

    op: str = ""
    operand: Node = None


@dataclass
class Call(Node):
    """Function call ``f(args)``.

    ``args`` may contain one trailing ``Vararg`` node (the last expression
    contributes multiple values), mirroring Lua's multi-value semantics.
    """

    func: Node = None
    args: List[Node] = field(default_factory=list)
    #: True when this call appears at the head of a suffix chain (its result
    #: is used only through index/field/method suffixes).  Such calls are
    #: truncated to a single value even in multi-value position.
    operand_single: bool = False


@dataclass
class MethodCall(Node):
    """Method call ``obj:method(args)``.

    Lowered by the IR builder to ``obj.method(obj, args...)`` with the object
    evaluated exactly once.
    """

    obj: Node = None
    method: str = ""
    args: List[Node] = field(default_factory=list)


@dataclass
class Paren(Node):
    """Parenthesized expression ``(expr)``.

    Parentheses force single-value semantics when ``expr`` is itself a
    multi-value expression (function call or varargs), matching Lua 5.1.
    """

    expr: Node = None


@dataclass
class Index(Node):
    """Index expression ``t[k]``."""

    obj: Node = None
    key: Node = None


@dataclass
class Field(Node):
    """Field access ``t.name`` (lowered to ``t["name"]``)."""

    obj: Node = None
    name: str = ""


@dataclass
class FunctionDef(Node):
    """Function literal ``function(a, b) body end``.

    Attributes:
        params: Parameter names.
        is_vararg: Whether the final parameter is ``...``.
        body: The function's statement list.
        name: Optional name (for debug/stats only; not serialised).
    """

    params: List[str] = field(default_factory=list)
    is_vararg: bool = False
    body: List[Node] = field(default_factory=list)
    name: Optional[str] = None


@dataclass
class Assignment(Node):
    """``t1, t2 = e1, e2``.

    ``targets`` must be variables (Name, Index, Field).
    """

    targets: List[Node] = field(default_factory=list)
    values: List[Node] = field(default_factory=list)


@dataclass
class Local(Node):
    """``local a, b = e1, e2``."""

    names: List[str] = field(default_factory=list)
    values: List[Node] = field(default_factory=list)


@dataclass
class LocalFunction(Node):
    """``local function f() ... end``."""

    name: str = ""
    func: FunctionDef = None


@dataclass
class GlobalFunction(Node):
    """``function f() ... end`` (lowered to ``f = function() ... end``)."""

    name: str = ""
    func: FunctionDef = None


@dataclass
class IfBranch(Node):
    """One branch of an ``if`` statement.

    ``cond`` is ``None`` for the ``else`` branch.
    """

    cond: Optional[Node] = None
    body: List[Node] = field(default_factory=list)


@dataclass
class If(Node):
    """``if ... then ... elseif ... then ... else ... end``."""

    branches: List[IfBranch] = field(default_factory=list)


@dataclass
class IfExpr(Node):
    """Luau if-then-else *expression* ``if c then a elseif c2 then b else d``.

    Unlike the ``If`` statement node, every branch holds exactly one value
    *expression*, the ``else`` branch is mandatory, and the whole expression
    yields exactly one value (branch values are truncated to a single result,
    matching Luau semantics).  Lowered to conditional jumps by the IR builder.
    """

    branches: List[IfBranch] = field(default_factory=list)


@dataclass
class While(Node):
    """``while cond do body end``."""

    cond: Node = None
    body: List[Node] = field(default_factory=list)


@dataclass
class Repeat(Node):
    """``repeat body until cond``."""

    body: List[Node] = field(default_factory=list)
    cond: Node = None


@dataclass
class NumericFor(Node):
    """``for i = e1, e2[, e3] do body end``.

    ``step`` is ``None`` when omitted.
    """

    var: str = ""
    start: Node = None
    limit: Node = None
    step: Optional[Node] = None
    body: List[Node] = field(default_factory=list)


@dataclass
class GenericFor(Node):
    """``for k, v in explist do body end``."""

    names: List[str] = field(default_factory=list)
    exprs: List[Node] = field(default_factory=list)
    body: List[Node] = field(default_factory=list)


@dataclass
class Return(Node):
    """``return e1, e2``.

    May be empty (``return`` with no values).
    """

    values: List[Node] = field(default_factory=list)


@dataclass
class Break(Node):
    """``break`` statement."""

    pass


@dataclass
class LuauTypeAnnotation(Node):
    """A Luau type annotation attached to a declaration.

    Parsed only when the target is ``luau``; lowered by discarding the
    annotation safely.  Never emitted into output.
    """

    annotation: str = ""


@dataclass
class CompoundAssign(Assignment):
    """Luau compound assignment ``a += b`` (also ``-=``, ``*=``, ``/=``, ``%=``, ``^=``, ``..=``)."""

    op: str = ""


@dataclass
class ShebangComment(Node):
    """A leading ``#!`` shebang line (preserved in output)."""

    pass


@dataclass
class ContinueMarker(Node):
    """Internal marker for a Luau ``continue`` statement.

    This node is never produced by the public parser API directly; it is
    created during parsing of ``luau`` targets and resolved during IR
    lowering.  It carries no user-visible semantics.
    """

    pass


def _make_continue_marker(loc: Location = None) -> "ContinueMarker":
    return ContinueMarker(loc=loc)