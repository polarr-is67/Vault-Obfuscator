"""AST-to-IR lowering.

The IR builder walks the AST and emits a register-based intermediate
representation with per-function prototypes.  Registers are plain integers;
jump targets are symbolic labels (emitted as ``MARK`` instructions whose pc is
resolved into jumps by :meth:`IRProto.resolve_labels`).

Lua 5.1 semantics preserved:

* Multiple-return evaluation rules (only the last expression of a list may
  expand; parentheses force single-value semantics).
* Short-circuit ``and`` / ``or`` returning operand values.
* Lexical scoping, shadowing, and ``repeat`` body visibility in its
  condition.
* Upvalue capture by reference with close-on-return.
* The order of evaluation matches PUC-Lua: assignment target prefixes
  (index expressions) are evaluated before the right-hand side.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vault import IRLoweringError, SourceLocation
from vault.ast.nodes import (
    Node,
    Literal,
    Name,
    Table,
    BinaryOp,
    UnaryOp,
    Call,
    MethodCall,
    Index,
    Field,
    FunctionDef,
    Assignment,
    Local,
    LocalFunction,
    GlobalFunction,
    If,
    IfBranch,
    IfExpr,
    While,
    Repeat,
    NumericFor,
    GenericFor,
    Return,
    Break,
    Vararg,
    TableEntry,
    Chunk,
    CompoundAssign,
    Paren,
    ContinueMarker,
)

#: Maximum number of dynamic values produced by a multi-value tail that the
#: compiler materialises into registers.  Caller frames always receive the
#: real runtime list via the VM call protocol; this cap only bounds how many
#: extra registers are reserved.
MULTI_CAP = 8


@dataclass
class IRInstr:
    """A single IR instruction."""

    op: str
    a: int = 0
    b: int = 0
    c: int = 0
    d: int = 0
    e: int = 0
    label: object = None


@dataclass
class UpvalDesc:
    """Upvalue descriptor of a prototype.

    ``instack`` selects the capture source: a variable in the enclosing
    function's registers (``idx`` = register) or an upvalue of the enclosing
    function (``idx`` = upvalue index).
    """

    instack: bool
    idx: int


class _Label:
    __slots__ = ("name",)

    def __init__(self, name: str = "") -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"<Label {self.name}>"


@dataclass
class IRProto:
    """A function prototype in the IR."""

    proto_id: int
    name: str
    params: int
    is_vararg: bool
    maxstack: int
    instructions: List[IRInstr] = field(default_factory=list)
    constants: List[object] = field(default_factory=list)
    children: List[int] = field(default_factory=list)
    upvaldescs: List[UpvalDesc] = field(default_factory=list)
    line: int = 0

    def resolve_labels(self) -> None:
        """Resolve MARK labels into jump program counters."""
        pc_of: Dict[_Label, int] = {}
        for idx, ins in enumerate(self.instructions):
            if ins.op == "MARK" and ins.label is not None:
                pc_of.setdefault(ins.label, idx)
        for ins in self.instructions:
            if ins.label is not None:
                if ins.label not in pc_of:
                    raise IRLoweringError(
                        f"internal: jump label {ins.label} never marked.",
                    )
                ins.d = pc_of[ins.label]
                ins.label = None
            for fname in ("a", "b", "c", "d", "e"):
                val = getattr(ins, fname)
                if isinstance(val, _Label):
                    if val not in pc_of:
                        raise IRLoweringError(
                            f"internal: jump label {val} never marked.",
                        )
                    setattr(ins, fname, pc_of[val])


class _Scope:
    __slots__ = ("names", "hidden")

    def __init__(self) -> None:
        self.names: Dict[str, int] = {}
        self.hidden: List[tuple] = []


class _LoopCtx:
    __slots__ = ("head", "exit", "cont")

    def __init__(self, head: _Label, exit: _Label, cont: _Label) -> None:
        self.head = head
        self.exit = exit
        self.cont = cont


class _VarRef:
    __slots__ = ("kind", "index")

    def __init__(self, kind: str, index: int) -> None:
        self.kind = kind  # "local" | "upval" | "global"
        self.index = index


class _FuncCtx:
    """Per-function lowering context."""

    def __init__(
        self,
        builder: "IRBuilder",
        proto: IRProto,
        parent: Optional["_FuncCtx"],
    ) -> None:
        self.builder = builder
        self.proto = proto
        self.parent = parent
        self.next_reg = proto.params
        self.pool: List[int] = []
        self.scopes: List[_Scope] = [_Scope()]
        self.upvals: List[UpvalDesc] = []
        self.upval_by_name: Dict[str, int] = {}
        self.loops: List[_LoopCtx] = []

        # register the parameters in the outermost scope
        for i in range(proto.params):
            self.scopes[0].names[builder._param_names[proto.proto_id][i]] = i

    # -- registers -------------------------------------------------------

    def new_reg(self) -> int:
        if self.pool:
            return self.pool.pop()
        r = self.next_reg
        self.next_reg += 1
        self.proto.maxstack = max(self.proto.maxstack, self.next_reg)
        return r

    def free_reg(self, r: int) -> None:
        if r < self.next_reg and r not in self.pool:
            self.pool.append(r)

    def alloc_block(self, n: int) -> int:
        """Allocate a contiguous block of ``n`` scratch registers."""
        if n == 0:
            return 0
        base = self.next_reg
        self.next_reg += n
        self.proto.maxstack = max(self.proto.maxstack, self.next_reg)
        return base

    # -- locals ----------------------------------------------------------

    def local_reg(self, name: str) -> Optional[int]:
        for scope in reversed(self.scopes):
            if name in scope.names:
                return scope.names[name]
        return None

    def declare_local(self, name: str) -> int:
        r = self.new_reg()
        top = self.scopes[-1]
        if name in top.names:
            top.hidden.append((name, top.names[name]))
        top.names[name] = r
        return r

    def enter_scope(self) -> None:
        self.scopes.append(_Scope())

    def exit_scope(self) -> None:
        scope = self.scopes.pop()
        for _, r in scope.names.items():
            self.free_reg(r)
        for _, r in scope.hidden:
            self.free_reg(r)

    # -- upvalues ---------------------------------------------------------

    def capture_upvalue(self, name: str) -> Optional[int]:
        if name in self.upval_by_name:
            return self.upval_by_name[name]
        # Contexts traversed between this function and the one that owns the
        # variable, from the direct parent up.  When the owner is a *grand*
        # parent, every intermediate context that does not itself reference
        # the name must still declare it as an upvalue so the capture can be
        # threaded registration-wise: the CLOSURE handler instantiates an
        # ``instack`` capture against the *direct* enclosing frame's
        # registers, so a grandchild cannot point at a register of a frame it
        # is not closed over by.  Canonical Lua handles this by giving each
        # intermediate prototype its own upvalue slot for the name.
        chain: List["_FuncCtx"] = []
        ctx: Optional["_FuncCtx"] = self.parent
        while ctx is not None:
            r = ctx.local_reg(name)
            if r is not None:
                # Owned as a register local of ``ctx``.  Thread outwards-first
                # so each context wraps the slot or inherited upvalue of the
                # context immediately *above* it, ending with this function
                # capturing the direct parent's upvalue index.  Only the
                # context whose direct parent is the owner may capture the
                # owner's register directly; every further-out context
                # inherits its parent's upvalue index.
                threaded = r
                for i_m, m in enumerate(reversed(chain)):
                    if i_m == 0:
                        threaded = m._ensure_upvalue(name, ("instack", threaded))
                    else:
                        threaded = m._ensure_upvalue(name, ("upval", threaded))
                idx = len(self.upvals)
                if not chain:
                    self.upvals.append(UpvalDesc(instack=True, idx=r))
                else:
                    self.upvals.append(UpvalDesc(instack=False, idx=threaded))
                self.upval_by_name[name] = idx
                return idx
            if name in ctx.upval_by_name:
                tid = ctx.upval_by_name[name]
                for m in reversed(chain):
                    tid = m._ensure_upvalue(name, ("upval", tid))
                idx = len(self.upvals)
                self.upvals.append(UpvalDesc(instack=False, idx=tid))
                self.upval_by_name[name] = idx
                return idx
            chain.append(ctx)
            ctx = ctx.parent
        return None

    def _ensure_upvalue(self, name: str, src: tuple) -> int:
        """Give ``self`` an upvalue for ``name`` unless it already has one.

        ``src`` is ``("instack", register)`` or ``("upval", index)`` of the
        context immediately enclosing ``self``.  Returns the upvalue index
        (existing or newly appended) so a caller in the next-inner context
        can reference it.
        """
        if name in self.upval_by_name:
            return self.upval_by_name[name]
        idx = len(self.upvals)
        kind, oid = src
        self.upvals.append(
            UpvalDesc(instack=(kind == "instack"), idx=oid)
        )
        self.upval_by_name[name] = idx
        return idx

    # -- emission ---------------------------------------------------------

    def emit(
        self,
        op: str,
        a: int = 0,
        b: int = 0,
        c: int = 0,
        d: int = 0,
        e: int = 0,
        label: object = None,
    ) -> None:
        self.proto.instructions.append(
            IRInstr(op=op, a=a, b=b, c=c, d=d, e=e, label=label)
        )

    def mark(self, label: _Label) -> None:
        self.emit("MARK", label=label)


class IRBuilder:
    """Lowers an AST chunk into a list of IR prototypes."""

    def __init__(self, source: str = "", target: str = "lua51") -> None:
        self.source = source
        self.target = target
        self.protos: List[IRProto] = []
        self._param_names: Dict[int, List[str]] = {}
        self._ctx: Optional[_FuncCtx] = None

    # ------------------------------------------------------------------
    # entry point
    # ------------------------------------------------------------------

    def build(self, chunk: Chunk) -> IRProto:
        proto = self._new_proto("<main>", 0, True, 1)
        self._param_names[proto.proto_id] = []
        ctx = _FuncCtx(self, proto, None)
        self._ctx = ctx
        try:
            self._emit_block(chunk.body, ctx)
        finally:
            self._ctx = None
        ctx.emit("RETURN", 0, 0)
        proto.resolve_labels()
        return proto

    def _new_proto(self, name: str, params: int, is_vararg: bool, line: int) -> IRProto:
        proto = IRProto(
            proto_id=len(self.protos),
            name=name,
            params=params,
            is_vararg=is_vararg,
            maxstack=params,
            line=line,
        )
        self.protos.append(proto)
        return proto

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------

    def _err(self, message: str, node: Optional[Node]) -> IRLoweringError:
        if node is not None and node.loc:
            loc = SourceLocation(node.loc[0], node.loc[1])
        else:
            loc = SourceLocation(0, 0)
        return IRLoweringError(message, loc)

    def _const(self, ctx: _FuncCtx, value: object) -> int:
        expected = value
        for i, c in enumerate(ctx.proto.constants):
            if self._c_eq(c, expected):
                return i
        ctx.proto.constants.append(expected)
        return len(ctx.proto.constants) - 1

    @staticmethod
    def _c_eq(a, b) -> bool:
        if isinstance(a, float) and isinstance(b, float):
            return a == b
        return type(a) is type(b) and a == b

    def _is_multivalue(self, node: Node) -> bool:
        if isinstance(node, (Vararg, MethodCall)):
            return True
        if isinstance(node, Call):
            return not node.operand_single
        return False

    def _resolve_var(self, name: str, ctx: _FuncCtx) -> _VarRef:
        r = ctx.local_reg(name)
        if r is not None:
            return _VarRef("local", r)
        u = ctx.capture_upvalue(name)
        if u is not None:
            return _VarRef("upval", u)
        return _VarRef("global", self._const(ctx, name))

    def _emit_load(self, dst: int, ref: _VarRef, ctx: _FuncCtx) -> None:
        if ref.kind == "local":
            ctx.emit("MOVE", dst, ref.index)
        elif ref.kind == "upval":
            ctx.emit("GETUPVAL", dst, ref.index)
        else:
            ctx.emit("LOADGLOBAL", dst, ref.index)

    def _emit_store(self, ref: _VarRef, src: int, ctx: _FuncCtx) -> None:
        if ref.kind == "local":
            ctx.emit("MOVE", ref.index, src)
        elif ref.kind == "upval":
            ctx.emit("SETUPVAL", src, ref.index)
        else:
            ctx.emit("STOREGLOBAL", src, ref.index)

    # ------------------------------------------------------------------
    # statements
    # ------------------------------------------------------------------

    def _emit_block(self, stmts: List[Node], ctx: _FuncCtx) -> None:
        for stmt in stmts:
            self._emit_stmt(stmt, ctx)

    def _emit_stmt(self, node: Node, ctx: _FuncCtx) -> None:
        if isinstance(node, Local):
            self._emit_local(node, ctx)
        elif isinstance(node, LocalFunction):
            self._emit_local_function(node, ctx)
        elif isinstance(node, GlobalFunction):
            self._emit_global_function(node, ctx)
        elif isinstance(node, Assignment):
            self._emit_assign(node, ctx)
        elif isinstance(node, CompoundAssign):
            self._emit_compound_assign(node, ctx)
        elif isinstance(node, If):
            self._emit_if(node, ctx)
        elif isinstance(node, While):
            self._emit_while(node, ctx)
        elif isinstance(node, Repeat):
            self._emit_repeat(node, ctx)
        elif isinstance(node, NumericFor):
            self._emit_numeric_for(node, ctx)
        elif isinstance(node, GenericFor):
            self._emit_generic_for(node, ctx)
        elif isinstance(node, Return):
            self._emit_return(node, ctx)
        elif isinstance(node, Break):
            self._emit_break(node, ctx)
        elif isinstance(node, ContinueMarker):
            self._emit_continue(node, ctx)
        elif isinstance(node, Chunk):
            self._emit_block(node.body, ctx)
        elif isinstance(node, (Call, MethodCall)):
            self._emit_call_expr(node, ctx, mode=0)
        else:
            raise self._err(
                f"attempted to lower unsupported statement node {type(node).__name__}.",
                node,
            )

    def _emit_local(self, node: Local, ctx: _FuncCtx) -> None:
        # Evaluate all initializers first (Lua: RHS is evaluated before the
        # new locals come into scope), then declare-and-assign in order.
        list_vals = self._emit_rhs_list(node.values, ctx)
        for i, name in enumerate(node.names):
            r = ctx.declare_local(name)
            entry = list_vals[i] if i < len(list_vals) else None
            self._emit_store_to_reg(r, entry, ctx)
        self._free_list(list_vals, ctx)

    def _emit_store_to_reg(self, dst: int, entry, ctx: _FuncCtx) -> None:
        if entry is None:
            ctx.emit("LOADNIL", dst)
        elif isinstance(entry, int):
            ctx.emit("MOVE", dst, entry)
        else:
            ctx.emit("GETRET", dst, entry[1])

    def _emit_local_function(self, node: LocalFunction, ctx: _FuncCtx) -> None:
        r = ctx.declare_local(node.name)
        self._emit_closure_into(ctx, r, node.func)
        # do not free r: it is a live local

    def _emit_global_function(self, node: GlobalFunction, ctx: _FuncCtx) -> None:
        tmp = ctx.new_reg()
        child_id = self._lower_function(node.func, ctx)
        ctx.emit("CLOSURE", tmp, child_id)
        ref = _VarRef("global", self._const(ctx, node.name))
        self._emit_store(ref, tmp, ctx)
        ctx.free_reg(tmp)

    def _emit_closure_into(self, ctx: _FuncCtx, dst: int, func: FunctionDef) -> None:
        child_id = self._lower_function(func, ctx)
        ctx.emit("CLOSURE", dst, child_id)

    # ------------------------------------------------------------------
    # assignment
    # ------------------------------------------------------------------

    def _emit_assign(self, node: Assignment, ctx: _FuncCtx) -> None:
        prefixes = []
        for t in node.targets:
            if isinstance(t, Name):
                prefixes.append((t, None, None))
            elif isinstance(t, (Index, Field)):
                obj = self._eval_expr(self._index_obj(t), ctx, single=True)
                key = self._eval_expr(self._index_key(t), ctx, single=True)
                prefixes.append((t, obj, key))
            else:
                raise self._err(
                    f"attempted to lower unsupported assignment target {type(t).__name__}.",
                    t,
                )
        vals = self._emit_rhs_list(node.values, ctx)
        for i, (t, obj, key) in enumerate(prefixes):
            entry = vals[i] if i < len(vals) else None
            self._emit_store_target(t, entry, obj, key, ctx)
        self._free_list(vals, ctx)
        for _, obj, key in prefixes:
            if obj is not None:
                ctx.free_reg(obj)
            if key is not None:
                ctx.free_reg(key)

    def _emit_store_target(self, t, entry, obj, key, ctx: _FuncCtx) -> None:
        if isinstance(t, Name):
            ref = self._resolve_var(t.name, ctx)
            if entry is None:
                tmp = ctx.new_reg()
                ctx.emit("LOADNIL", tmp)
                self._emit_store(ref, tmp, ctx)
                ctx.free_reg(tmp)
            elif isinstance(entry, int):
                self._emit_store(ref, entry, ctx)
            else:
                tmp = ctx.new_reg()
                ctx.emit("GETRET", tmp, entry[1])
                self._emit_store(ref, tmp, ctx)
                ctx.free_reg(tmp)
        else:
            # Index / Field target
            if entry is None:
                tmp = ctx.new_reg()
                ctx.emit("LOADNIL", tmp)
                ctx.emit("SETTABLE", obj, key, tmp)
                ctx.free_reg(tmp)
            elif isinstance(entry, int):
                ctx.emit("SETTABLE", obj, key, entry)
            else:
                tmp = ctx.new_reg()
                ctx.emit("GETRET", tmp, entry[1])
                ctx.emit("SETTABLE", obj, key, tmp)
                ctx.free_reg(tmp)

    def _emit_compound_assign(self, node: CompoundAssign, ctx: _FuncCtx) -> None:
        t = node.targets[0]
        if not isinstance(t, Name):
            raise self._err(
                "compound assignment on an indexed target is not supported by "
                "Vault-Obf; assign to a plain variable instead.",
                node,
            )
        # node.values[0] already holds the expanded `name op rhs` expression.
        rhs = self._eval_expr(node.values[0], ctx, single=True)
        ref = self._resolve_var(t.name, ctx)
        self._emit_store(ref, rhs, ctx)
        ctx.free_reg(rhs)

    def _index_obj(self, t) -> Node:
        return t.obj

    def _index_key(self, t) -> Node:
        if isinstance(t, Index):
            return t.key
        return Literal(t.name)

    # ------------------------------------------------------------------
    # RHS list
    # ------------------------------------------------------------------

    def _emit_rhs_list(self, values: List[Node], ctx: _FuncCtx) -> List:
        """Evaluate an expression list.

        Returns entries: an ``int`` register for fixed values, or a tuple
        ``("res", j)`` for dynamic multi-value tail elements.
        """
        if not values:
            return []
        fixed = len(values)
        is_multi = self._is_multivalue(values[-1])
        if is_multi:
            fixed -= 1
        out = []
        for i in range(fixed):
            out.append(self._eval_expr(values[i], ctx, single=True))
        if is_multi:
            self._eval_expr(values[-1], ctx, single=False)
            for j in range(1, MULTI_CAP + 1):
                out.append(("res", j))
        return out

    def _free_list(self, list_vals, ctx: _FuncCtx) -> None:
        for entry in list_vals:
            if isinstance(entry, int):
                ctx.free_reg(entry)

    # ------------------------------------------------------------------
    # expressions
    # ------------------------------------------------------------------

    def _eval_expr(self, node: Node, ctx: _FuncCtx, single: bool = True):
        """Evaluate an expression.

        ``single=True`` returns a register holding exactly one value.
        ``single=False`` is allowed only for multi-value capable nodes; the
        value list is left in the runtime ``frame.res`` array.
        """
        if isinstance(node, Literal):
            r = ctx.new_reg()
            if node.value is None:
                ctx.emit("LOADNIL", r)
            elif node.value is True:
                ctx.emit("LOADBOOL", r, 1)
            elif node.value is False:
                ctx.emit("LOADBOOL", r, 0)
            else:
                k = self._const(ctx, node.value)
                ctx.emit("LOADCONST", r, k)
            return r
        if isinstance(node, Name):
            r = ctx.new_reg()
            ref = self._resolve_var(node.name, ctx)
            self._emit_load(r, ref, ctx)
            return r
        if isinstance(node, Paren):
            # Parentheses always yield exactly one value (Lua 5.1 truncation).
            return self._eval_expr(node.expr, ctx, single=True)
        if isinstance(node, IfExpr):
            return self._emit_if_expr(node, ctx)
        if isinstance(node, Vararg):
            if single:
                r = ctx.new_reg()
                ctx.emit("VARARG", r, 1)
                return r
            ctx.emit("VARARG", 0, 0)
            return None
        if isinstance(node, UnaryOp):
            r = ctx.new_reg()
            a = self._eval_expr(node.operand, ctx, single=True)
            if node.op == "-":
                ctx.emit("NEG", r, a)
            elif node.op == "not":
                ctx.emit("NOT", r, a)
            elif node.op == "#":
                ctx.emit("LEN", r, a)
            else:
                raise self._err(f"unsupported unary operator '{node.op}'.", node)
            ctx.free_reg(a)
            return r
        if isinstance(node, BinaryOp):
            r = ctx.new_reg()
            a = self._eval_expr(node.left, ctx, single=True)
            b = self._eval_expr(node.right, ctx, single=True)
            self._emit_binop(ctx, node.op, r, a, b)
            ctx.free_reg(a)
            ctx.free_reg(b)
            return r
        if isinstance(node, (Call, MethodCall)):
            if single:
                r = ctx.new_reg()
                self._emit_call_expr(node, ctx, mode=1, dst=r)
                return r
            if isinstance(node, Call) and node.operand_single:
                raise self._err(
                    "internal: suffix calls cannot be multi-value.",
                    node,
                )
            self._emit_call_expr(node, ctx, mode=2)
            return None
        if isinstance(node, (Index, Field)):
            r = ctx.new_reg()
            obj = self._eval_expr(self._index_obj(node), ctx, single=True)
            key = self._eval_expr(self._index_key(node), ctx, single=True)
            ctx.emit("GETTABLE", r, obj, key)
            ctx.free_reg(obj)
            ctx.free_reg(key)
            return r
        if isinstance(node, Table):
            return self._emit_table(node, ctx)
        if isinstance(node, FunctionDef):
            r = ctx.new_reg()
            self._emit_closure_into(ctx, r, node)
            return r
        raise self._err(
            f"attempted to lower unsupported expression node {type(node).__name__}.",
            node,
        )

    def _emit_binop(self, ctx: _FuncCtx, op: str, dst: int, a: int, b: int) -> None:
        simple = {
            "+": "ADD", "-": "SUB", "*": "MUL", "/": "DIV",
            "%": "MOD", "^": "POW", "..": "CONCAT", "//": "EDIV",
        }
        if op in simple:
            ctx.emit(simple[op], dst, a, b)
        elif op == "==":
            ctx.emit("EQ", dst, a, b)
        elif op == "~=":
            ctx.emit("EQ", dst, a, b)
            ctx.emit("NOT", dst, dst)
        elif op == "<":
            ctx.emit("LT", dst, a, b)
        elif op == ">":
            ctx.emit("LT", dst, b, a)
        elif op == "<=":
            ctx.emit("LE", dst, a, b)
        elif op == ">=":
            ctx.emit("LE", dst, b, a)
        elif op in ("and", "or"):
            ctx.emit("MOVE", dst, a)
            end = _Label("andor")
            if op == "and":
                ctx.emit("JMPIFFALSE", dst, 0, 0, end, 0)
            else:
                ctx.emit("JMPIFTRUE", dst, 0, 0, end, 0)
            ctx.emit("MOVE", dst, b)
            ctx.mark(end)
        else:
            raise self._err(f"unsupported binary operator '{op}'.", None)

    def _emit_if_expr(self, node: IfExpr, ctx: _FuncCtx) -> int:
        """Lower a Luau ``if c then a elseif c2 then b else d`` expression.

        Conditions are evaluated in order and short-circuit.  Every branch
        writes its (single) value into the destination register; the last
        branch has no condition and is reached when all conditions fail.  The
        whole construct yields exactly one value, matching Luau semantics.
        """
        branches = node.branches
        n = len(branches)
        dst = ctx.new_reg()
        labs = [_Label("ifx") for _ in branches]
        end = _Label("ifx_end")
        for i, br in enumerate(branches):
            # Mark the branch label before its dispatch: a false condition
            # from an earlier branch must land on this branch's own condition
            # evaluation, not skip straight into its body.
            ctx.mark(labs[i])
            if br.cond is not None:
                c = self._eval_expr(br.cond, ctx, single=True)
                ctx.emit("JMPIFFALSE", c, 0, 0, labs[min(i + 1, n - 1)], 0)
                ctx.free_reg(c)
            val = self._eval_expr(br.body[0], ctx, single=True)
            ctx.emit("MOVE", dst, val)
            ctx.free_reg(val)
            if i < n - 1:
                ctx.emit("JMP", 0, 0, 0, end, 0)
        ctx.mark(end)
        return dst

    # ------------------------------------------------------------------
    # calls
    # ------------------------------------------------------------------

    def _emit_call_expr(self, node, ctx: _FuncCtx, mode: int, dst: int = 0) -> None:
        """Emit a call.

        ``mode``: 0 = discard, 1 = single, 2 = multi.
        """
        if isinstance(node, MethodCall):
            o = self._eval_expr(node.obj, ctx, single=True)
            f = ctx.new_reg()
            km = self._const(ctx, node.method)
            kreg = ctx.new_reg()
            ctx.emit("LOADCONST", kreg, km)
            ctx.emit("GETTABLE", f, o, kreg)
            ctx.free_reg(kreg)
            # build argument block: self + evaluated args
            nargs = 1 + len(node.args)
            block = ctx.alloc_block(nargs)
            ctx.emit("MOVE", block, o)
            for i, arg in enumerate(node.args):
                atmp = self._eval_expr(arg, ctx, single=True)
                ctx.emit("MOVE", block + 1 + i, atmp)
                ctx.free_reg(atmp)
            ctx.emit("CALL", f, block, nargs, dst, mode)
            ctx.free_reg(f)
            ctx.free_reg(o)
            return
        func = self._eval_expr(node.func, ctx, single=True)
        nargs = len(node.args)
        tail_rest = False
        if nargs > 0 and self._is_multivalue(node.args[-1]):
            fixed = nargs - 1
            block = ctx.alloc_block(fixed)
            for i in range(fixed):
                atmp = self._eval_expr(node.args[i], ctx, single=True)
                ctx.emit("MOVE", block + i, atmp)
                ctx.free_reg(atmp)
            self._eval_expr(node.args[-1], ctx, single=False)
            nargs = fixed
            tail_rest = True
        else:
            block = ctx.alloc_block(nargs)
            for i in range(nargs):
                atmp = self._eval_expr(node.args[i], ctx, single=True)
                ctx.emit("MOVE", block + i, atmp)
                ctx.free_reg(atmp)
        eff_mode = mode + (3 if tail_rest else 0)
        ctx.emit("CALL", func, block, nargs, dst, eff_mode)
        ctx.free_reg(func)

    # ------------------------------------------------------------------
    # tables
    # ------------------------------------------------------------------

    def _emit_table(self, node: Table, ctx: _FuncCtx) -> int:
        t = ctx.new_reg()
        ctx.emit("NEWTABLE", t)
        arr = 1
        n = len(node.entries)
        for i, entry in enumerate(node.entries):
            if entry.key is None:
                k = float(arr)
                if i == n - 1 and self._is_multivalue(entry.value):
                    self._eval_expr(entry.value, ctx, single=False)
                    for j in range(1, MULTI_CAP + 1):
                        tmp = ctx.new_reg()
                        ctx.emit("GETRET", tmp, j)
                        kk = self._const(ctx, float(arr))
                        kreg = ctx.new_reg()
                        ctx.emit("LOADCONST", kreg, kk)
                        ctx.emit("SETTABLE", t, kreg, tmp)
                        ctx.free_reg(kreg)
                        ctx.free_reg(tmp)
                        arr += 1
                else:
                    v = self._eval_expr(entry.value, ctx, single=True)
                    kk = self._const(ctx, k)
                    kreg = ctx.new_reg()
                    ctx.emit("LOADCONST", kreg, kk)
                    ctx.emit("SETTABLE", t, kreg, v)
                    ctx.free_reg(kreg)
                    ctx.free_reg(v)
                    arr += 1
            else:
                key = self._eval_expr(entry.key, ctx, single=True)
                v = self._eval_expr(entry.value, ctx, single=True)
                ctx.emit("SETTABLE", t, key, v)
                ctx.free_reg(key)
                ctx.free_reg(v)
        return t

    # ------------------------------------------------------------------
    # control flow
    # ------------------------------------------------------------------

    def _emit_if(self, node: If, ctx: _FuncCtx) -> None:
        end = _Label("if_end")
        labels: List[_Label] = []
        for i in range(len(node.branches)):
            labels.append(_Label(f"elif_{i}"))
        for i, branch in enumerate(node.branches):
            # The branch label is marked *before* its dispatch code so that a
            # false condition from the previous branch lands exactly on this
            # branch's own evaluation (and own dispatch), not on its body.
            ctx.mark(labels[i])
            if branch.cond is not None:
                c = self._eval_expr(branch.cond, ctx, single=True)
                target = labels[i + 1] if i + 1 < len(node.branches) else end
                ctx.emit("JMPIFFALSE", c, 0, 0, target, 0)
                ctx.free_reg(c)
            if isinstance(branch.body, list):
                ctx.enter_scope()
                self._emit_block(branch.body, ctx)
                ctx.exit_scope()
            else:
                self._emit_stmt(branch.body, ctx)
            if branch.cond is not None or i < len(node.branches) - 1:
                ctx.emit("JMP", 0, 0, 0, end, 0)
        ctx.mark(end)

    def _emit_while(self, node: While, ctx: _FuncCtx) -> None:
        head = _Label("while_head")
        exit = _Label("while_exit")
        ctx.mark(head)
        c = self._eval_expr(node.cond, ctx, single=True)
        ctx.emit("JMPIFFALSE", c, 0, 0, exit, 0)
        ctx.free_reg(c)
        loop = _LoopCtx(head, exit, head)
        ctx.loops.append(loop)
        try:
            ctx.enter_scope()
            self._emit_block(node.body, ctx)
            ctx.exit_scope()
        finally:
            ctx.loops.pop()
        ctx.emit("JMP", 0, 0, 0, head, 0)
        ctx.mark(exit)

    def _emit_repeat(self, node: Repeat, ctx: _FuncCtx) -> None:
        head = _Label("repeat_head")
        exit = _Label("repeat_exit")
        cont = _Label("repeat_cont")
        ctx.mark(head)
        loop = _LoopCtx(head, exit, cont)
        ctx.loops.append(loop)
        try:
            ctx.enter_scope()
            self._emit_block(node.body, ctx)
            # continue jumps here (before condition evaluation)
            ctx.mark(cont)
            c = self._eval_expr(node.cond, ctx, single=True)
            ctx.emit("JMPIFFALSE", c, 0, 0, head, 0)
            ctx.free_reg(c)
            ctx.exit_scope()
        finally:
            ctx.loops.pop()
        ctx.mark(exit)

    def _emit_numeric_for(self, node: NumericFor, ctx: _FuncCtx) -> None:
        var = ctx.declare_local(node.var)
        lim = ctx.new_reg()
        step = ctx.new_reg()
        s = self._eval_expr(node.start, ctx, single=True)
        ctx.emit("MOVE", var, s)
        ctx.free_reg(s)
        l = self._eval_expr(node.limit, ctx, single=True)
        ctx.emit("MOVE", lim, l)
        ctx.free_reg(l)
        if node.step is not None:
            st = self._eval_expr(node.step, ctx, single=True)
            ctx.emit("MOVE", step, st)
            ctx.free_reg(st)
        else:
            ctx.emit("LOADCONST", step, self._const(ctx, 1.0))
        test = _Label("for_test")
        exit = _Label("for_exit")
        inc = _Label("for_inc")
        ctx.mark(test)
        # FCHECK var,lim,step branches to exit when out of range
        ctx.emit("FCHECK", var, lim, step, exit, 0)
        loop = _LoopCtx(test, exit, inc)
        ctx.loops.append(loop)
        try:
            ctx.enter_scope()
            self._emit_block(node.body, ctx)
            ctx.exit_scope()
        finally:
            ctx.loops.pop()
        ctx.mark(inc)
        ctx.emit("FADD", var, step)
        ctx.emit("JMP", 0, 0, 0, test, 0)
        ctx.mark(exit)
        ctx.free_reg(lim)
        ctx.free_reg(step)

    def _emit_generic_for(self, node: GenericFor, ctx: _FuncCtx) -> None:
        fname = self._new_internal_name("it")
        sname = self._new_internal_name("st")
        f = ctx.declare_local(fname)
        s = ctx.declare_local(sname)
        # evaluate explist into f, s, control
        vals = self._emit_rhs_list(node.exprs, ctx)
        self._emit_list_entry(f, vals, 0, ctx)
        self._emit_list_entry(s, vals, 1, ctx)
        var_regs = []
        for name in node.names:
            r = ctx.declare_local(name)
            var_regs.append(r)
        # the first loop variable doubles as the control value; seed it from
        # the explist's third result (f, s, var) or clear it explicitly so a
        # reused scratch register cannot leak a stale value into the first
        # iterator call.
        self._emit_list_entry(var_regs[0], vals, 2, ctx)
        # free the values list
        self._free_list(vals, ctx)
        # Luau generalized iteration: `for v in x` accepts tables and strings
        # directly.  Normalise the (f, s, var) triple so a plain value is
        # expanded to a real iterator before the loop head is entered.
        if self.target == "luau":
            self._emit_gfor_normalize(ctx, f, s, var_regs[0])
        # force the private locals to stay allocated
        head = _Label("gfor_head")
        exit = _Label("gfor_exit")
        ctx.mark(head)
        # call f(s, var)
        block = ctx.alloc_block(2)
        ctx.emit("MOVE", block, s)
        ctx.emit("MOVE", block + 1, var_regs[0])
        tmp = ctx.new_reg()
        ctx.emit("CALL", f, block, 2, tmp, 2)
        ctx.emit("JMPIFFALSE", tmp, 0, 0, exit, 0)
        ctx.emit("MOVE", var_regs[0], tmp)
        for i in range(1, len(var_regs)):
            # first iterator return is the control key (loop var 0); every
            # further loop variable copies the i-th *following* return value.
            ctx.emit("GETRET", var_regs[i], i + 1)
        ctx.free_reg(tmp)
        loop = _LoopCtx(head, exit, head)
        ctx.loops.append(loop)
        try:
            ctx.enter_scope()
            self._emit_block(node.body, ctx)
            ctx.exit_scope()
        finally:
            ctx.loops.pop()
        ctx.emit("JMP", 0, 0, 0, head, 0)
        ctx.mark(exit)

    def _emit_gfor_normalize(self, ctx: _FuncCtx, f: int, s: int, v0: int) -> None:
        """Expand ``for`` iterable values for the Luau target.

        After the explicit triple ``(f, s, var)`` is materialised, ``f`` is
        still the *value* in Luau when the program wrote ``for v in value``
        (e.g. a table from ``GetChildren()`` or a string).  This pass rewrites
        ``f`` to a real iterator when it holds a table or a string:

        * table  -> ``f = next``, ``s = table``, ``var = nil``
        * string -> a stateful closure that yields ``s:sub(i, i)`` one
          character per call

        ``__iter`` metamethod expansion and userdata iteration are not
        supported and keep the stock 5.1 behaviour (a call-time error), which
        is documented in the target notes.
        """
        t = ctx.new_reg()
        l_tbl = _Label("gfor_tbl")
        l_str = _Label("gfor_str")
        l_done = _Label("gfor_done")
        ctx.emit("ISTBL", t, f)
        ctx.emit("JMPIFTRUE", t, 0, 0, l_tbl, 0)
        ctx.emit("ISTRG", t, f)
        ctx.emit("JMPIFTRUE", t, 0, 0, l_str, 0)
        ctx.emit("JMP", 0, 0, 0, l_done, 0)
        # table path: next(t, nil)
        ctx.mark(l_tbl)
        ctx.emit("MOVE", s, f)
        ctx.emit("LOADGLOBAL", f, self._const(ctx, "next"))
        ctx.emit("LOADNIL", v0)
        ctx.emit("JMP", 0, 0, 0, l_done, 0)
        # string path: a fresh, stateful char iterator for this loop entry.
        ctx.mark(l_str)
        self._emit_string_iter(ctx, f, s)
        ctx.emit("LOADNIL", v0)
        ctx.mark(l_done)
        ctx.free_reg(t)

    def _emit_string_iter(self, ctx: _FuncCtx, f: int, s: int) -> None:
        """Emit a stateful character iterator bound to the string in ``s``.

        ``s`` stays the iteration-state argument (the generic-for protocol
        calls ``f(state, control)``); the character index is kept in a fresh
        local of the enclosing frame and advanced by the iterator closure,
        which the protocol supplies as a new closure for each loop entry.
        """
        si = self._new_internal_name("stri")
        si_reg = ctx.declare_local(si)
        # si = 0  (fresh counter for this loop entry)
        ctx.emit("LOADCONST", si_reg, self._const(ctx, 0.0))
        # `s` is handed to the generic-for protocol as the state argument; the
        # iterable string currently lives in `f`, so copy it over before `f`
        # is replaced by the iterator closure.
        ctx.emit("MOVE", s, f)
        func = self._string_iter_ast(si, self._new_internal_name("ss"), self._new_internal_name("tt"))
        proto_id = self._lower_function(func, ctx)
        ch = ctx.new_reg()
        ctx.emit("CLOSURE", ch, proto_id)
        ctx.emit("MOVE", f, ch)
        ctx.free_reg(ch)

    def _string_iter_ast(self, si: str, ss: str, tt: str) -> FunctionDef:
        """AST for the string-iteration helper prototype.

        ``function(ss, tt)
             si = si + 1
             if si <= #ss then return ss:sub(si, si) end
           end``

        ``si`` is an upvalue of the enclosing frame (declared by
        ``_emit_string_iter``); ``ss``/``tt`` shadow nothing because they use
        fresh internal names the user cannot reference.  The iterator returns
        one character per call (``nil`` past the end), which is exactly Luau's
        string-iteration contract for single loop variables.
        """
        inc = Assignment(
            targets=[Name(si, loc=())],
            values=[BinaryOp(op="+", left=Name(si, loc=()), right=Literal(1.0, loc=()), loc=())],
            loc=(0, 0),
        )
        done = If(
            branches=[
                IfBranch(
                    cond=BinaryOp(
                        op="<=",
                        left=Name(si, loc=()),
                        right=UnaryOp(op="#", operand=Name(ss, loc=()), loc=()),
                        loc=(0, 0),
                    ),
                    body=[
                        Return(
                            values=[
                                MethodCall(
                                    obj=Name(ss, loc=()),
                                    method="sub",
                                    args=[Name(si, loc=()), Name(si, loc=())],
                                    loc=(0, 0),
                                )
                            ],
                            loc=(0, 0),
                        )
                    ],
                    loc=(0, 0),
                )
            ],
            loc=(0, 0),
        )
        return FunctionDef(
            params=[ss, tt],
            is_vararg=False,
            body=[inc, done],
            loc=(0, 0),
        )

    def _emit_list_entry(self, dst: int, vals: List, idx: int, ctx: _FuncCtx) -> None:
        entry = vals[idx] if idx < len(vals) else None
        if entry is None:
            ctx.emit("LOADNIL", dst)
        elif isinstance(entry, int):
            ctx.emit("MOVE", dst, entry)
        else:
            ctx.emit("GETRET", dst, entry[1])
        entry = vals[idx] if idx < len(vals) else None
        if entry is None:
            ctx.emit("LOADNIL", dst)
        elif isinstance(entry, int):
            ctx.emit("MOVE", dst, entry)
        else:
            ctx.emit("GETRET", dst, entry[1])

    _internal_counter = 0

    def _new_internal_name(self, base: str) -> str:
        self.__class__._internal_counter += 1
        return f"__vf_{base}_{self.__class__._internal_counter}"

    # ------------------------------------------------------------------
    # return / break / continue
    # ------------------------------------------------------------------

    def _emit_return(self, node: Return, ctx: _FuncCtx) -> None:
        if not node.values:
            ctx.emit("RETURN", 0, 0)
            return
        last = node.values[-1]
        if len(node.values) == 1 and self._is_multivalue(last):
            self._eval_expr(last, ctx, single=False)
            ctx.emit("RETURNDYN")
            return
        fixed = len(node.values)
        is_multi = self._is_multivalue(last)
        if is_multi:
            fixed -= 1
        block = ctx.alloc_block(fixed)
        for i in range(fixed):
            v = self._eval_expr(node.values[i], ctx, single=True)
            ctx.emit("MOVE", block + i, v)
            ctx.free_reg(v)
        if is_multi:
            self._eval_expr(last, ctx, single=False)
            ctx.emit("RETURNMIX", block, fixed, 1)
        else:
            ctx.emit("RETURN", block, fixed)

    def _emit_break(self, node: Break, ctx: _FuncCtx) -> None:
        if not ctx.loops:
            raise self._err("`break` outside of a loop.", node)
        ctx.emit("JMP", 0, 0, 0, ctx.loops[-1].exit, 0)

    def _emit_continue(self, node: ContinueMarker, ctx: _FuncCtx) -> None:
        if self.target != "luau":
            raise self._err(
                "continue is not supported by the Lua 5.1 target.",
                node,
            )
        if not ctx.loops:
            raise self._err("`continue` outside of a loop.", node)
        ctx.emit("JMP", 0, 0, 0, ctx.loops[-1].cont, 0)

    # ------------------------------------------------------------------
    # functions
    # ------------------------------------------------------------------

    def _lower_function(self, func: FunctionDef, parent: _FuncCtx) -> int:
        line = func.loc[0] if func.loc else 0
        proto = self._new_proto(func.name or "<anon>", len(func.params), func.is_vararg, line)
        self._param_names[proto.proto_id] = list(func.params)
        ctx = _FuncCtx(self, proto, parent)
        prev = self._ctx
        self._ctx = ctx
        try:
            ctx.enter_scope()
            self._emit_block(func.body, ctx)
            ctx.exit_scope()
        finally:
            self._ctx = prev
        ctx.emit("RETURN", 0, 0)
        proto.upvaldescs = list(ctx.upvals)
        proto.resolve_labels()
        if parent is not None:
            parent.proto.children.append(proto.proto_id)
        return proto.proto_id