"""Recursive-descent parser for Lua 5.1 and a supported Luau subset.

The parser consumes a :class:`~vault.frontend.lexer.Lexer` token stream and
produces a :class:`~vault.ast.nodes.Chunk` AST.  Target-dependent behaviour is
gated on the ``target`` field:

* ``lua51``: Luau-only syntax (type annotations, compound assignment,
  ``continue``, ``//``) is rejected with a diagnostic.
* ``luau``: the supported Luau subset is accepted; everything outside the
  subset is rejected with a precise error.
"""

from __future__ import annotations

from typing import List, Optional

from vault.ast.nodes import (
    Node,
    Literal,
    Name,
    Table,
    BinaryOp,
    UnaryOp,
    Call,
    MethodCall,
    Paren,
    Index,
    Field,
    FunctionDef,
    Assignment,
    Local,
    LocalFunction,
    GlobalFunction,
    If,
    IfBranch,
    While,
    Repeat,
    NumericFor,
    GenericFor,
    Return,
    Break,
    Vararg,
    TableEntry,
    Chunk,
    LuauTypeAnnotation,
    CompoundAssign,
)
from vault.frontend.diagnostics import DiagnosticReporter
from vault.frontend.lexer import Lexer, Token

BINOP_PRECEDENCE = {
    "or": 1,
    "and": 2,
    "<": 3,
    ">": 3,
    "<=": 3,
    ">=": 3,
    "~=": 3,
    "!=": 3,
    "==": 3,
    "|": 4,
    "~": 4,
    "&": 5,
    "<<": 6,
    ">>": 6,
    "..": 7,
    "+": 8,
    "-": 8,
    "*": 9,
    "/": 9,
    "//": 9,
    "%": 9,
    "^": 10,
}

UNARY_OPS = {"not", "-", "#"}

RIGHT_ASSOC = {"^", ".."}

COMPOUND_OPS = {
    "+=": "+", "-=": "-", "*=": "*", "/=": "/",
    "%=": "%", "^=": "^", "..=": "..",
}


class Parser:
    """Recursive-descent parser.

    Raises :class:`~vault.ParseError` (and related errors) on invalid input.
    """

    def __init__(
        self,
        source: str,
        target: str = "lua51",
        reporter: Optional[DiagnosticReporter] = None,
    ) -> None:
        reporter = reporter or DiagnosticReporter(source)
        lexer = Lexer(source, reporter)
        self.reporter = reporter
        self.tokens = lexer.tokenize()
        self.index = 0
        self.target = target
        self.source = source

    # -- token helpers ---------------------------------------------------

    def _peek(self, offset: int = 0) -> Token:
        i = min(self.index + offset, len(self.tokens) - 1)
        return self.tokens[i]

    def _advance(self) -> Token:
        tok = self._peek()
        if self.index < len(self.tokens) - 1:
            self.index += 1
        return tok

    def _check(self, kind: str) -> bool:
        return self._peek().kind == kind

    def _match(self, kind: str) -> Optional[Token]:
        if self._check(kind):
            return self._advance()
        return None

    def _expect(self, kind: str, what: str = "") -> Token:
        if self._check(kind):
            return self._advance()
        got = self._peek().kind
        detail = f" (expected {what})" if what else ""
        if got == "eof":
            raise self.reporter.parse_error(
                f"unexpected end of file; expected '{kind}'{detail}",
                self._peek().line,
                self._peek().column,
            )
        raise self.reporter.parse_error(
            f"expected '{kind}'{detail}, found '{got}'",
            self._peek().line,
            self._peek().column,
        )

    def _err_here(self, message: str):
        tok = self._peek()
        return self.reporter.parse_error(message, tok.line, tok.column)

    def _loc(self, tok: Token):
        return (tok.line, tok.column)

    def _luau_only(self) -> bool:
        return self.target == "luau"

    def _reject_luau_syntax(self, feature: str, suggestion: str = "") -> None:
        tok = self._peek()
        msg = f"{feature} is Luau-only syntax and is not supported by target 'lua51'."
        if suggestion:
            msg = f"{msg}\nSuggestion: {suggestion}"
        raise self.reporter.unsupported(msg, tok.line, tok.column, "lua51")

    def _reject_unsupported_luau(self, feature: str, line: int, col: int, suggestion: str = "") -> None:
        msg = f"{feature} is not currently supported by Vault-Obf."
        if suggestion:
            msg = f"{msg}\nSuggestion: {suggestion}"
        raise self.reporter.unsupported(msg, line, col, "luau")

    # -- entry point -----------------------------------------------------

    def parse(self) -> Chunk:
        chunk = Chunk()
        while not self._check("eof"):
            if self._check(";") or self._check("comment"):
                self._advance()
                continue
            if self._check("return"):
                r = self._parse_return_stmt()
                chunk.body.append(r)
                self._skip_after_return()
                break
            chunk.body.append(self._parse_statement())
            self._skip_terminators()
        return chunk

    def _skip_terminators(self) -> None:
        while self._check(";") or self._check("comment"):
            self._advance()

    def _skip_after_return(self) -> None:
        """Consume any tokens remaining after a top-level return."""
        while not self._check("eof"):
            self._advance()

    def _parse_return_stmt(self) -> Return:
        tok = self._advance()  # 'return'
        r = Return(loc=self._loc(tok))
        if self._check(";") or self._check("eof") or self._check("end") or self._check("until") or self._check("else") or self._check("elseif"):
            return r
        r.values = self._parse_exprlist()
        return r

    # -- statements ------------------------------------------------------

    def _parse_statement(self) -> Node:
        tok = self._peek()
        k = tok.kind
        if k == "if":
            return self._parse_if()
        if k == "while":
            return self._parse_while()
        if k == "repeat":
            return self._parse_repeat()
        if k == "for":
            return self._parse_for()
        if k == "do":
            self._advance()
            body = self._parse_block_until("end")
            self._expect("end")
            branch = IfBranch(cond=Literal(True), body=body, loc=self._loc(tok))
            return If(branches=[branch], loc=self._loc(tok))
        if k == "function":
            self._advance()
            return self._parse_function_statement_after_keyword(tok)
        if k == "local":
            return self._parse_local_statement()
        if k == "break":
            self._advance()
            return Break(loc=self._loc(tok))
        if k == "return":
            return self._parse_return_stmt()
        if k == "continue" or (
            self._luau_only()
            and k == "ident"
            and tok.value == "continue"
            and self._peek(1).kind
            not in ("=", "(", ".", "[", ":", ",", "{", "string", "long-string")
        ):
            if not self._luau_only():
                self._reject_luau_syntax(
                    "`continue` statement",
                    "rephrase the loop to avoid `continue`, or target Luau.",
                )
            self._advance()
            from vault.ast.nodes import _make_continue_marker
            return _make_continue_marker(self._loc(tok))
        if k in ("export", "declare", "type"):
            self._reject_luau_syntax(
                f"`{k}` construct",
                "remove type declarations/export statements or target Luau.",
            )
        return self._parse_assignment_or_call()

    def _parse_if(self) -> If:
        tok = self._advance()  # 'if'
        branches = []
        cond = self._parse_expr()
        self._expect("then")
        body = self._parse_block_until("elseif", "else", "end")
        branches.append(IfBranch(cond=cond, body=body, loc=self._loc(tok)))
        while self._check("elseif"):
            self._advance()
            c = self._parse_expr()
            self._expect("then")
            b = self._parse_block_until("elseif", "else", "end")
            branches.append(IfBranch(cond=c, body=b, loc=self._loc(tok)))
        if self._check("else"):
            self._advance()
            b = self._parse_block_until("end")
            branches.append(IfBranch(cond=None, body=b, loc=self._loc(tok)))
        self._expect("end")
        return If(branches=branches, loc=self._loc(tok))

    def _parse_while(self) -> While:
        tok = self._advance()
        cond = self._parse_expr()
        self._expect("do")
        body = self._parse_block_until("end")
        self._expect("end")
        return While(cond=cond, body=body, loc=self._loc(tok))

    def _parse_repeat(self) -> Repeat:
        tok = self._advance()
        body = self._parse_block_until("until")
        self._expect("until")
        cond = self._parse_expr()
        return Repeat(body=body, cond=cond, loc=self._loc(tok))

    def _parse_for(self) -> Node:
        tok = self._advance()
        name_tok = self._expect("ident", "loop variable name")
        if self._match("="):
            start = self._parse_expr()
            self._expect(",")
            limit = self._parse_expr()
            step = None
            if self._match(","):
                step = self._parse_expr()
            self._expect("do")
            body = self._parse_block_until("end")
            self._expect("end")
            return NumericFor(var=name_tok.value, start=start, limit=limit, step=step, body=body, loc=self._loc(tok))
        names = [name_tok.value]
        while self._match(","):
            nm = self._expect("ident", "loop variable name")
            names.append(nm.value)
        self._expect("in")
        exprs = self._parse_exprlist()
        self._expect("do")
        body = self._parse_block_until("end")
        self._expect("end")
        return GenericFor(names=names, exprs=exprs, body=body, loc=self._loc(tok))

    def _parse_function_statement_after_keyword(self, tok: Token) -> Node:
        """After consuming ``function``, handles ``function name(...)``."""
        name_tok = self._expect("ident", "function name")
        parts = [name_tok.value]
        while self._match("."):
            nxt = self._expect("ident", "field name")
            parts.append(nxt.value)
        func = self._parse_function_sig()
        func.name = parts[-1]
        if len(parts) == 1:
            return GlobalFunction(name=parts[0], func=func, loc=self._loc(tok))
        # function a.b.c(...) => a.b.c = function(...) end
        target = Name(parts[0], loc=self._loc(name_tok))
        for p in parts[1:]:
            target = Field(obj=target, name=p, loc=self._loc(name_tok))
        return Assignment(targets=[target], values=[func], loc=self._loc(tok))

    def _parse_local_statement(self) -> Node:
        tok = self._advance()  # 'local'
        if self._check("function"):
            self._advance()
            name_tok = self._expect("ident", "local function name")
            func = self._parse_function_sig()
            func.name = name_tok.value
            return LocalFunction(name=name_tok.value, func=func, loc=self._loc(tok))
        names = []
        n0 = self._expect("ident", "local name")
        names.append(n0.value)
        while self._match(","):
            nm = self._expect("ident", "local name")
            names.append(nm.value)
        if self._check(":"):
            if not self._luau_only():
                self._reject_luau_syntax(
                    "type annotations (`local x: T`)",
                    "remove the annotation or target Luau.",
                )
            self._skip_type_annotation()
        values: List[Node] = []
        if self._match("="):
            values = self._parse_exprlist()
        return Local(names=names, values=values, loc=self._loc(tok))

    def _skip_type_annotation(self) -> None:
        """Consume a Luau type annotation `: Type`.

        We parse enough to skip safely ("soft" parsing).  Full type-packs and
        complex generics are rejected by the target validator at a later
        stage, so here we only need to skip compact, well-formed tokens.
        """
        # ':' already consumed
        depth = 0
        while True:
            k = self._peek().kind
            if k == "eof":
                break
            if depth == 0 and k in ("=", ",", ")", "do", "then", "end", ";", "}"):
                break
            if k in ("(", "{", "[", "<"):
                depth += 1
            elif k in (")", "}", "]", ">"):
                if depth == 0:
                    break
                depth -= 1
            self._advance()

    def _parse_assignment_or_call(self) -> Node:
        first = self._parse_suffixed_expr()
        if isinstance(first, (Call, MethodCall)):
            return first
        targets = [first]
        while self._check(".") or self._check("["):
            if self._check("."):
                self._advance()
                name = self._expect("ident", "field name")
                targets.append(Field(obj=targets[-1], name=name.value, loc=self._loc(name)))
            else:
                self._advance()
                idx = self._parse_expr()
                self._expect("]")
                targets.append(Index(obj=targets[-1], key=idx, loc=self._loc(self._peek())))
        if self._check(","):
            # multi-assignment `a, b, ... = explist`
            while self._check(","):
                self._advance()
                t = self._parse_suffixed_expr()
                if isinstance(t, (Call, MethodCall)):
                    raise self.reporter.parse_error(
                        "cannot assign to a function call",
                        t.loc[0] if t.loc else 0,
                        t.loc[1] if t.loc else 0,
                    )
                while self._check(".") or self._check("["):
                    if self._check("."):
                        self._advance()
                        name = self._expect("ident", "field name")
                        t = Field(obj=t, name=name.value, loc=self._loc(name))
                    else:
                        self._advance()
                        idx = self._parse_expr()
                        self._expect("]")
                        t = Index(obj=t, key=idx, loc=self._loc(self._peek()))
                targets.append(t)
            self._expect("=")
            values = self._parse_exprlist()
            return Assignment(targets=targets, values=values, loc=first.loc or self._loc(self._peek()))
        compound = self._peek().kind in COMPOUND_OPS
        if compound:
            if not self._luau_only():
                self._reject_luau_syntax(
                    "compound assignment",
                    "expand to `a = a OP b` or target Luau.",
                )
            op_tok = self._advance()
            op = COMPOUND_OPS[op_tok.kind]
            if len(targets) != 1:
                self._reject_unsupported_luau(
                    "compound assignment on a multi-part target",
                    op_tok.line, op_tok.column,
                    "assign to a single variable instead.",
                )
            rhs = self._parse_expr()
            expanded = BinaryOp(op=op, left=first, right=rhs, loc=self._loc(op_tok))
            return CompoundAssign(op=op, targets=[first], values=[expanded], loc=self._loc(op_tok))
        if self._check("="):
            self._advance()
            values = self._parse_exprlist()
            for t in targets:
                if isinstance(t, (Call, MethodCall)):
                    raise self.reporter.parse_error(
                        "cannot assign to a function call",
                        t.loc[0] if t.loc else tok_safe(t, self._peek()).line,
                        t.loc[1] if t.loc else tok_safe(t, self._peek()).column,
                    )
            loc = first.loc or self._loc(first if hasattr(first, "kind") else self._peek())
            return Assignment(targets=targets, values=values, loc=loc)
        return targets[0]

    def _parse_function_sig(self) -> FunctionDef:
        self._expect("(")
        params = []
        is_vararg = False
        if not self._check(")"):
            while True:
                if self._check("..."):
                    self._advance()
                    is_vararg = True
                    if self._check(":"):
                        if not self._luau_only():
                            self._reject_luau_syntax(
                                "type annotations (`function(...: T)`)",
                                "remove the annotation or target Luau.",
                            )
                        self._advance()
                        self._skip_type_annotation()
                    break
                p = self._expect("ident", "parameter name")
                params.append(p.value)
                if self._check(":"):
                    if not self._luau_only():
                        self._reject_luau_syntax(
                            "type annotations (`function(x: T)`)",
                            "remove the annotation or target Luau.",
                        )
                    self._skip_type_annotation()
                if not self._match(","):
                    break
        self._expect(")")
        if self._check(":"):
            if not self._luau_only():
                self._reject_luau_syntax(
                    "function return type annotations (`function f(): T`)",
                    "remove the annotation or target Luau.",
                )
            self._advance()
            self._skip_type_annotation()
        body = self._parse_block_until("end")
        self._expect("end")
        return FunctionDef(params=params, is_vararg=is_vararg, body=body)

    def _parse_block_until(self, *stops: str) -> List[Node]:
        body: List[Node] = []
        while True:
            k = self._peek().kind
            if k in stops or k == "eof":
                break
            if k == ";":
                self._advance()
                continue
            if k == "comment":
                self._advance()
                continue
            if k == "return":
                body.append(self._parse_return_stmt())
                continue
            body.append(self._parse_statement())
            self._skip_terminators()
        return body

    # -- expressions -----------------------------------------------------

    def _parse_exprlist(self) -> List[Node]:
        exprs = [self._parse_expr()]
        while self._match(","):
            exprs.append(self._parse_expr())
        return exprs

    def _parse_expr(self) -> Node:
        return self._parse_binop(1)

    def _parse_binop(self, min_prec: int) -> Node:
        left = self._parse_unary()
        while True:
            op = self._peek()
            prec = BINOP_PRECEDENCE.get(op.kind)
            if prec is None or prec < min_prec:
                break
            self._advance()
            op_kind = op.kind
            if op_kind == "!=":
                if not self._luau_only():
                    self._reject_luau_syntax(
                        "the `!=` operator",
                        "use `~=` instead.",
                    )
                op_kind = "~="
            next_min = prec if op.kind in RIGHT_ASSOC else prec + 1
            right = self._parse_binop(next_min)
            left = BinaryOp(op=op_kind, left=left, right=right, loc=self._loc(op))
        return left

    def _parse_unary(self) -> Node:
        op = self._peek()
        if op.kind in UNARY_OPS:
            self._advance()
            operand = self._parse_unary()
            return UnaryOp(op=op.kind, operand=operand, loc=self._loc(op))
        return self._parse_suffixed_expr()

    def _parse_suffixed_expr(self) -> Node:
        prim = self._parse_primary()
        while True:
            k = self._peek().kind
            if k == ".":
                self._advance()
                name = self._expect("ident", "field name")
                prim = Field(obj=prim, name=name.value, loc=self._loc(name))
            elif k == "[":
                self._advance()
                idx = self._parse_expr()
                self._expect("]")
                prim = Index(obj=prim, key=idx, loc=self._loc(self._peek()))
            elif k == "(":
                self._advance()
                args = self._parse_call_args()
                prim = Call(func=prim, args=args, loc=self._loc(self._peek()))
            elif k == ":":
                self._advance()
                name = self._expect("ident", "method name")
                if self._check("("):
                    self._advance()
                    args = self._parse_call_args()
                else:
                    args = []
                method_call = MethodCall(obj=prim, method=name.value, args=args, loc=self._loc(name))
                prim = self._lower_method_call(method_call)
            elif k == "{" or k in ("string", "long-string"):
                # sugar call: f"str" or f{...}
                if k in ("string", "long-string"):
                    str_tok = self._advance()
                    arg = Literal(str_tok.value, loc=self._loc(str_tok))
                    prim = Call(func=prim, args=[arg], loc=self._loc(self._peek()))
                else:
                    self._advance()
                    tbl = self._parse_table()
                    prim = Call(func=prim, args=[tbl], loc=self._loc(self._peek()))
            else:
                break
        return prim

    def _lower_method_call(self, mc: MethodCall) -> Node:
        field = Field(obj=mc.obj, name=mc.method, loc=mc.loc)
        args = [mc.obj] + list(mc.args)
        return Call(func=field, args=args, loc=mc.loc)

    def _parse_call_args(self) -> List[Node]:
        args = []
        if self._check(")"):
            self._advance()
            return args
        while True:
            args.append(self._parse_expr())
            if not self._match(","):
                break
        self._expect(")")
        return args

    def _parse_primary(self) -> Node:
        tok = self._peek()
        k = tok.kind
        if k == "nil":
            self._advance()
            return Literal(None, loc=self._loc(tok))
        if k == "true":
            self._advance()
            return Literal(True, loc=self._loc(tok))
        if k == "false":
            self._advance()
            return Literal(False, loc=self._loc(tok))
        if k == "number":
            self._advance()
            return Literal(tok.value, loc=self._loc(tok))
        if k in ("string", "long-string"):
            self._advance()
            return Literal(tok.value, loc=self._loc(tok))
        if k == "ident":
            self._advance()
            return Name(tok.value, loc=self._loc(tok))
        if k == "function":
            self._advance()
            return self._parse_function_sig_after_keyword(tok)
        if k == "(":
            self._advance()
            inner = self._parse_expr()
            self._expect(")")
            return Paren(expr=inner, loc=self._loc(tok))
        if k == "{":
            self._advance()
            return self._parse_table()
        if k == "...":
            self._advance()
            return Vararg(loc=self._loc(tok))
        if k == "eof":
            raise self._err_here("unexpected end of file in expression")
        raise self._err_here(f"unexpected token '{k}' in expression")

    def _parse_function_sig_after_keyword(self, tok: Token) -> FunctionDef:
        return self._parse_function_sig()

    def _parse_table(self) -> Table:
        entries = []
        while not self._check("}"):
            if self._check("["):
                self._advance()
                key = self._parse_expr()
                self._expect("]")
                self._expect("=")
                val = self._parse_expr()
                entries.append(TableEntry(key=key, value=val, loc=self._loc(self._peek())))
            elif self._check("ident") and self._peek(1).kind == "=":
                name_tok = self._advance()
                self._match("=")
                val = self._parse_expr()
                entries.append(TableEntry(key=Literal(name_tok.value), value=val, loc=self._loc(self._peek())))
            else:
                val = self._parse_expr()
                entries.append(TableEntry(key=None, value=val, loc=self._loc(self._peek())))
            if not self._match(",") and not self._match(";"):
                if not self._check("}"):
                    raise self._err_here("expected ',' or '}' in table constructor")
        self._expect("}")
        return Table(entries=entries)


def tok_safe(node: Node, fallback: Token) -> Token:
    return fallback


def parse(source: str, target: str = "lua51", reporter: Optional[DiagnosticReporter] = None) -> Chunk:
    """Parse Lua/Luau ``source`` into a :class:`Chunk` AST."""
    return Parser(source, target, reporter).parse()