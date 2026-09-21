"""Lexer for Lua 5.1 / Luau.

Produces a stream of :class:`Token` objects.  The lexer is deliberately
target-agnostic for the token stream it produces; the parser decides how to
interpret Luau-only syntax.

Token kinds are simple strings:
    "ident", "number", "string", and the literal operators/keywords.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from vault import LexerError
from vault.frontend.diagnostics import DiagnosticReporter
from vault.frontend.lexer_char import OPERATORS

# Lua 5.1 keywords.
KEYWORDS = frozenset({
    "and", "break", "do", "else", "elseif", "end", "false",
    "for", "function", "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true", "until", "while",
})

# Luau-only keywords that conflict with Lua 5.1 identifier usage.
LUAU_KEYWORDS = frozenset({"continue", "type", "export", "declare"})

# Multi-character operators sorted longest-first so tokenization is greedy.
OPERATORS_LIST = sorted(OPERATORS, key=len, reverse=True)

# Characters that can start a name (plus underscore).
_NAME_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_NAME_CHARS = _NAME_START | set("0123456789")


@dataclass
class Token:
    """A single lexed token.

    Attributes:
        kind: Token kind (see class docstring).
        value: For ident/number/string tokens, the decoded value.
        line: 1-based line number.
        column: 1-based column number.
    """

    kind: str
    value: object
    line: int
    column: int

    def __repr__(self) -> str:
        return f"Token({self.kind!r}, {self.value!r}, {self.line}:{self.column})"


class Lexer:
    """A streaming tokenizer for Lua 5.1 + Luau source.

    Lua 5.1 keywords are tokenised as their literal text.  Identifiers that
    collide with Luau-only keywords (``continue``, ``type``, ``export``,
    ``declare``) are tokenised as identifiers; the parser decides how to
    treat them based on the active target.
    """

    def __init__(self, source: str, reporter: DiagnosticReporter) -> None:
        self.source = source
        self.reporter = reporter
        self.pos = 0
        self.line = 1
        self.col = 1
        self.n = len(source)

    # -- low-level character helpers ------------------------------------

    def _peek(self, offset: int = 0) -> str:
        i = self.pos + offset
        if i < self.n:
            return self.source[i]
        return ""

    def _peek2(self, offset: int = 0) -> str:
        i = self.pos + offset
        if i + 1 < self.n:
            return self.source[i : i + 2]
        return ""

    def _advance(self) -> str:
        c = self.source[self.pos]
        self.pos += 1
        if c == "\n":
            self.line += 1
            self.col = 1
        else:
            self.col += 1
        return c

    def _error(self, message: str) -> LexerError:
        return self.reporter.lex_error(message, self.line, self.col)

    # -- main tokeniser -------------------------------------------------

    def tokenize(self) -> List[Token]:
        tokens: List[Token] = []
        while self.pos < self.n:
            c = self._peek()
            if c in " \t\r\n":
                self._advance()
                continue
            if c == "-" and self._peek(1) == "-":
                tokens.append(self._lex_long_comment_or_line_comment())
                continue
            if c == "/" and self._peek(1) == "/" and self._is_luau_double_slash():
                # Luau floor division -- tokenised the same as a keyword operator.
                self._advance()
                self._advance()
                tokens.append(Token("//", "//", self.line, self.col - 2))
                continue
            if c == "[":
                br = self._lex_bracket_if_long()
                if br is None:
                    self._advance()
                    tokens.append(Token("[", "[", self.line, self.col - 1))
                else:
                    tokens.append(br)
                continue
            if c == '"' or c == "'":
                tokens.append(self._lex_quoted_string())
                continue
            if c == "`":
                raise self._error("interpolated strings are not supported by the lexer without Luau target")
            if c in _NAME_START:
                tokens.append(self._lex_name())
                continue
            if c.isdigit():
                tokens.append(self._lex_number())
                continue
            if c == "." and self._peek(1).isdigit():
                tokens.append(self._lex_number())
                continue
            op = self._match_operator()
            if op is not None:
                tokens.append(op)
                continue
            raise self._error(f"unexpected character {c!r}")
        tokens.append(Token("eof", "eof", self.line, self.col))
        return tokens

    def _is_luau_double_slash(self) -> bool:
        # ``//`` is Luau floor division; must not be interpreted as a comment
        # longer form.  The common Lua tokeniser treats ``--`` as comment;
        # ``//`` is safe to lex as an operator only when it is not ``//=``.
        if self._peek(2) == "=":
            return True
        nxt = self._peek(2)
        # A following `/` like `///` should remain ambiguous; treat as `//`.
        return nxt not in "=+"

    def _match_operator(self) -> Optional[Token]:
        for op in OPERATORS_LIST:
            if self.source.startswith(op, self.pos):
                start_line, start_col = self.line, self.col
                for _ in op:
                    self._advance()
                return Token(op, op, start_line, start_col)
        return None

    # -- comment handling -------------------------------------------------

    def _lex_long_comment_or_line_comment(self) -> Token:
        start_line, start_col = self.line, self.col
        self._advance()  # '-'
        self._advance()  # '-'
        # Distinguish long comment [=[..]=] or line comment.
        b = self._lex_bracket_if_long()
        if b is not None:
            # Long comment -> skip through closing brackets; ignore content.
            # b.kind == "long-open"? For simplicity, treat as a comment token
            # whose value is the raw comment text.  We already consumed it.
            return Token("comment", b.value, start_line, start_col)
        # Line comment: consume to end of line.
        while self.pos < self.n and self._peek() not in "\r\n":
            self._advance()
        return Token("comment", "", start_line, start_col)

    def _lex_bracket_if_long(self) -> Optional[Token]:
        """If source at ``[`` begins a long bracket ``[=*[``, consume it.

        Returns a ``comment`` or ``longopen``/``longclose`` token, or None if
        the bracketed expression is a plain ``[``.
        """
        if self._peek(0) != "[":
            return None
        save_pos, save_line, save_col = self.pos, self.line, self.col
        # consume '['
        self._advance()
        level = 0
        while self._peek() == "=":
            level += 1
            self._advance()
        if self._peek() != "[":
            # not a long bracket; rollback
            self.pos, self.line, self.col = save_pos, save_line, save_col
            return None
        self._advance()  # opening '['
        # At this point we're inside a long bracket of the given level.
        close = "]" + ("=" * level) + "]"
        # Consume content until closing delimiter.
        content = []
        while self.pos < self.n:
            if self.source.startswith(close, self.pos):
                for _ in close:
                    self._advance()
                return Token("long-string", "".join(content), save_line, save_col)
            if self._peek() == "\n":
                content.append("\n")
                self._advance()
                continue
            content.append(self._advance())
        raise self._error(f"unfinished long bracket (level {level})")

    # -- strings ----------------------------------------------------------

    def _lex_quoted_string(self) -> Token:
        start_line, start_col = self.line, self.col
        quote = self._advance()  # opening quote
        out: List[str] = []
        while self.pos < self.n:
            c = self._advance()
            if c == quote:
                return Token("string", "".join(out), start_line, start_col)
            if c == "\\":
                out.append(self._lex_escape())
                continue
            if c == "\n":
                raise self._error("unfinished string near newline")
            out.append(c)
        raise self._error("unfinished string")

    def _lex_escape(self) -> str:
        """Decode a backslash escape (after the backslash was already consumed)."""
        c = self._advance()
        simple = {
            "a": "\a", "b": "\b", "f": "\f", "n": "\n",
            "r": "\r", "t": "\t", "v": "\v", "\\": "\\",
            '"': '"', "'": "'", "\n": "", "\r": "",
        }
        if c in simple:
            return simple[c]
        if c == "x":
            hex_digits = ""
            for _ in range(2):
                if self._peek() and self._peek() in "0123456789abcdefABCDEF":
                    hex_digits += self._advance()
                else:
                    break
            if not hex_digits:
                raise self._error("invalid hex escape")
            return chr(int(hex_digits, 16))
        if c.isdigit():
            digits = [c]
            for _ in range(2):
                if self._peek().isdigit():
                    digits.append(self._advance())
                else:
                    break
            val = int("".join(digits))
            if val > 255:
                raise self._error("escape sequence out of range")
            return chr(val)
        if c == "u":
            raise self._error("unicode escapes not supported by Lua 5.1 string literals")
        raise self._error(f"invalid escape sequence \\{c}")

    # -- names ------------------------------------------------------------

    def _lex_name(self) -> Token:
        start_line, start_col = self.line, self.col
        chars = []
        while self.pos < self.n and self._peek() in _NAME_CHARS:
            chars.append(self._advance())
        name = "".join(chars)
        if name in KEYWORDS:
            return Token(name, name, start_line, start_col)
        return Token("ident", name, start_line, start_col)

    # -- numbers ----------------------------------------------------------

    def _lex_number(self) -> Token:
        start_line, start_col = self.line, self.col
        # Hex literal
        if self._peek() == "0" and self._peek(1) in ("x", "X"):
            self._advance()
            self._advance()
            digits = []
            while self.pos < self.n and self._peek() in "0123456789abcdefABCDEF":
                digits.append(self._advance())
            hexes = "".join(digits)
            if not hexes:
                raise self._error("malformed number (missing hex digits)")
            return Token("number", float(int(hexes, 16)), start_line, start_col)
        # Decimal
        int_part = []
        while self._peek().isdigit():
            int_part.append(self._advance())
        frac_part = []
        if self._peek() == "." and not self._is_dot_call_or_field_break():
            self._advance()  # consume '.'
            while self._peek().isdigit():
                frac_part.append(self._advance())
        exp_part = []
        if self._peek() in ("e", "E"):
            self._advance()
            if self._peek() in ("+", "-"):
                exp_part.append(self._advance())
            while self._peek().isdigit():
                exp_part.append(self._advance())
            if not any(d.isdigit() for d in exp_part):
                raise self._error("malformed number (missing exponent digits)")
        text = "".join(int_part)
        if frac_part:
            text = text + "." + "".join(frac_part)
        if exp_part:
            text = text + "e" + "".join(exp_part)
        try:
            value = float(text)
        except ValueError:
            raise self._error(f"malformed number {text!r}")
        return Token("number", value, start_line, start_col)

    def _is_dot_call_or_field_break(self) -> bool:
        # A '.' here could be: `1.5` (number continuation) vs `1 .. 2`.
        # We already consumed digits; a `.` is a numeric decimal point only
        # when followed by a digit and not part of `..`.
        return self._peek(1) == "."