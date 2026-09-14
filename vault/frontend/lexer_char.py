"""Character-level constants shared by the lexer/parser."""

from __future__ import annotations

# Binary operators, ordered longest-first so tokenization is greedy.
OPERATORS = (
    "==", "~=", "<=", ">=", "..", "//=", "^=", "+=", "-=", "*=", "/=", "%=",
    "&=", "|=", "<<=", ">>=", "->", "::", "=>", "<<", ">>", "...",
    "+", "-", "*", "/", "%", "^", "#", "=", "~", "&", "|",
    "<", ">", "(", ")", "[", "]", "{", "}", ";", ":",
    ",", ".", "..",
)