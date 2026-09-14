"""Diagnostics reporting for the frontend."""

from __future__ import annotations

import textwrap
from typing import List, Optional

from vault import (
    LexerError,
    ParseError,
    SourceLocation,
    UnsupportedFeatureError,
)


class DiagnosticReporter:
    """Collects compiler diagnostics with excerpt formatting.

    The reporter knows the source text so it can build small excerpts for
    each reported location.
    """

    def __init__(self, source_text: str) -> None:
        self._source = source_text
        self._lines = source_text.splitlines()
        self.warnings: List[str] = []

    def line_text(self, line: int) -> Optional[str]:
        """Return the text of a 1-based line, if present."""
        if 1 <= line <= len(self._lines):
            return self._lines[line - 1]
        return None

    def _excerpt(self, line: int, column: int) -> Optional[str]:
        text = self.line_text(line)
        if text is None:
            return None
        # Build a caret line. Column is 1-based. Caret may run off the end.
        caret_col = min(column, len(text) + 1)
        caret = " " * (caret_col - 1) + "^"
        return f"{text}\n{caret}"

    def location(self, line: int, column: int) -> SourceLocation:
        return SourceLocation(line=line, column=column, excerpt=self._excerpt(line, column))

    def lex_error(self, message: str, line: int, column: int) -> LexerError:
        return LexerError(message, self.location(line, column))

    def parse_error(self, message: str, line: int, column: int) -> ParseError:
        return ParseError(message, self.location(line, column))

    def unsupported(
        self,
        message: str,
        line: int,
        column: int,
        target: str,
        suggestion: Optional[str] = None,
    ) -> UnsupportedFeatureError:
        full = message
        if suggestion:
            full = f"{message}\nSuggestion: {suggestion}"
        return UnsupportedFeatureError(full, self.location(line, column), stage=target)


class CompileError(Exception):
    """A wrapped compiler failure holding the first diagnostic error."""

    def __init__(self, error: Exception) -> None:
        super().__init__(str(error))
        self.error = error