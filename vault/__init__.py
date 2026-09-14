"""Vault-Obf error hierarchy.

All Vault-Obf errors derive from :class:`VaultError`. Each error carries a
stage name, an optional source location, and a human-readable message.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class SourceLocation:
    """A location within a source file.

    Attributes:
        line: 1-based line number.
        column: 1-based column number.
        excerpt: Optional snippet of the offending source line.
    """

    line: int
    column: int
    excerpt: Optional[str] = None

    def __str__(self) -> str:
        return f"line {self.line}, column {self.column}"


class VaultError(Exception):
    """Base error for all Vault-Obf errors."""

    stage: str = "vault-obf"

    def __init__(
        self,
        message: str,
        location: Optional[SourceLocation] = None,
        stage: Optional[str] = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.location = location
        if stage is not None:
            self.stage = stage

    def format(self) -> str:
        """Render a full multi-line diagnostic."""
        if self.location is not None:
            loc = f" at {self.location}"
            excerpt = f"\n  {self.location.excerpt}" if self.location.excerpt else ""
        else:
            loc = ""
            excerpt = ""
        return f"{self.stage} error{loc}:\n{self.message}{excerpt}"

    def __str__(self) -> str:
        return self.format()


class LexerError(VaultError):
    """Lexing error with line/column."""

    stage = "lexer"


class ParseError(VaultError):
    """Parsing error with line/column."""

    stage = "parser"


class UnsupportedFeatureError(VaultError):
    """Unsupported feature detected during target validation."""

    stage = "unsupported-feature"


class IRLoweringError(VaultError):
    """Error during AST-to-IR lowering."""

    stage = "IR lowering"


class BytecodeGenerationError(VaultError):
    """Error during bytecode generation."""

    stage = "bytecode generation"


class VMGenerationError(VaultError):
    """Error during VM runtime generation."""

    stage = "VM generation"


class OutputError(VaultError):
    """Error during output emission."""

    stage = "output generation"


class ConfigError(VaultError):
    """Configuration or CLI argument error."""

    stage = "config"


class FrontendInputError(VaultError):
    """Error raised for invalid frontend input (e.g. wrong target name)."""

    stage = "input validation"


class VerificationError(VaultError):
    """Error raised when output verification fails."""

    stage = "verification"