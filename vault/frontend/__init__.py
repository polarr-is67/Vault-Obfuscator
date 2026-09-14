"""Frontend package for Vault-Obf."""

from __future__ import annotations

from vault.frontend.diagnostics import DiagnosticReporter, CompileError


def parse_source(
    source: str,
    target: str = "lua51",
    filename: str = "",
) -> object:
    """Parse ``source`` for the given target and run target validation.

    Returns the parsed :class:`~vault.ast.nodes.Chunk`.  Raises
    :class:`~vault.VaultError` subclasses on invalid or unsupported input.
    """
    from vault.frontend.lexer import Lexer
    from vault.frontend.parser import Parser
    from vault.targets import TARGETS

    reporter = DiagnosticReporter(source)
    parser = Parser(source, target=target, reporter=reporter)
    chunk = parser.parse()
    if target in TARGETS:
        TARGETS[target]().validate(chunk, reporter)
    return chunk


__all__ = ["DiagnosticReporter", "CompileError", "parse_source"]