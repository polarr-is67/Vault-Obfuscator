"""The end-to-end obfuscation pipeline.

``obfuscate`` is the only public entry point of the compiler.  It drives:

    frontend (lexer + parser + target validation)
        -> IR lowering
        -> bytecode image generation
        -> payload encoding
        -> VM emitter assembly

every stage seeded from the same build seed so a build is fully
reproducible byte-for-byte.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from vault import OutputError, VerificationError, VaultError
from vault.bytecode.encoder import BytecodeEncoder
from vault.bytecode.generator import BytecodeGenerator
from vault.frontend import parse_source
from vault.ir.builder import IRBuilder
from vault.presets.config import get_preset
from vault.utils.random import DeterministicRandom
from vault.utils.stats import BuildStats
from vault.vm.emitter import DEFAULT_MESSAGES, DEFAULT_META_KEYS, ObfuscationOptions, VMOmitter


@dataclass
class BuildResult:
    """The products of one obfuscation build."""

    output: str = ""
    stats: BuildStats = field(default_factory=BuildStats)


def _find_lua() -> Optional[str]:
    import shutil
    for name in ("lua", "lua5.1", "lua5.2", "lua5.3", "lua5.4", "lua51", "lua53", "lua54", "luau"):
        path = shutil.which(name)
        if path:
            return path
    return None


def _syntax_check(output: str, target: str) -> None:
    """Re-lex/re-parse the emitted script as a cheap well-formedness check."""
    try:
        parse_source(output, target=target)
    except VaultError as exc:
        raise VerificationError(
            f"generated script failed syntax verification: {exc.message}"
        ) from exc


def obfuscate(
    source: str,
    seed: int,
    target: str = "lua51",
    preset: str = "low",
    pretty: Optional[bool] = None,
    minify: Optional[bool] = None,
    verify: bool = False,
    out_path: Optional[str] = None,
    debug: bool = False,
    overrides: Optional[dict] = None,
) -> BuildResult:
    """Compile and protect ``source``.

    Args:
        source:   Lua 5.1 / Luau source text.
        seed:     deterministic build seed.
        target:   ``"lua51"`` or ``"luau"``.
        preset:   ``"low"``, ``"medium"`` or ``"strong"``.
        pretty:   optional override; pretty output.
        minify:   optional override; compact output.
        verify:   run a post-compile well-formedness check.
        out_path: optional output path; used only for diagnostics.
        overrides: optional per-build preset overrides (e.g. ``{"dispatch":
            "table"}``); validated against the preset schema.

    Returns:
        A :class:`BuildResult` with the protected script and stats.

    Raises:
        VaultError subclasses for invalid input or compilation failures.
    """
    from vault.targets import TARGETS

    if target not in TARGETS:
        from vault import FrontendInputError

        raise FrontendInputError(
            f"unknown target '{target}'; choose one of {sorted(TARGETS)}."
        )
    start = time.perf_counter()
    options = ObfuscationOptions(
        seed=seed,
        target=target,
        preset=preset,
        pretty=pretty,
        minify=minify,
        debug=debug,
        overrides=overrides,
    )
    # capture preset config once for stats
    cfg = get_preset(options.preset, overrides)
    if pretty is not None:
        cfg.pretty = pretty
    if minify is not None:
        cfg.minify = minify if not cfg.pretty else False

    # -- frontend --------------------------------------------------------
    chunk = parse_source(source, target=target)
    builder = IRBuilder(source=source, target=target)
    builder.build(chunk)
    ir_protos = list(builder.protos)

    # -- bytecode image --------------------------------------------------
    rng = DeterministicRandom(seed)
    generator = BytecodeGenerator(rng, cfg.__dict__)
    image = generator.generate(ir_protos)

    # -- encoding --------------------------------------------------------
    rng = DeterministicRandom(seed)
    encoder = BytecodeEncoder(rng, cfg.__dict__)
    payload = encoder.encode(image, DEFAULT_META_KEYS, DEFAULT_MESSAGES)

    # -- emission --------------------------------------------------------
    emitter = VMOmitter(options)
    output = emitter.emit(image, payload)

    if verify:
        _syntax_check(output, target)

    elapsed_ms = (time.perf_counter() - start) * 1000.0
    stats = BuildStats(
        source_size=len(source.encode("utf-8")),
        output_size=len(output.encode("utf-8")),
        bytecode_size=sum(len(p.code_blob) + len(p.const_blob) for p in payload.protos) * 8,
        instruction_count=sum(len(ip.instructions) for ip in ir_protos),
        constant_count=sum(len(ip.constants) for ip in ir_protos),
        function_count=len(ir_protos),
        compile_time_ms=elapsed_ms,
        seed=seed,
        preset=preset,
        target=target,
        source_lines=source.count("\n") + 1,
    )
    return BuildResult(output=output, stats=stats)