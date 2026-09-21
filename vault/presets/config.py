"""Obfuscation presets.

Each preset is a validated block of settings that tunes every stage of the
pipeline: AST transforms, identifier policy, bytecode shuffling, VM runtime
features, integrity coverage and output formatting.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List

from vault import ConfigError


@dataclass
class PresetConfig:
    """Configuration block for one build."""

    name: str = "low"

    # bytecode shuffling
    opcode_permute: bool = True
    proto_shuffle: bool = False
    const_shuffle: bool = True
    upval_shuffle: bool = True
    # Instruction-word encoding layers: 1 = one shared per-instruction delta
    # (classic additive), 2 = a distinct delta per operand word, which breaks
    # the "six words share an offset" signature.  Both variants are further
    # diversified per build by a random multiplier and modulus.
    encoding_layers: int = 1
    # Upper bound on build-random decoy prototypes appended (unused) to the
    # payload so its size does not track the source's function count.
    decoy_protos: int = 0
    # Upper bound on build-random unused helper functions/constants emitted
    # into the script text so its size does not track the source's structure.
    decoy_helpers: int = 0

    # dispatch
    dispatch: str = "cascade"  # "cascade" | "tree" | "table"
    # Split frame fetch from instruction execution so the interpreter is not
    # a single contiguous fetch/decode/switch/execute loop.
    nonlinear_vm: bool = False

    # integrity
    integrity_regions: int = 3
    load_verify_regions: int = 3
    # Mix the seed-derived build secret into every integrity checksum so one
    # build's checksum key never matches another build's payload.
    build_specific_keys: bool = True

    # runtime hardening
    watchdog: bool = False
    watchdog_threshold: int = 0
    watchdog_step: int = 2
    anti_debug: bool = False
    # Re-check for a installed debug hook while the program runs (sampled by
    # the watchdog), not only at load time.
    unexpected_hook_detection: bool = False
    # Sanity-check that every standard function the VM depends on was captured
    # from the real environment at load time.
    env_sanity: bool = False
    # Embed build metadata (VM version, seed-derived build id, flags) and
    # abort when the payload was produced by a different VM revision.
    runtime_versioning: bool = False
    # Scramble the frame-slot locators used to address VM state.
    protected_vm_state: bool = False
    # Bounds-check the instruction pointer and frame chain while running
    # (sampled); abort cleanly on structural corruption.
    vm_state_validation: bool = False
    # Re-verify a decoded instruction stream chunk on a watchdog budget.
    bytecode_integrity: bool = False
    # Route every security abort through a build-specific sentinel so a tamper
    # produces one clean, opaque error instead of a leaky internal message.
    controlled_failures: bool = False
    # Guard every security abort with a build-specific always-true predicate so
    # the abort branch cannot be located and excised by a constant-naive
    # deobfuscator.
    opaque_predicates: bool = False
    # Best-effort verification of the script's own on-disk source (FNV-style
    # hash) when the host exposes file IO and debug info; silently skipped
    # everywhere else (Roblox/Luau, loadstring, stdin).
    self_file_check: bool = False

    # identifiers
    identifier_policy: str = "low"  # -> IdentifierGenerator.policy_for

    # output
    pretty: bool = False
    minify: bool = True
    line_wrap: int = 80


PRESETS: Dict[str, Dict[str, Any]] = {
    "low": {
        "name": "low",
        "opcode_permute": True,
        "proto_shuffle": False,
        "const_shuffle": True,
        "upval_shuffle": True,
        "encoding_layers": 1,
        "decoy_protos": 2,
        "decoy_helpers": 3,
        "integrity_regions": 3,
        "load_verify_regions": 3,
        "build_specific_keys": True,
        "dispatch": "cascade",
        "nonlinear_vm": False,
        "watchdog": False,
        "watchdog_threshold": 0,
        "anti_debug": False,
        "unexpected_hook_detection": False,
        "env_sanity": False,
        "runtime_versioning": False,
        "protected_vm_state": False,
        "vm_state_validation": False,
        "bytecode_integrity": False,
        "controlled_failures": False,
        "opaque_predicates": False,
        "self_file_check": False,
        "identifier_policy": "low",
        "pretty": False,
        "minify": True,
    },
    "medium": {
        "name": "medium",
        "opcode_permute": True,
        "proto_shuffle": True,
        "const_shuffle": True,
        "upval_shuffle": True,
        "encoding_layers": 2,
        "decoy_protos": 4,
        "decoy_helpers": 5,
        "integrity_regions": 4,
        "load_verify_regions": 4,
        "build_specific_keys": True,
        "dispatch": "cascade",
        "nonlinear_vm": True,
        "watchdog": True,
        "watchdog_threshold": 750,
        "watchdog_step": 3,
        "anti_debug": False,
        "unexpected_hook_detection": False,
        "env_sanity": True,
        "runtime_versioning": True,
        "protected_vm_state": True,
        "vm_state_validation": False,
        "bytecode_integrity": False,
        "controlled_failures": False,
        "opaque_predicates": True,
        "self_file_check": False,
        "identifier_policy": "medium",
        "pretty": False,
        "minify": True,
    },
    "strong": {
        "name": "strong",
        "opcode_permute": True,
        "proto_shuffle": True,
        "const_shuffle": True,
        "upval_shuffle": True,
        "encoding_layers": 2,
        "decoy_protos": 6,
        "decoy_helpers": 8,
        "integrity_regions": 5,
        "load_verify_regions": 5,
        "build_specific_keys": True,
        "dispatch": "tree",
        "nonlinear_vm": True,
        "watchdog": True,
        "watchdog_threshold": 220,
        "watchdog_step": 3,
        "anti_debug": True,
        "unexpected_hook_detection": True,
        "env_sanity": True,
        "runtime_versioning": True,
        "protected_vm_state": True,
        "vm_state_validation": True,
        "bytecode_integrity": True,
        "controlled_failures": True,
        "opaque_predicates": True,
        "self_file_check": True,
        "identifier_policy": "strong",
        "pretty": True,
        "minify": False,
    },
}


def get_preset(name: str, overrides: Dict[str, Any] | None = None) -> PresetConfig:
    """Build a :class:`PresetConfig` from a preset name plus overrides.

    Raises :class:`~vault.ConfigError` when ``name`` is unknown or an
    override violates a hard constraint.
    """
    key = (name or "low").lower()
    if key not in PRESETS:
        raise ConfigError(
            f"unknown preset '{name}'; choose one of {sorted(PRESETS)}."
        )
    data = dict(PRESETS[key])
    if overrides:
        if not isinstance(overrides, dict):
            raise ConfigError("preset overrides must be a mapping.")
        data.update(_validated_overrides(overrides))
    cfg = PresetConfig(**data)
    if cfg.integrity_regions < 3:
        raise ConfigError("integrity_regions must be at least 3.")
    if cfg.load_verify_regions < 0 or cfg.load_verify_regions > cfg.integrity_regions:
        raise ConfigError("load_verify_regions must be in [0, integrity_regions].")
    if cfg.watchdog_threshold < 0:
        raise ConfigError("watchdog_threshold must be non-negative.")
    if cfg.dispatch not in ("cascade", "tree", "table"):
        raise ConfigError(
            f"unsupported dispatch strategy '{cfg.dispatch}'; "
            "choose one of cascade, tree, table."
        )
    return cfg


def _validated_overrides(overrides: Dict[str, Any]) -> Dict[str, Any]:
    allowed = set(PresetConfig.__dataclass_fields__)
    cleaned: Dict[str, Any] = {}
    for key, value in overrides.items():
        if key not in allowed:
            raise ConfigError(f"unknown preset option '{key}'.")
        cleaned[key] = value
    return cleaned


def as_dict(cfg: PresetConfig) -> Dict[str, Any]:
    data = asdict(cfg)
    data["known_options"] = sorted(PresetConfig.__dataclass_fields__)
    return data