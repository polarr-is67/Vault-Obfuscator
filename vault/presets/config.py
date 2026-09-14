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

    # dispatch
    dispatch: str = "cascade"  # "cascade" only at present

    # integrity
    integrity_regions: int = 3
    load_verify_regions: int = 3

    # runtime hardening
    watchdog: bool = False
    watchdog_threshold: int = 0
    watchdog_step: int = 2
    anti_debug: bool = False

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
        "integrity_regions": 3,
        "load_verify_regions": 3,
        "watchdog": False,
        "watchdog_threshold": 0,
        "anti_debug": False,
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
        "integrity_regions": 4,
        "load_verify_regions": 4,
        "watchdog": True,
        "watchdog_threshold": 750,
        "watchdog_step": 3,
        "anti_debug": False,
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
        "integrity_regions": 5,
        "load_verify_regions": 5,
        "watchdog": True,
        "watchdog_threshold": 220,
        "watchdog_step": 3,
        "anti_debug": True,
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
    if cfg.dispatch not in ("cascade",):
        raise ConfigError(f"unsupported dispatch strategy '{cfg.dispatch}'.")
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