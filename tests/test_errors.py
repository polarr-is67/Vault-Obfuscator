"""Error-path tests covering the public API surface."""

from __future__ import annotations

import pytest

from vault import ConfigError, LexerError, ParseError, VaultError
from vault.compiler.pipeline import obfuscate
from vault.presets.config import get_preset


def test_unknown_preset_is_config_error():
    with pytest.raises(ConfigError):
        get_preset("nope")
    with pytest.raises(ConfigError, match="preset"):
        obfuscate("print(1)", seed=1, preset="cosmic")


def test_lexer_error():
    with pytest.raises(LexerError):
        obfuscate("local x = `bad`", seed=1)


def test_parse_error():
    with pytest.raises(ParseError):
        obfuscate("function (", seed=1)


def test_unsupported_feature_error(target_class=None):
    """Luau-only features should be rejected for lua51."""
    with pytest.raises(VaultError):
        obfuscate("local x: number = 1", seed=1, target="lua51")


def test_config_error_on_bad_override():
    with pytest.raises(ConfigError):
        get_preset("low", {"integrity_regions": 1})


def test_oversized_regions_error():
    with pytest.raises(ConfigError):
        get_preset("low", {"load_verify_regions": 9})