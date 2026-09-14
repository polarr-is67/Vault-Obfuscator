"""Tests for the vault-obf command-line interface."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from vault.cli import build_parser, find_lua, main

SIMPLE = "local x = 2\nprint(x * 3)\n"


def write_input(tmp_path: Path) -> Path:
    p = tmp_path / "in.lua"
    p.write_text(SIMPLE, encoding="utf-8")
    return p


def test_parser_defaults():
    p = build_parser()
    args = p.parse_args(["in.lua"])
    assert args.preset == "low"
    assert args.target == "lua51"
    assert args.output is None
    assert args.verify is False


def test_main_writes_output(tmp_path):
    src = write_input(tmp_path)
    out = tmp_path / "out.lua"
    rc = main([str(src), "-o", str(out), "-p", "medium", "-s", "3", "--verify", "--stats"])
    assert rc == 0
    assert out.exists()
    text = out.read_text(encoding="utf-8")
    assert text.strip()
    assert "build statistics" not in text  # stats go to stdout, not the file


def test_main_stdin(tmp_path):
    import io
    import sys

    out = tmp_path / "out.lua"
    saved = sys.stdin
    sys.stdin = io.StringIO(SIMPLE)
    try:
        rc = main(["-", "-o", str(out), "-t", "lua51", "-s", "9"])
    finally:
        sys.stdin = saved
    assert rc == 0
    assert out.read_text(encoding="utf-8").strip()


def test_main_bad_preset_exit_code(tmp_path):
    src = write_input(tmp_path)
    with pytest.raises(SystemExit) as exc:
        main([str(src), "-p", "ultra"])
    assert exc.value.code == 2


def test_main_missing_file(tmp_path, capsys):
    rc = main([str(tmp_path / "nope.lua")])
    assert rc == 1
    assert "nope.lua" in capsys.readouterr().err


def test_check_lua_requires_output(tmp_path, capsys):
    src = write_input(tmp_path)
    rc = main([str(src), "--check-lua"])
    assert rc == 1
    assert "requires -o/--output" in capsys.readouterr().err


def test_find_lua_prefers_env(tmp_path):
    fake = tmp_path / "lua.exe"
    fake.write_text("", encoding="utf-8")
    import os

    old = os.environ.get("VAULT_LUA")
    os.environ["VAULT_LUA"] = str(fake)
    try:
        assert find_lua() == str(fake)
    finally:
        if old is None:
            os.environ.pop("VAULT_LUA", None)
        else:
            os.environ["VAULT_LUA"] = old


def test_json_stats(tmp_path, capsys):
    import json

    src = write_input(tmp_path)
    out = tmp_path / "out.lua"
    rc = main([str(src), "-o", str(out), "--stats", "--json"])
    assert rc == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["preset"] == "low"
    assert payload["output_size"] > 0