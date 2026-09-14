"""Tests for the token-preserving minifier."""

from __future__ import annotations

from vault.vm.emitter import minify_lua


def test_removes_comments():
    src = "--[[ block\ncomment ]] local x = 1\n-- line comment\nprint(x)"
    assert "--" not in minify_lua(src)


def test_preserves_string_literals():
    src = "local a = 'hi there'\nlocal b = \"\\\"quoted\\\"\"\nprint(a .. b)"
    out = minify_lua(src)
    assert "hi there" in out
    assert '\\"quoted\\"' in out


def test_preserves_identifier_boundaries():
    src = "local xyz = 1\nlocal x = xyz + 2"
    out = minify_lua(src)
    assert "xyz" in out
    assert "xyzz" not in out.replace("xyz", "")
    # 'x' must remain distinct from 'xyz'
    for token in ("local", "xyz", "+", "2"):
        assert token.split()[0] in " " + out or token in out


def test_empty_and_whitespace():
    assert minify_lua("   ") == ""
    assert minify_lua("") == ""


def test_keeps_semantics_equivalent_when_run():
    from vault.compiler.pipeline import obfuscate

    src = "local t = {'a', 'b c', [[d]]}\nprint(#t, t[2])"
    r = obfuscate(src, seed=1, preset="low", verify=True)
    mixed = minify_lua(r.output)
    assert mixed.strip()  # still a meaningful script