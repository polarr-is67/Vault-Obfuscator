"""Shared security-failure body generation.

Every security abort (integrity, version mismatch, debug-hook detection,
environment or state corruption) ends in one of two forms chosen at build
time:

* ``controlled_failures`` -- raise the build-specific sentinel via ``@KILL@``;
  the outer invocation wrapper maps it to a single clean opaque error.
* otherwise -- raise the load-time integrity message directly (the classic
  behaviour, kept for presets that leave controlled failures off).
"""

from __future__ import annotations

from typing import Any, Dict

# Every form below is an integer identity that holds for all integer ``a`` and
# stays exact in IEEE-754 doubles because ``a`` is bounded well below 2**53.
_OPAQUE_FORMS = (
    "(({a}*{a}-{a})%2==0)",
    "(({a}*{a})%4~=2)",
    "(({a}*({a}+1)*({a}+2))%6==0)",
    "(({a}*{a}+{a})%2==0)",
)


def opaque_true(preset_config) -> str:
    """A build-specific always-true Lua boolean expression.

    The expression is not constant-folded by the interpreter and its constants
    change with the build seed, so a deobfuscator cannot simply recognise and
    drop the guard around a security abort.
    """
    seed = int(preset_config.get("seed", 0) or 0)
    a = seed % 46337
    return _OPAQUE_FORMS[seed % len(_OPAQUE_FORMS)].format(a=a)


def failure_body(name_map: Dict[str, str], preset_config) -> str:
    """Return the Lua source that aborts execution on a security failure."""
    n = dict(name_map)
    if preset_config.get("controlled_failures", False):
        stmt = f"{n['KILL']}()"
    else:
        stmt = f"{n['ER']}(({n['EMT']}[1] or 'integrity check failed'))"
    if preset_config.get("opaque_predicates", False):
        return f"if {opaque_true(preset_config)} then {stmt} end"
    return stmt