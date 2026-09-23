"""Generated identifier policy for VM internals.

Generated names must be valid Lua identifiers, must never collide with Lua
keywords, and must be deterministic under a fixed seed.  The policy controls
the character set and average length per preset.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, List, Optional, Set

from vault.utils.random import DeterministicRandom

LUA_KEYWORDS = frozenset({
    "and", "break", "do", "else", "elseif", "end", "false",
    "for", "function", "if", "in", "local", "nil", "not", "or",
    "repeat", "return", "then", "true", "until", "while",
})


@dataclass
class IdentifierPolicy:
    """Configuration for identifier generation.

    Attributes:
        charset: Allowed characters for generated names.
        min_len / max_len: Length bounds for generated names.
        prefix: Optional mandatory prefix.
        numbered: Emit sequential ``v0``, ``v1``, ``v2``... names (the
            vault-obfuscator style) instead of drawing from ``charset``.
    """

    charset: str
    min_len: int
    max_len: int
    prefix: str = ""
    numbered: bool = False


class IdentifierGenerator:
    """Deterministic generator of unique Lua identifiers."""

    def __init__(
        self,
        rng: DeterministicRandom,
        policy: Optional[IdentifierPolicy] = None,
        reserved: Optional[Set[str]] = None,
    ) -> None:
        self.rng = rng
        if policy is None:
            policy = IdentifierPolicy(
                charset="abcdefghijklmnopqrstuvwxyz_",
                min_len=3,
                max_len=8,
            )
        self.policy = policy
        self._used: Set[str] = set()
        self._n = 0
        if reserved:
            # Reserve words that appear as identifiers in the emitted VM
            # template so generated names can never shadow them.
            for name in reserved:
                self._used.add(name)
                self._used.add(name.upper())

    @staticmethod
    def policy_for(preset: str) -> "IdentifierPolicy":
        """Return a policy appropriate for the given preset name."""
        if preset == "vault":
            # Sequential shortcut locals in the style of the classic
            # vault-obfuscator ("local v0", "local v1", ...): short, similar,
            # and easy to skim past, unlike readable or hex-dump names.
            return IdentifierPolicy(
                charset="v",
                min_len=1,
                max_len=1,
                prefix="v",
                numbered=True,
            )
        if preset == "low":
            return IdentifierPolicy(
                charset="abcdefghijklmnopqrstuvwxyz",
                min_len=2,
                max_len=4,
                prefix="",
            )
        if preset == "strong":
            return IdentifierPolicy(
                charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_",
                min_len=6,
                max_len=14,
                prefix="_",
            )
        if preset == "hex":
            # Identifiers that look like bare hex byte data (``_a56f8c``,
            # ``_c9ab4f``).  Only hex digits appear after the leading ``_`` so
            # the names blend with hex-dump-style output while remaining valid
            # Lua identifiers (the first body character is forced to a letter).
            return IdentifierPolicy(
                charset="0123456789abcdef",
                min_len=6,
                max_len=16,
                prefix="_",
            )
        # medium
        return IdentifierPolicy(
            charset="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_",
            min_len=4,
            max_len=10,
            prefix="_",
        )

    def _generate_one(self) -> str:
        plen = self.rng.randint(self.policy.min_len, self.policy.max_len)
        chars = []
        if self.policy.prefix:
            chars.append(self.policy.prefix)
        start = self.policy.charset
        while len(chars) < plen:
            if len(chars) == 0:
                # a leading digit is not allowed; charset may contain digits
                # but we skip them for the first character by construction.
                candidate = [c for c in start if not c.isdigit()]
                chars.append(self.rng.choice(candidate))
            else:
                chars.append(self.rng.choice(start))
        return "".join(chars)

    def next(self, fallback: str = "") -> str:
        """Return a fresh unused identifier."""
        if self.policy.numbered:
            # Sequential v0, v1, v2, ... locals (vault-obfuscator style).
            # Skipping is only ever needed if a reserved word were shaped
            # like ``vN``; keep the loop for safety.
            for _ in range(1000):
                name = "%s%d" % (self.policy.prefix, self._n)
                self._n += 1
                if not name or name in LUA_KEYWORDS or name in self._used:
                    continue
                self._used.add(name)
                return name
            name = "%s%d" % (self.policy.prefix, self._n)
            self._n += 1
            self._used.add(name)
            return name
        for _ in range(1000):
            name = self._generate_one()
            if not name or name in LUA_KEYWORDS or name in self._used:
                continue
            self._used.add(name)
            return name
        # Extremely unlikely path: fall back to an indexed name.
        idx = len(self._used) + 1
        name = f"__va_{idx}"
        self._used.add(name)
        return name