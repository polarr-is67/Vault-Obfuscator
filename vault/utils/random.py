"""Deterministic random source for reproducible builds.

A thin wrapper around Python's :mod:`random` module that:

* derives an integer seed from a textual seed string,
* is fully reproducible when ``seed`` is supplied,
* draws fresh entropy when ``seed`` is ``None``.
"""

from __future__ import annotations

import random
import secrets
from typing import Optional


def _derive_seed(seed: Optional[str]) -> int:
    """Map a seed string (or integer) to a deterministic 64-bit integer."""
    if seed is None:
        return secrets.randbits(64)
    if isinstance(seed, int):
        return seed & ((1 << 64) - 1)
    # FNV-1a 64-bit over the UTF-8 byte sequence.
    text = seed.encode("utf-8")
    h = 0xCBF29CE484222325
    prime = 0x100000001B3
    for b in text:
        h ^= b
        h = (h * prime) & ((1 << 64) - 1)
    return h


class DeterministicRandom:
    """Deterministic PRNG.

    All randomness flavour requested by the obfuscator must flow through an
    instance of this class so that ``--seed`` reproduces byte-identical output.
    """

    __slots__ = ("seed", "_rng", "random_bytes_source")

    def __init__(self, seed: Optional[str] = None) -> None:
        self.seed = seed
        self._rng = random.Random(_derive_seed(seed))

    def randint(self, a: int, b: int) -> int:
        return self._rng.randint(a, b)

    def randrange(self, start: int, stop: int, step: int = 1) -> int:
        return self._rng.randrange(start, stop, step)

    def choice(self, seq):
        return self._rng.choice(seq)

    def choices(self, population, weights=None, k=1):
        return self._rng.choices(population, weights=weights, k=k)

    def shuffle(self, seq) -> None:
        self._rng.shuffle(seq)

    def sample(self, population, k):
        return self._rng.sample(population, k)

    def random(self) -> float:
        return self._rng.random()

    def getrandbits(self, k: int) -> int:
        return self._rng.getrandbits(k)

    def seed_int(self) -> int:
        """Return the derived numeric seed (useful for stats/debug)."""
        return _derive_seed(self.seed)