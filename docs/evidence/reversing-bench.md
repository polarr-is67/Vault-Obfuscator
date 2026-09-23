# Reversing evidence benchmark

Generated: 2026-09-21T21:25:34  
Source: 280 bytes, 5 vault builds, target `lua51`, preset `strong`.

Heuristics are the low-cost greps an analyst fires first; lower `recoverability` (0..1) means less structure stood out to a textual sweep.  `cross_fingerprint` is the byte-level structural similarity between two builds of the same source at different seeds (lower = builds look less alike).

| metric | description |
|---|---|
| `sentinels` | benchmark sentinel literals quoted verbatim in the output (0 is the goal) |
| `ids` | source identifiers that survive verbatim |
| `op==` | opcode-dispatch comparison sites (`op==N` cascade recognisability) |
| `handlers` | anonymous five-argument closures matching the VM handler-closure signature |
| `seq-frame` | sequential `local a=1..local k=11` frame-slot locator block surviving in the output |
| `while` | `while` loop occurrences (interpreter loop surface) |

## Vault-obf

- aggregate recoverability: **0.208** (per-build: 0.24, 0.2, 0.2, 0.2, 0.2)

| run | size | recoverability | sentinels | ids | op== | handlers | seq-frame | while |
|---|---|---|---|---|---|---|---|---|
| 0 | 26.8 KB | 0.24 | 0 | 1 | 0 | 41 | no | 9 |
| 1 | 27.2 KB | 0.2 | 0 | 0 | 0 | 41 | no | 9 |
| 2 | 25.5 KB | 0.2 | 0 | 0 | 0 | 41 | no | 9 |
| 3 | 26.5 KB | 0.2 | 0 | 0 | 0 | 41 | no | 9 |
| 4 | 26.3 KB | 0.2 | 0 | 0 | 0 | 41 | no | 9 |

- seeds used: `1, 2, 3, 4, 5`
- cross-build fingerprint (same source, two seeds): **0.558**

_No choco run configured (`--choco-command`); vault-only report._

