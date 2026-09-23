# VM Internals

This document describes the bytecode protocol and the interpreter that runs
it. It is written for contributors who want to extend or debug the VM.

## Data model

The generated script carries the encoded program in a small number of globals
(under scrambled names) that are decoded during bootstrap into a prototype
table `@PT@`. Each function prototype is a record `{consts, code, params,
maxstack, upvals, kids}` that the loader additionally decorates with decoded
artefacts:

* `pr.kc` – decoded constant list.
* `pr.kd` – decoded instruction stream (six fields per instruction:
  opcode then `a`, `b`, `c`, `d`, `e`).
* `pr.kv` – key/value descriptor pairs used for instruction-embedded
  lookups (e.g. upvalue names and constants that live in the payload).

All numeric payload arrays (the constant, code, upvalue and integrity blobs)
are embedded as opaque **string blobs** rather than bare integer tables. Two
container formats exist:

* **Printable** (default): each blob packs its integers with a zig-zag
  base-45 varint over a seed-shuffled 90-character alphabet; a small load-time
  decoder (`@BLOB@`) expands each blob back into the integer array the loader
  consumes.
* **Binary** (`binary_payload`, the `strong` preset): each blob is a
  proprietary byte container — magic byte, format selector, a per-blob
  additive key, then a field stream of signed LEB128 or fixed-width
  little-endian integers, with every transmitted byte rotated by the blob's
  key. The runtime decoder (`@BIN@`) reconstructs the additive key first, so
  the *transmitted* bytes never equal the *decoded* values, and identical
  value sets differ across records and builds. The emitted literal is still
  pure ASCII (every non-ASCII byte becomes a `\ddd` escape).

Because the values are additionally keyed per build with the seed-derived LCG
stream, constants extracted in one build cannot be replayed in another.
Values that cannot be represented exactly by the integer encoding
(non-integer floats, or integers at or beyond `2^52`) fall back to a plain
numeric table so decoding is always exact.

### Constant schemes

Each prototype's constant blob is decoded by the per-record decoder `@DKC@`,
which takes the prototype's recorded scheme (`pr.cm`, header field 7). Under
`diverse_consts` each prototype is assigned one of three modes:

| mode | integer                    | string                          | float |
|------|----------------------------|---------------------------------|-------|
| 0    | `(v - IA) / IM`            | bytes `+ SH`                    | `num/den` |
| 1    | `(v + IA) / IM`            | bytes `+ SH` then `- SX`        | `num/den` (denominator stored first) |
| 2    | `(v - IA - SX) / IM`       | bytes `+ SH`, then order reversed | `num/den` |

Integer values whose scaled form would leave the exact double / blob range
tag-6 with denominator 1 instead (exact for every magnitude under `2^52`).
The mode-agnostic values still round-trip exactly through the LCG keying.

## Instructions

Bytes are decoded into 6 integer fields per instruction. The field-to-purpose
mapping follows Lua 5.1 conventions:

| Field | Meaning (typical) |
|-------|-------------------|
| `a`   | destination register (0-based) |
| `b`   | operand register / constant index (1-based) |
| `c`   | operand register / count |
| `d`   | secondary target (e.g. jump offset, result slot) |
| `e`   | extra encoding / effect mode |
| `f`   | rarely used; reserved |

Register operands are decoded from `b`/`c` and used as `regs[reg]`.
Constant operands index the decoded constant array as `consts[idx]` (1-based).

The dispatch loop is a switch on the opcode that was **permuted per build**,
so opcode *numbers* must never be treated as stable across builds; the emitter
always emits the same shuffled dispatch table.

### VM families

Every build runs on one of four fetch/execute families (`vm_family`):

* `classic` - the flat decoded stream is read word-by-word; the ip addresses
  a word and the five operand slots are the next five words (word-stride
  `6`, jumps written as `ip=d*6+1`).
* `soa` - the decoded stream is split into six parallel field arrays on
  `pr.ff` (op, a, b, c, d, e); the ip is an *instruction index* and operands
  are field lookups by position (`F[2..6][ip]`).
* `threaded` - the `soa` layout plus a per-proto successor table
  (`pr.nx`) on `pr.ff`; the loop falls through to `next[ip]` instead of
  advancing arithmetically, so no static `ip+1`/`ip+6` pair exists for it.
* `scrambled` - a physical permutation of the 6-word instruction groups.
  The generator records a per-proto logical->physical map (`pr.oo`) and the
  fetch `physical = (pr.oo and pr.oo[ip]) or ip` threads it through, so the
  decoded stream is not in execution order while jump targets stay logical.
  The map is the inverse of the permutation used to scramble the stream, so
  fetching logical index `i` lands on the group that now holds instruction
  `i`.

The `classic` family keeps `KADJ=6`/`SZ=6`; the field families use instruction
indexes (`KADJ=1`/`SZ=1`, loop bounds from the field split).  `vm_family` is
`auto` by default and is resolved once per build against the seed; ordinary
builds sample a strategy from the build-configurable family pool.  `dispatch`
defaults to `auto` too and likewise resolves to one strategy per build, and
`dispatch_noise` (0/2/4 under low/medium/strong) adds unreachable synthetic
edges to the cascade/table/indirect dispatch shapes.

When a prototype's `cgrp` flag is set (`diverse_consts`), every full 6-word
instruction group is stored in the build's shuffled operand order. The loader
detects the flag from header field 8 and, for each full group, writes word
`wi + CW[k]` from stored slot `k` before applying the per-word delta, so the
byte order the analyst sees no longer matches the order the dispatch reads.

## Function calls

Call/return uses a fixed-size frame with these slots (indices `1..11`):

| # | Name       | Contents                                        |
|---|------------|-------------------------------------------------|
| 1 | `pr`       | prototype descriptor (code/constants/params)  |
| 2 | `ip`       | instruction pointer (index into `kv`)          |
| 3 | `regs`     | register array                                  |
| 4 | `res`      | multi-value result buffer                      |
| 5 | `resn`     | number of values in `res`                      |
| 6 | `open`     | open-upvalue list for closure capture          |
| 7 | `upvals`   | upvalue cells captured for this frame          |
| 8 | `varargs`  | `{...}` table for vararg functions             |
| 9 | `back`     | caller frame (or nil at top level)             |
|10 | `dst`      | caller's destination register / result slot   |
|11 | `mode`     | effect mode (deterministic/single/multi)      |

Because the VM is written in Lua, a Lua-to-Lua call is one `call`: `call`
harness (`onh`) packs `regs` + `res` into the frame, invokes the interpreter
for the target proto, and unpacks results back into the caller's registers.

## Upvalues

Upvalue handles are stored as cells in a per-frame table (`upvals`). A cell
is either open (points at a live parent register — shared) or closed (owns a
value). Upvalue *indices* are stored 0-based and accessed as `cells[z-1]`.

The key table `kc` maps every global name to a slot so closure capture and
`_ENV`-style lookup both succeed under the scrambling.

## Integrity & dispatch protection

The medium/strong presets add:

* **Watchdog**: a step counter that compares against `watchdog_threshold`;
  when the budget is exhausted the VM aborts. Long-running loops are handled
  by `watchdog_step` so the counter does not terminate legitimate programs.
* **Integrity regions**: the output is split into regions covered by a
  checksum; a failure to match trips an error path. `build_specific_keys`
  mixes the seed-derived build secret into every checksum.
* **Anti-debug** (strong): a trap program runs checks for common debugging
  surfaces and aborts when suspicious. `unexpected_hook_detection` re-checks
  for an installed hook while the program runs (sampled by the watchdog).
* **Environment sanity**: verifies the standard functions the VM captured
  from the real environment at load time (`env_sanity`).
* **Runtime versioning**: embeds build metadata (VM version, seed-derived
  build id, flags) and aborts when the payload came from another VM revision.
* **Protected VM state / state validation**: frame-slot locators are
  scrambled (`protected_vm_state`) and the instruction pointer and frame
  chain are bounds-checked while running (`vm_state_validation`).  The 11
  slot locators (`K_P`..`K_M`) are assigned `1..11` by default and their
  numeric meaning is shuffled per seed when the option is on; every frame is
  then constructed with those keyed locators (`{[K_P]=pr,[K_I]=1,...}`),
  never as a positional literal, so a contiguous `[[1]..[11]]` frame cannot
  be recovered from the build alone.
* **Bytecode integrity**: a decoded instruction-stream chunk is re-verified on
  a watchdog budget (`bytecode_integrity`).
* **Controlled failures**: every security abort is routed through a
  build-specific sentinel so a tamper yields one clean, opaque error rather
  than a leaky internal message (`controlled_failures`).

### Dispatch strategies

The opcode dispatch chain is emitted in one of four shapes (`dispatch`):

* `cascade` - a flat, RNG-shuffled `if/elseif` chain.
* `tree` - a balanced binary decision tree over the permuted opcodes.
* `table` - a per-opcode closure table built once at load time, with an
  in-loop lookup instead of comparisons.
* `indirect` - a shuffled opcode->key remap blob plus a closure table keyed
  by the remapped integer.  The loop looks up `<DPL>[(op and <RM>[op+1]) or 0]`
  and calls the closure, so the emitted builder loop never contains a literal
  `op==N` comparison; an unknown/nil opcode resolves to a missing slot and is
  routed through the controlled-failure path.

Preset defaults use `dispatch: "auto"` (one resolution per build from the
strategy pool rather than a single hardcoded strategy); the interpreter
auto-advance is emitted as an expression over a generated step constant
rather than the recognisable `if av==0 then ip=ip+6` pair (in the non-linear
runner the executor is called first and the frame ip is read only after it
returns, so jump targets written by the executor are not clobbered).  Table
and indirect closures receive the frame, instruction stream, constants,
registers and skip-state as five explicit arguments and, for the field
families, re-fetch the current operands from `pr.ff` inside the closure — the
loop-bound operand locals are not in scope there.

### Payload string appearance

Scattering and the binary container pull in opposite directions: every byte of
a binary blob is non-printable, so a scattered binary blob would still render
as walls of `\ddd` escapes.  `scattered_payload` therefore switches payload
encoding to the printable alphabet (excludes `"`, `\` and `@`, so chunk
literals need zero escapes and read as plain characters like the decoy
locals).  The binary container remains the payload format whenever scattering
is off (e.g. `--set scattered_payload=false` under `strong`).

Encoding is further decorrelated so the serialised data never repeats:

* every record array is encoded with a per-build, per-record numeric offset
  that the decoder subtracts after unpacking, so identical value sets produce
  byte-for-byte different literals (and decode calls carry a distinct small
  integer key);
* the 90-character alphabet literal is split into 2-3 pieces with mixed quote
  styles instead of one fixed "data table" line;
* scattered chunk definitions are shuffled (the decode call always re-assembles
  chunks in byte order), alternate between single and double quotes, and some
  pairs merge onto one line; decoy helpers come from several code templates
  and carry long or deliberately silly filler words.

## Limits and notes

* The interpreter is implemented on top of plain Lua tables, so a value
  list cannot represent a *present-but-nil* slot. Passing trailing nils to a
  `...` vararg list (e.g. `t(1, 'a', nil, 4)`) makes `select('#', ...)`
  under-count by one per trailing nil. See `docs/limitations.md`.
* `goto` is not part of the supported Lua 5.1 subset.
* Different targets (Lua 5.1 vs Luau) share the VM but use their own emitter
  dispatch tables and validator.