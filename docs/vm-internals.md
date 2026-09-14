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

All payload strings are stored base64-encoded and keyed per build with the
seed-derived stream, so constants extracted in one build cannot be replayed
in another.

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
  checksum; a failure to match trips an error path.
* **Anti-debug** (strong): a trap program runs checks for common debugging
  surfaces and aborts when suspicious.

## Limits and notes

* The interpreter is implemented on top of plain Lua tables, so a value
  list cannot represent a *present-but-nil* slot. Passing trailing nils to a
  `...` vararg list (e.g. `t(1, 'a', nil, 4)`) makes `select('#', ...)`
  under-count by one per trailing nil. See `docs/limitations.md`.
* `goto` is not part of the supported Lua 5.1 subset.
* Different targets (Lua 5.1 vs Luau) share the VM but use their own emitter
  dispatch tables and validator.