# Limitations

This document lists what Vault-Obf does *not* support, and known behaviours
to design around when writing source to obfuscate.

## Language subset

Vault-Obf implements a Lua 5.1–compatible frontend with a curated Luau
extension. Anything outside that subset is rejected at compile time with a
diagnostic — nothing is silently mis-compiled:

* `goto` and labels are not supported.
* The Lua 5.1 target rejects all Luau-only syntax. The Luau target accepts:
  * `continue` (lowered to a jump; works in `while`, `repeat`, numeric `for`
    and generic `for` loops).
  * `..=` concatenating compound assignment.
  * `!=` as an alias for `~=`.
  * Type annotations, which are parsed and discarded: `local x: T`,
    annotated parameters and return types (`: (T, U) -> R`), vararg
    annotations (`...: T`), optional/union/intersection types and
    `{[K]: V}` table types.
* Other Luau constructs are **not** supported and are reported: `type` /
  `export type` / `declare` statements, string interpolation
  (`` `hello {name}` ``), and `if ... then ... else ...` expressions.
* Lua 5.2+ semantics (integer division, bitwise operators, `goto`,
  `__len`, `table.unpack` in 5.3+, etc.) are not available.

## Trailing nil in varargs / select('#', ...)

The VM stores call results in Lua tables. A table cannot distinguish "slot
absent" from "value is nil". Consequently, when a vararg call passes one or
more *trailing* nils — for example `t(1, 'a', nil, 4)` — the vararg capture
under-counts the actual argument count:

```lua
local function t(...) print(select("#", ...)) end
t(1, "a", nil, 4)   -- raw Lua 5.1: 4, under Vault-Obf VM: 3
```

Note this matches the undefined behaviour of Lua on implementations that
trim trailing nil arguments: LuaJIT and Lua 5.4 also normalise the trailing
nil here (both report 3). Only the reference Lua 5.1 VM distinguishes the
slots, and only because it keeps an explicit count.

If the code under obfuscation relies on the *count* of a call that ends in
nil, use `{...}` array iteration (`#`) instead of `select('#', ...)` and
ensure call sites do not pass trailing nils when the count must be exact.

## Environment and sandbox

The VM captures the global environment (and `setmetatable`, `getmetatable`,
`rawget`, `rawset`, `select`, `unpack`, `pcall`, `error`, `type`,
`string.char`, `math.floor`) once at load time. The environment is taken from
`getfenv()` when available and `_G` otherwise: on stock Lua `_G` *is* the
global environment, but on Roblox/Luau `_G` is a separate, empty shared table,
so the standard library and the script's own globals are reached through the
function environment instead. This keeps the VM robust if globals are replaced
later, but it also means:

* Replacing those standard functions at runtime does not redirect the VM.
* A sandbox that deliberately removes `unpack`/`select`/etc. before loading
  the script may break startup.

## Anti-tamper is deterrent, not security

The integrity regions, watchdog and anti-debug trap exist to raise the cost
of defeating the compiled artifact. They are not a proof of resilience:

* All decoding happens inside the output file itself; a determined analyst
  with a trace debugger can replay the VM at the Lua level.
* `pretty` output (the `strong` preset) trades readability for direct
  quantity of meat; use the minified output for distribution.
* No protection covers the runtime edits: modifying the emitted file without
  updating its integrity checks is expected to abort the program, which is
  the intended failure mode.

## Size and performance

* Output size grows roughly linearly with input size; the included VM + VM
  dispatch adds a fixed constant per build (several kilobytes).
* Runtime is a plain Lua interpreter; expect a significant slowdown versus
  running the original bytecode, on the order of tens of times, worst case
  on the `strong` preset with the watchdog at its default threshold.
* The theoretical speed limit is a moving target; do not use Vault-Obf for
  CPU-bound patches where latency matters.

## Determinism

Same seed + same source + same preset ⇒ identical output, *within the same
version of the tool*. No promise of byte-stability between releases —
prefer to store the seed (not the tool version) as the reproducible
identity of a build.