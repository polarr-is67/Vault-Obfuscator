# Architecture

This document describes the internal structure of Vault-Obf.

## Overview

Vault-Obf transforms Lua 5.1 / Luau source into a single self-contained Lua
script that embeds a custom virtual machine. When executed, the VM reads a
bytecode payload baked into the output and reproduces the original program's
behaviour.

All pipeline stages are seeded from a single integer (`seed`), making every
build fully reproducible: same seed + same source + same preset = identical
output.

```
Source text
  │
  ▼
┌─────────────┐
│  Lexer       │   vault.frontend.lexer
│  Parser      │   vault.frontend.parser
└─────┬───────┘
      ▼
┌─────────────┐
│ IR Builder   │   vault.ir.builder
│              │   (AST → register-allocated IR instructions)
└─────┬───────┘
      ▼
┌─────────────┐
│ Bytecode     │   vault.bytecode.generator
│ Generator    │   → vault.bytecode.encoder (payload blobs)
└─────┬───────┘
      ▼
┌─────────────┐
│ VM Emitter   │   vault.vm.emitter
│              │   assembles the Lua source of the VM + payload
└─────┬───────┘
      ▼
Protected script
```

## Source text → AST

The **frontend** consists of a hand-written recursive-descent lexer
(`lexer_char.py`, a character-level scanner) and a recursive-descent parser
(`parser.py`) that produce an AST defined in `vault/ast/nodes.py`.

Target-specific validation runs during parsing:
* The Lua 5.1 target rejects Luau-only syntax (`continue`, `..=`, `!=` and
  type annotations) with a diagnostic.
* The Luau target accepts `continue` (lowered to a jump by the IR builder),
  the `..=` concatenating compound assignment, `!=` as an alias for `~=`,
  and Luau type annotations (`local x: T`, `: (T, U) -> R`, `...: T`, `T?`,
  union/intersection and `{[K]: V}` types), which are skipped before lowering.
  Parenthesised expressions are preserved so `(f())` still truncates to a
  single value.

## AST → IR

`vault/ir/builder.py` lowers the AST into a register-based intermediate
representation. Each IR instruction uses six integer slots (`a`, `b`, `c`,
`d`, `e`, `f`) following a Lua 5.1–inspired convention.

Registers are allocated by a pool-based allocator (`_FuncCtx`). A block
allocation (`alloc_block(n)`) reserves `n` contiguous scratch registers;
individual temporaries use `new_reg()`. Locals (`declare_local`) bind a
name to the next available register.

Labels (`_Label`) and resolution in `IRProto.resolve_labels()` turn
forward/backward jumps into fixed byte offsets at instruction-finalisation
time.

## Bytecode generation & encoding

`vault/bytecode.generator.BytecodeGenerator` serialises the IR into a
compact bytecode image (`Image`, containing `ProtoImage` per function). Each
prototype stores:

* `code_blob` – the opcodes + operands (packed 6 ints per instruction).
* `const_blob` – packed constant values (numbers and strings).
* Metadata: `nparams`, `nslots`, `maxstack`, `is_vararg`, debug names.

`vault/bytecode.encoder.BytecodeEncoder` encodes the image into the payload
tables injected into the output. The `vault/vm.emitter` then serialises each
numeric array as an opaque string blob (see `vault/utils/luaval`), so the
payload holds no long bare integer lists. Blobs use either the printable
base-45 varint alphabet or — when `binary_payload` is enabled — a proprietary
binary byte container (`BINARY_BLOB_MAGIC` + format selector + per-blob key +
signed LEB128/fixed-width little-endian fields), emitted as straight ASCII
`\ddd` escapes.

Each prototype's constant blob is recorded with a per-build scheme
(`diverse_consts`): prototype `cmode` picks the integer/string/float forms
(plain, affine-minus with a string xor key, or affine-plus with reversed
strings) so the constant blobs are not one uniform shape, and per-prototype
`cgrp` optionally stores every full 6-word instruction group in the build's
shuffled operand order (the runtime's load loop reorders it back through the
build's `CW` permutation).

## VM emitter

`vault/vm.emitter.VMOmitter` produces the final Lua script:

1. A runtime header (`@RUN@`) containing the interpreter main loop,
   op-handlers (`@MK@` wrapper), and helpers (`@COLL@`, `@PT@`, etc.).
2. Dispatch (opcode-switch) code built from `vault.targets.lua51.EMITTER`
   or the Luau equivalent, with identifiers shuffled per seed.
3. Protection snippets: integrity checks, anti-debug stubs, and metamethod
   hooks when enabled.
4. The encoded payload (`kv` / `cs` / `cc` tables).
5. A bootstrap that calls the interpreter.

## Presets

Obfuscation presets (`vault/presets/config.py`) tune the actual pipeline
settings:

| Setting               | Description                                        |
|-----------------------|----------------------------------------------------|
| `opcode_permute`      | Shuffle instruction opcodes per build             |
| `proto_shuffle`       | Shuffle internal function prototype order         |
| `const_shuffle`       | Shuffle constant pool order                       |
| `upval_shuffle`       | Shuffle upvalue descriptor order                  |
| `dispatch`            | Dispatch strategy: `cascade`, `tree`, `table` or `indirect` |
| `vm_family`           | VM family: `classic`, `soa`, `threaded` or `scrambled` |
| `integrity_regions`   | Number of protected output regions                |
| `load_verify_regions` | Number of regions verified at startup             |
| `build_specific_keys` | Mix the build secret into every integrity checksum|
| `watchdog`            | Execution-time watchdog                           |
| `watchdog_threshold`  | Step limit before watchdog trips                  |
| `anti_debug`          | Anti-debugger trap program                        |
| `unexpected_hook_detection` | Re-check for a debug hook while running      |
| `env_sanity`          | Verify captured standard functions at load time   |
| `runtime_versioning`  | Seal builds to a VM revision via metadata         |
| `protected_vm_state`  | Scramble frame-slot locators                      |
| `vm_state_validation` | Bounds-check the instruction pointer / frame chain|
| `bytecode_integrity`  | Re-verify decoded instruction chunks at runtime    |
| `controlled_failures` | Route aborts through one opaque sentinel error     |
| `binary_payload`      | Ship payload arrays as custom binary byte containers instead of printable blobs |
| `diverse_consts`      | Per-prototype constant schemes + per-build operand-order shuffle |
| `identifier_policy`   | Identifier rename strategy (`vault`/`low`/`medium`/`strong`/`hex`) |
| `pretty` / `minify`   | Output formatting                                 |
| `line_wrap`           | Max line width when pretty-printing               |

Use `-p low`, `-p medium`, or `-p strong` via the CLI, or `preset=`
via the Python API. Any setting can be overridden for a single build with
`--set key=value` (CLI), `overrides={...}` (Python) or the `overrides` object
(HTTP); unsupported keys are rejected.
