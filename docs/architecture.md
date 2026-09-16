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
* Lua 5.1 rejects `continue` (a Luau extension).
* Luau accepts `continue` but rejects Lua 5.1–style numeric-for step syntax
  when ambiguous.

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
numeric array as an opaque printable string blob (see `vault/utils/luaval`),
so the payload holds no long bare integer lists.

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
| `proto_shuffle`       | Shuffle internal function prototype order        |
| `const_shuffle`       | Shuffle constant pool order                      |
| `upval_shuffle`       | Shuffle upvalue descriptor order                 |
| `integrity_regions`   | Number of protected output regions               |
| `load_verify_regions` | Number of regions verified at startup            |
| `watchdog`            | Execution-time watchdog                          |
| `watchdog_threshold`  | Step limit before watchdog trips                 |
| `anti_debug`          | Anti-debugger trap program                       |
| `identifier_policy`   | Identifier rename strategy (low/medium/strong)   |
| `pretty` / `minify`   | Output formatting                                |
| `line_wrap`           | Max line width when pretty-printing              |

Use `-p low`, `-p medium`, or `-p strong` via the CLI, or `preset=`
via the Python API.
