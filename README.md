# Vault-Obf

Vault-Obf is a deterministic, VM-based source obfuscator for Lua 5.1 and a
subset of Luau. It compiles your Lua source to *bytecode*, encrypts and
embeds that bytecode inside a hand-rolled **virtual machine** written in Lua,
and emits a single self-contained script. At runtime the embedded VM decodes
and executes the original program on top of the host Lua interpreter.

The tool is built around one hard rule: **correctness first**. Every preset
boosts obfuscation only insofar as it keeps the generated script able to run
on a real interpreter (Lua 5.1 through 5.4 and Luau), with byte-for-byte
identical program output.

## Feature summary

- **Compile to a VM**: source -> AST -> IR -> bytecode image -> encoded
  payload -> VM program (a single Lua script, no external files).
- **Deterministic builds**: the same seed and source produce the identical
  output every time.
- **Two targets**: `lua51` and a `luau` subset (annotations, compound
  assignment operators, `continue`).
- **Three presets** (`low`, `medium`, `strong`) that scale opcode permutation,
  constant/upvalue shuffling, load-time integrity checks, a VM watchdog and
  anti-debug hooks.
- **Encrypted payload**: constants and instructions are stored as integers,
  scrambled by a seed-derived LCG, and decoded inside the VM at load time.
- **Token-preserving minifier** for compact output (`--minify`) alongside
  pretty output for auditing (`--pretty`).
- **CLI + Python API**: `vault-obf` on the command line or
  `from vault.compiler.pipeline import obfuscate` in code.

## Installation

Requires Python 3.10+.

```bash
pip install .
```

On Windows: `install.bat` (or run the login shell version `install.sh` with
WSL / Git Bash / Cygwin). Both create a virtual environment, install the
package editable with the `web` extras, and print a usage summary.

To run without installing:

```bash
pip install -r requirements.txt
python -m vault.cli --help
```

To run the optional end-to-end tests against a real interpreter, install one
of `lua5.1` / `lua5.3` / `lua5.4` / `luau` and put it on `PATH`, or set the
`VAULT_LUA` environment variable to its path.

## Usage

```bash
# obfuscate a file with default (low) settings; write to stdout
vault-obf program.lua

# to a file, medium preset, deterministic seed, print stats
vault-obf program.lua -o p.lua -p medium -s 42 --stats

# strong preset, pretty output, then verify the result runs
vault-obf program.lua -o p.lua -p strong --pretty --verify --check-lua

# JSON statistics for tooling
vault-obf program.lua -o p.lua --stats --json | jq .
```

Run `vault-obf --help` for the full option list.

### Python API

```python
from vault.compiler.pipeline import obfuscate

result = obfuscate(
    source="print('hello')",
    seed=123,          # deterministic
    target="lua51",    # or "luau"
    preset="medium",   # low | medium | strong
    verify=True,       # re-parse output as a sanity check
)
with open("out.lua", "w", encoding="utf-8") as fh:
    fh.write(result.output)
print(result.stats.format_cli())
```

### Web service

A small FastAPI service (`web/`) wraps the same pipeline over HTTP, with a
browser UI served at `/`.

```bash
pip install ".[web]"
python -m web --port 8000
```

* `POST /obfuscate` (JSON body) returns the protected Lua script as text.
* `POST /obfuscate.json` returns `{ "output": ..., "stats": ... }`.
* `GET /health` and `GET /` (the editor UI) are available at `http://127.0.0.1:8000`.

## Presets

| preset   | opcode shuffle | proto/const shuffle | load integrity | watchdog | anti-debug | output   |
|----------|----------------|---------------------|----------------|----------|------------|----------|
| `low`    | yes            | const/upval         | 3 regions      | off      | off        | minified |
| `medium` | yes            | + proto             | 4 regions      | on       | off        | minified |
| `strong` | yes            | + proto             | 5 regions      | on       | on         | pretty   |

The exact mix of protections available at each level is defined in
`vault/presets/config.py`.

## Architecture

```
source ──► frontend (lexer + parser + target validation)
        ──► IR lowering (vault/ir)
        ──► bytecode image  (vault/bytecode)   opcode/const/upvalue shuffles
        ──► payload encoding(LCG-encrypted constant & code blobs)
        ──► VM emitter      (vault/vm)         runtime + dispatch + guards
        ──► single *.lua script
```

The emitted file contains:

1. the encoded payload table `Q`,
2. a Lua runtime implementing a register-based VM (frame stack, closures with
   upvalue cells, varargs, metamethods, multi-value returns),
3. a dispatch chain matching the build's permuted opcode numbers,
4. integrity/watchdog/anti-debug fragments selected by the preset.

Source identifiers and string literals are not preserved; the original
program text does not appear in the output.

## Supported syntax (Lua 5.1)

All of Lua 5.1's grammar:

- locals, closures, `local function`, upvalues, `...`
- all statements: `if/elseif/else`, `while`, `repeat/until`, numeric and
  generic `for`, `break`, `return`
- expressions: arithmetic `+ - * / % ^`, concatenation `..`, comparison
  `== ~= < <= > >=`, logic `and or not`, unary `- #`
- tables and field access, function/method calls, multi-value semantics for
  calls and varargs, `select('#', ...)`
- metamethods on tables (`__add`, `__index`, ...) used naturally through the
  host interpreter

### Luau subset

Additional features accepted with `-t luau`: type annotations (safely
discarded), compound assignment (`+=`, `-=`, `*=`, `/=`, `%=`, `^=`, `..=`),
and `continue`.

Anything outside the subset (interpolated strings, lambdas, bitwise ops,
if-expressions, type packs, `export`/`declare`) is rejected with a clear
error.

## Known limitations

The embedded VM is written in Lua and stores values in real Lua tables. Two
semantic edges follow from that design and are **not** supported:

- **Trailing `nil` varargs**: `select('#', ...)` counts actual arguments,
  and Lua 5.1 counts arguments that are trailing `nil`. A table-based value
  store cannot represent "a slot that is nil but present", so
  `select('#', ...)` may under-count when the call passes trailing nils
  (e.g. `f(1, 'a', nil, 4)`). Non-nil varargs behave correctly.
- **`goto` / labels**: not part of Lua 5.1; not implemented for Luau.

Everything else is exercised by the test suite against a real interpreter.

## Documentation

Deeper material lives in `docs/`:

- `docs/architecture.md` – pipeline stages and data flow.
- `docs/vm-internals.md` – bytecode protocol and interpreter internals.
- `docs/limitations.md` – unsupported grammar, trailing-`nil` varargs,
  environment capture, and anti-tamper boundaries.

## Development

```bash
python -m pytest tests -q
```

End-to-end semantic tests compare the VM output against the un-obfuscated
source on a real interpreter and **skip automatically** when none is
installed. Set `VAULT_LUA` to point at a specific binary, e.g.:

```bash
VAULT_LUA=/usr/bin/lua5.1 python -m pytest tests -q
```

## License

MIT. See `LICENSE`.