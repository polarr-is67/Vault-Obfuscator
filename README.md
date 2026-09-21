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
  constant/upvalue shuffling, load-time integrity checks, a VM watchdog,
  anti-debug hooks and a build-specific integrity key.
- **Layered hardening, individually switchable** via `--set key=value`:
  environment sanity checks, runtime version sealing, protected VM state, VM
  state validation, sampled bytecode integrity, runtime hook detection and
  controlled (opaque) failure routing. Dispatch can be emitted as a flat
  `cascade`, a balanced `tree`, or a per-opcode `table` lookup.
- **Encrypted payload**: constants and instructions are scrambled by a
  seed-derived LCG and decoded inside the VM at load time. The scrambled
  numbers are not emitted as bare integer tables; each numeric array is
  packed into an opaque printable **string blob** (a seed-shuffled base-45
  varint alphabet) that the VM expands back into numbers at load time, so the
  output contains no long `{123,123,123,...}` lists.
- **Token-preserving minifier** for compact output (`--minify`) alongside
  pretty output for auditing (`--pretty`).
- **CLI + Python API**: `vault-obf` on the command line or
  `from vault.compiler.pipeline import obfuscate` in code.
- **Web UI + local service**: a FastAPI service with a browser editor,
  installable as a Windows service and deployable as a static GitHub Pages
  front end.

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
`VAULT_LUA` environment variable to its path. If no interpreter is present but
[`lupa`](https://pypi.org/project/lupa/) is installed (`pip install ".[tests]"`),
the suite falls back to an in-process Lua runtime.

## Usage

```bash
# obfuscate a file with default (low) settings; write to stdout
vault-obf program.lua

# to a file, medium preset, deterministic seed, print stats
vault-obf program.lua -o p.lua -p medium -s 42 --stats

# strong preset, pretty output, then verify the result runs
vault-obf program.lua -o p.lua -p strong --pretty --verify --check-lua

# override individual protections for one build
vault-obf program.lua -p medium --set dispatch=table --set controlled_failures=true

# JSON statistics for tooling
vault-obf program.lua -o p.lua --stats --json | jq .
```

Any key from `vault/presets/config.py` can be passed with `--set`; values are
coerced to booleans, integers or floats where possible. Invalid keys are
rejected with a clear error.

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
    overrides={"dispatch": "table", "controlled_failures": True},
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
* `POST /obfuscate.json` returns `{ "output": ..., "stats": ... }`; the body
  accepts the same fields plus an `overrides` object.
* `GET /presets` returns preset defaults and the set of overridable options.
* `GET /health` and `GET /` (the editor UI) are available at `http://127.0.0.1:8000`.

### Windows service

Install the API as a background Windows service so the UI is always available:

```bash
pip install ".[service]"        # pywin32
vault-obf service install
vault-obf service start
vault-obf service status
vault-obf service stop
vault-obf service remove
```

Host/port can be overridden with `var/service.json` (gitignored) or the
`VAULT_API_HOST` / `VAULT_API_PORT` environment variables. Without `pywin32`,
`vault-obf service debug` runs the API in the foreground instead.

### Static web UI

`web/static/` is a dependency-free front end (drag-and-drop `.lua`/`.luau`
loading, syntax highlighting, build stats and diagnostics, dark/light theme).
It can be hosted anywhere and pointed at a local service with
`?api=http://host:port`; `.github/workflows/pages.yml` publishes it to GitHub
Pages on changes.

## Presets

| preset   | opcode shuffle | proto/const shuffle | load integrity | dispatch | runtime hardening                                              | output   |
|----------|----------------|---------------------|----------------|----------|----------------------------------------------------------------|----------|
| `low`    | yes            | const/upval         | 3 regions      | cascade  | none                                                           | minified |
| `medium` | yes            | + proto             | 4 regions      | cascade  | watchdog, env sanity, version seal, protected state            | minified |
| `strong` | yes            | + proto             | 5 regions      | tree     | + anti-debug, hook detection, state validation, bytecode verify, controlled failures | pretty   |

The exact mix of protections available at each level is defined in
`vault/presets/config.py`. Every field can be overridden per build with
`--set` (CLI), the `overrides` argument (Python) or the `overrides` object
(HTTP).

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

1. the encoded payload table `Q`, whose numeric arrays are embedded as opaque
   printable string blobs and expanded by a small load-time decoder,
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
source on a real interpreter. When no `lua` binary is on `PATH` the suite uses
the bundled `lupa` fallback (`tools/run_lua.py`), and only skips when neither
is available. Set `VAULT_LUA` to point at a specific binary, e.g.:

```bash
VAULT_LUA=/usr/bin/lua5.1 python -m pytest tests -q
```

## License

MIT. See `LICENSE`.