"""Command-line interface for Vault-Obf."""

from __future__ import annotations

import argparse
import json
import os
import random
import subprocess
import sys
from typing import List, Optional

from vault import VaultError
from vault.compiler.pipeline import obfuscate
from vault.presets.config import PRESETS
from vault.targets import TARGETS

DEFAULT_LUA_NAMES = ("lua", "lua51", "lua5.1", "lua53", "lua5.3", "lua54", "lua5.4", "luau")


def find_lua(explicit: Optional[str] = None) -> Optional[str]:
    """Locate a Lua interpreter for ``--check-lua``.

    Preference order: explicit argument, ``VAULT_LUA`` environment
    variable, then known interpreter names on ``PATH``.
    """
    import shutil

    if explicit:
        return explicit
    from_env = os.environ.get("VAULT_LUA")
    if from_env and os.path.isfile(from_env):
        return from_env
    for name in DEFAULT_LUA_NAMES:
        path = shutil.which(name)
        if path:
            return path
    return None


def _check_lua(interpreter: str, output_path: str) -> int:
    """Run the generated script and report the verdict.

    Returns 0 when the script exited 0 and produced no error output,
    2 when the script failed to run, and 1 when no interpreter is
    available.
    """
    try:
        proc = subprocess.run(
            [interpreter, output_path],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except FileNotFoundError:
        print(f"error: interpreter not found: {interpreter}", file=sys.stderr)
        return 1
    except subprocess.TimeoutExpired:
        print("check-lua: timed out after 120s", file=sys.stderr)
        return 2
    if proc.returncode != 0:
        print("check-lua: FAILED", file=sys.stderr)
        print(proc.stderr.strip()[:2000], file=sys.stderr)
        return 2
    if proc.stderr.strip():
        print("check-lua: OK (with stderr output)", file=sys.stderr)
        print(proc.stderr.strip()[:2000], file=sys.stderr)
        return 2
    print("check-lua: OK")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vault-obf",
        description="VM-based source obfuscator/compiler for Lua 5.1 and Luau.",
        epilog=(
            "The output is a self-contained Lua script that embeds a virtual "
            "machine which executes the original program's bytecode at runtime."
        ),
    )
    parser.add_argument(
        "input",
        metavar="SOURCE",
        help="input Lua file, or '-' to read from stdin",
    )
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="output file (default: stdout)",
    )
    parser.add_argument(
        "-s", "--seed",
        type=int,
        default=None,
        help="deterministic build seed (default: random)",
    )
    parser.add_argument(
        "-p", "--preset",
        default="low",
        choices=sorted(PRESETS),
        help="obfuscation strength preset (default: low)",
    )
    parser.add_argument(
        "-t", "--target",
        default="lua51",
        choices=sorted(TARGETS),
        help="Lua dialect to target (default: lua51)",
    )
    fmt = parser.add_mutually_exclusive_group()
    fmt.add_argument(
        "--pretty",
        action="store_true",
        help="pretty-print the VM source",
    )
    fmt.add_argument(
        "--minify",
        action="store_true",
        help="emit a compact minified script",
    )
    parser.add_argument(
        "--verify",
        action="store_true",
        help="re-parse the output as a well-formedness check",
    )
    parser.add_argument(
        "--check-lua",
        nargs="?",
        const="",
        metavar="EXE",
        help=(
            "run the generated script against a Lua interpreter and report "
            "the verdict (uses VAULT_LUA or PATH when EXE is omitted)"
        ),
    )
    parser.add_argument(
        "--stats",
        action="store_true",
        help="print build statistics",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit statistics as a JSON object",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="keep debug metadata in the build",
    )
    return parser


def _emit_stats(result, args) -> None:
    if args.json:
        payload = result.stats.to_dict()
        payload["preset"] = result.stats.preset
        payload["target"] = result.stats.target
        payload["seed"] = result.stats.seed
        print(json.dumps(payload))
        return
    print(result.stats.format_cli())


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        if args.input == "-":
            source = sys.stdin.read()
        else:
            with open(args.input, "r", encoding="utf-8") as fh:
                source = fh.read()

        seed = args.seed if args.seed is not None else random.randrange(1 << 63)
        result = obfuscate(
            source,
            seed=seed,
            target=args.target,
            preset=args.preset,
            pretty=True if args.pretty else None,
            minify=True if args.minify else None,
            verify=args.verify,
            debug=args.debug,
        )
    except VaultError as exc:
        print(exc.format(), file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"config error:\n{exc}", file=sys.stderr)
        return 1

    if args.output and args.output != "-":
        with open(args.output, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(result.output)
    else:
        sys.stdout.write(result.output)

    if args.stats:
        _emit_stats(result, args)

    if args.check_lua is not None:
        if not args.output or args.output == "-":
            print(
                "error: --check-lua requires -o/--output to write the script first",
                file=sys.stderr,
            )
            return 1
        interpreter = find_lua(args.check_lua or None)
        if interpreter is None:
            print(
                "error: no Lua interpreter found; set VAULT_LUA or install lua",
                file=sys.stderr,
            )
            return 1
        return _check_lua(interpreter, args.output)

    return 0


if __name__ == "__main__":
    sys.exit(main())