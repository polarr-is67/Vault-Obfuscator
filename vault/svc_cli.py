"""``vault-obf service`` subcommand implementation.

Delegates each command to ``python -m vault.service`` so the pywin32
service framework is driven exactly as if the service module had been
invoked directly, without requiring the optional extra in the caller.
"""

from __future__ import annotations

import subprocess
import sys
from typing import List, Optional

SERVICE_VERBS = ("install", "start", "stop", "remove", "restart", "update", "debug", "status")


def _status() -> int:
    """Query the service state with ``sc.exe`` (always available on Windows)."""
    try:
        proc = subprocess.run(
            ["sc", "query", "VaultObfWeb"],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"service: could not query status: {exc}", file=sys.stderr)
        return 1
    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("STATE"):
            state = line.split(":", 1)[1].strip()
            print(f"VaultObfWeb service: {state}")
            return 0
    print(proc.stdout.strip() or proc.stderr.strip(), file=sys.stderr)
    return 1


def main(argv: Optional[List[str]] = None) -> int:
    """Run one ``service`` command."""
    argv = argv if argv is not None else sys.argv[1:]
    if not argv or argv[0] not in SERVICE_VERBS:
        print(
            "usage: vault-obf service <"
            + "|".join(SERVICE_VERBS)
            + ">",
            file=sys.stderr,
        )
        return 2
    verb = argv[0]
    if verb == "status":
        return _status()
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "vault.service"] + [verb],
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"service: {exc}", file=sys.stderr)
        return 1
    sys.stdout.write(proc.stdout)
    sys.stderr.write(proc.stderr)
    return proc.returncode


if __name__ == "__main__":
    sys.exit(main())