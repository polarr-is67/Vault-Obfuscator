"""Run the Vault-Obf web service with ``python -m web``."""

from __future__ import annotations

import argparse


def main(argv=None) -> None:
    parser = argparse.ArgumentParser(prog="python -m web", description="Run the Vault-Obf web service.")
    parser.add_argument("--host", default="127.0.0.1", help="bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="bind port (default: 8080)")
    args = parser.parse_args(argv)

    import uvicorn

    uvicorn.run("web.app:app", host=args.host, port=args.port)


if __name__ == "__main__":
    main()