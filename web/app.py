"""Vault-Obf web service.

A thin FastAPI wrapper around :func:`vault.compiler.pipeline.obfuscate`.
Run it directly with ``python -m web`` or with uvicorn:

    uvicorn web.app:app --port 8000

Endpoints:

* ``GET  /health``      service status and version
* ``GET  /presets``     preset defaults and the set of overridable options
* ``POST /obfuscate``   obfuscate Lua source, returns plain Lua text
* ``POST /obfuscate.json`` obfuscate and return JSON with stats
* ``GET  /``            small browser UI (served from :data:`web/static`)
* ``GET  /styles.css`` / ``/config.js`` / ``/app.js`` / ``/favicon.ico``
  the frontend assets, served at the site root.

The service is designed to be driven both from the bundled UI and from a
statically hosted site (for example the project's GitHub Pages build), so it
ships with permissive CORS; it is a local build helper and should not be
exposed to untrusted networks.
"""

from __future__ import annotations

import random
from pathlib import Path
from typing import Any, Callable, Dict

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from vault import VaultError
from vault.compiler.pipeline import obfuscate
from vault.presets.config import PRESETS, PresetConfig

__version__ = "1.0.0"

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(
    title="Vault-Obf",
    description="VM-based source obfuscator/compiler for Lua 5.1 and Luau.",
    version=__version__,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
    # Allow a page served from a public origin (e.g. GitHub Pages) to call this
    # loopback service under Chrome's Private Network Access preflight.
    allow_private_network=True,
)


class ObfuscateRequest(BaseModel):
    """JSON body accepted by the obfuscation endpoints."""

    source: str = Field(..., description="Lua 5.1 / Luau source text.")
    seed: int = Field(0, description="Deterministic build seed.")
    target: str = Field("lua51", description='"lua51" or "luau".')
    preset: str = Field("low", description='"low", "medium" or "strong".')
    pretty: bool = Field(False, description="Pretty-print the VM source.")
    minify: bool = Field(False, description="Emit a compact minified script.")
    verify: bool = Field(False, description="Re-parse output as a sanity check.")
    debug: bool = Field(False, description="Keep debug metadata in the build.")
    overrides: Dict[str, Any] = Field(
        default_factory=dict,
        description="Per-build preset overrides, e.g. {'dispatch': 'table'}.",
    )


def _build(request: ObfuscateRequest):
    try:
        seed = request.seed or random.randrange(1 << 63)
        return obfuscate(
            request.source,
            seed=seed,
            target=request.target,
            preset=request.preset,
            pretty=True if request.pretty else None,
            minify=True if request.minify else None,
            verify=request.verify,
            debug=request.debug,
            overrides=request.overrides or None,
        )
    except VaultError as exc:
        raise HTTPException(status_code=400, detail=exc.format()) from exc


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "version": __version__}


def create_app() -> FastAPI:
    """Return the configured ASGI application.

    Provided as a factory so service runners (``python -m vault.service``)
    can obtain the app without importing the module-level singleton.
    """
    return app


@app.get("/presets")
def presets() -> dict:
    """Return preset defaults and the set of options that may be overridden."""
    return {
        "presets": {name: dict(data) for name, data in PRESETS.items()},
        "known_options": sorted(PresetConfig.__dataclass_fields__),
    }


@app.post("/obfuscate", response_class=PlainTextResponse)
def obfuscate_endpoint(request: ObfuscateRequest) -> str:
    """Compile ``source`` and return the protected Lua script as text."""
    result = _build(request)
    return result.output


@app.post("/obfuscate.json")
def obfuscate_json(request: ObfuscateRequest) -> dict:
    """Compile ``source`` and return ``{"output": ..., "stats": ...}``."""
    result = _build(request)
    return {"output": result.output, "stats": result.stats.to_dict()}


@app.exception_handler(VaultError)
async def _vault_error_handler(_req: Request, exc: VaultError):
    return PlainTextResponse(exc.format(), status_code=400)


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


# ``static/index.html`` references its assets with relative URLs
# (``styles.css``, ``config.js``, ``app.js``) so that the same folder works
# when dropped at the root of a static host such as GitHub Pages.  Served
# from this app at ``/`` those requests resolve against the site root, so the
# files must answer there too.  We register explicit routes instead of
# mounting ``StaticFiles`` at ``/``: a root mount would shadow routes
# registered afterwards and make every unknown path hit the static handler.
_ROOT_ASSETS = {
    "styles.css": "text/css",
    "config.js": "application/javascript",
    "app.js": "application/javascript",
}


def _asset_endpoint(filename: str, media_type: str) -> Callable[[], FileResponse]:
    def _serve() -> FileResponse:
        return FileResponse(STATIC_DIR / filename, media_type=media_type)

    return _serve


for _name, _media_type in _ROOT_ASSETS.items():
    app.get(
        f"/{_name}",
        include_in_schema=False,
        name=f"asset_{_name}",
    )(_asset_endpoint(_name, _media_type))


@app.get("/favicon.ico", include_in_schema=False)
def favicon() -> Response:
    """Serve a favicon when one is present, otherwise answer 204."""
    icon = STATIC_DIR / "favicon.ico"
    if icon.is_file():
        return FileResponse(icon, media_type="image/x-icon")
    return Response(status_code=204)
