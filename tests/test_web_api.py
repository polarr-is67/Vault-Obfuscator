"""Tests for the optional FastAPI web service (skipped if fastapi absent)."""

import pytest

try:
    from fastapi.testclient import TestClient
except Exception:  # pragma: no cover
    TestClient = None

from web.app import app


@pytest.mark.skipif(TestClient is None, reason="fastapi/httpx not installed")
def test_health():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


@pytest.mark.skipif(TestClient is None, reason="fastapi/httpx not installed")
def test_obfuscate_json():
    client = TestClient(app)
    resp = client.post(
        "/obfuscate.json",
        json={"source": 'print("hi")', "preset": "low", "target": "lua51", "seed": 7},
    )
    assert resp.status_code == 200
    payload = resp.json()
    assert "output" in payload and "stats" in payload
    assert "local" in payload["output"]


@pytest.mark.skipif(TestClient is None, reason="fastapi/httpx not installed")
def test_obfuscate_bad_source_is_400():
    client = TestClient(app)
    resp = client.post("/obfuscate", json={"source": "print("})
    assert resp.status_code == 400


@pytest.mark.skipif(TestClient is None, reason="fastapi/httpx not installed")
def test_ui_index():
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Vault-Obf" in resp.text