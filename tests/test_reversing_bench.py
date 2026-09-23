"""Smoke tests for the reversing-evidence benchmark tool."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def _run_bench(tmp_path, *extra) -> subprocess.CompletedProcess:
    out = tmp_path / "report"
    return subprocess.run(
        [
            sys.executable,
            str(TOOLS / "reversing_bench.py"),
            "--preset", "strong",
            "--seeds", "2",
            "--base-seed", "11",
            "--out", str(out),
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )


def test_bench_writes_md_and_json(tmp_path):
    proc = _run_bench(tmp_path)
    assert proc.returncode == 0, proc.stderr
    md = tmp_path / "report.md"
    js = tmp_path / "report.json"
    assert md.exists()
    assert js.exists()
    report = json.loads(js.read_text(encoding="utf-8"))
    assert report["preset"] == "strong"
    assert len(report["vault"]["runs"]) == 2
    assert report["seeds"] == [11, 12]
    assert 0.0 <= report["vault"]["recoverability"] <= 1.0
    assert 0.0 <= report["vault"]["cross_fingerprint"] <= 1.0
    assert "# Reversing evidence benchmark" in md.read_text(encoding="utf-8")


def test_bench_strong_shuffles_frame_metric(tmp_path):
    """The protected-VM-state shuffle must flip the sequential-frame tell."""
    out_strong = tmp_path / "strong"
    subprocess.run(
        [
            sys.executable,
            str(TOOLS / "reversing_bench.py"),
            "--preset", "strong", "--seeds", "1", "--base-seed", "3",
            "--out", str(out_strong),
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    out_low = tmp_path / "low"
    subprocess.run(
        [
            sys.executable,
            str(TOOLS / "reversing_bench.py"),
            "--preset", "low", "--seeds", "1", "--base-seed", "3",
            "--out", str(out_low),
        ],
        capture_output=True,
        text=True,
        timeout=600,
    )
    strong = json.loads(
        (tmp_path / "strong.md").with_suffix(".json").read_text(encoding="utf-8")
    )
    low = json.loads(
        (tmp_path / "low.md").with_suffix(".json").read_text(encoding="utf-8")
    )
    assert strong["vault"]["runs"][0]["metrics"]["sequential_frame"] is False
    assert low["vault"]["runs"][0]["metrics"]["sequential_frame"] is True
    assert strong["vault"]["recoverability"] < low["vault"]["recoverability"]