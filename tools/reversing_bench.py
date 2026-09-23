"""Reversing-evidence benchmark for Vault-obf builds.

Measures how easily an automated analyst can recover structural fingerprints
from a build, using a battery of cheap grep-level heuristics that real
tooling (and humans grepping) rely on:

  * leaked sentinel string literals
  * leaked source identifiers
  * a recognizable ``op==``-style dispatch ladder (the classic VM tell)
  * a recognizable handler-closure table (``function(I,cd,cs,regs,sk)``)
  * a sequential frame-slot locator block (``local a=1 local b=2 ...``)
  * the interpreter's main ``while`` loop surface
  * cross-build structural correlation (same source, different seeds)

For a quick vocabulary: "recoverability" is 0.0 (nothing jumped out to the
grep) to 1.0 (fully textbook layout).  The VM's own claim is that strong
presets should be well below 0.35 while a bare reference build hovers near
0.9.

Usage::

    python tools/reversing_bench.py [--preset strong] [--target lua51]
        [--seeds 5] [--base-seed 1] [--minify]
        [--choco-command "ruby choco.py {in} > {out}"]
        [--out docs/evidence/reversing-bench]
``--choco-command`` optionally runs a reference obfuscator on the same
        source; ``{inp}`` and ``{outp}`` are substituted with the source and
        expected output file paths.  A single MD + JSON report is written next
        to ``--out``.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from difflib import SequenceMatcher
from pathlib import Path
from typing import Dict, List, Optional

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vault.compiler.pipeline import obfuscate  # noqa: E402

SENTINELS = ["vault_alpha_77", "u_deep_vermin_99"]

BENCH_SOURCE = """\
local function fib(x)
  if x < 2 then return x end
  return fib(x - 1) + fib(x - 2)
end
local items = {}
for i = 1, 8 do items[#items + 1] = fib(i) end
local accum = 0
for _, vk in pairs(items) do accum = accum + vk end
local msg = "vault_alpha_77:" .. tostring(accum)
print(msg)
"""

BENCH_IDS = ["fib", "items", "accum", "msg", "vk"]


def _identifiers(src: str) -> List[str]:
    return re.findall(r"[A-Za-z_][A-Za-z0-9_]*", src)


def _leaked_sentinels(out: str) -> List[str]:
    return [s for s in SENTINELS if s in out]


def _leaked_ids(out: str) -> List[str]:
    return [i for i in BENCH_IDS if re.search(r"\b" + re.escape(i) + r"\b", out)]


def _op_ladder_count(out: str) -> int:
    """Count ``op==N`` comparison sites (minified output has no spaces)."""
    return len(re.findall(r"\bop==\d+", out))


def _handler_table_count(out: str) -> int:
    """Count handler closures shaped ``function(I,cd,cs,regs,sk)``.

    Field names are randomized so we match arity only: any anonymous
    five-argument function is suspect.
    """
    return len(re.findall(r"function\((\w+),(\w+),(\w+),(\w+),(\w+)\)", out))


def _sequential_frame_block(out: str) -> bool:
    """True when a contiguous ``local a=1 local b=2 ... local k=11`` block
    survives.  This is the pre-shuffle frame-slot tell."""
    pattern = r"local \w+=1 "
    for i in range(2, 12):
        pattern += r"local \w+=" + str(i) + r" "
    return re.search(pattern, out) is not None


def _while_loops(out: str) -> int:
    return len(re.findall(r"\bwhile ", out))


def _score(out: str) -> Dict[str, object]:
    sent = _leaked_sentinels(out)
    ids = _leaked_ids(out)
    ladder = _op_ladder_count(out)
    handlers = _handler_table_count(out)
    frame = _sequential_frame_block(out)
    loops = _while_loops(out)
    return {
        "leaked_sentinels": sent,
        "leaked_ids": ids,
        "op_ladder_count": ladder,
        "handler_closures": handlers,
        "sequential_frame": frame,
        "while_loops": loops,
    }


def _recoverability(m: Dict[str, object]) -> float:
    # All metrics normalised to 0..1 where higher = more recoverable.
    strings = min(1.0, len(m["leaked_sentinels"]) / len(SENTINELS))
    ids = min(1.0, len(m["leaked_ids"]) / len(BENCH_IDS))
    ladder = 1.0 if m["op_ladder_count"] > 0 else 0.0
    handlers = min(1.0, m["handler_closures"] / 8.0)
    frame = 1.0 if m["sequential_frame"] else 0.0
    loops = min(1.0, m["while_loops"] / 5.0)
    weights = (0.30, 0.20, 0.15, 0.15, 0.15, 0.05)
    raw = (
        strings * weights[0]
        + ids * weights[1]
        + ladder * weights[2]
        + handlers * weights[3]
        + frame * weights[4]
        + loops * weights[5]
    )
    return round(raw, 3)


def _run_vault(source: str, preset: str, target: str, seed: int,
               minify: bool) -> str:
    res = obfuscate(
        source, seed=seed, target=target, preset=preset,
        minify=minify, verify=False,
    )
    return res.output


def _run_choco(source: str, command: str) -> Optional[str]:
    """Run the reference obfuscator ``command`` with {in}/{out} substituted."""
    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        inp = tmpdir / "bench_in.lua"
        out = tmpdir / "bench_out.lua"
        inp.write_text(source, encoding="utf-8")
        argv = command.format(inp=str(inp), outp=str(out))
        try:
            proc = subprocess.run(
                argv, shell=True, capture_output=True, text=True,
                timeout=300,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            print(f"  choco command failed: {exc}", file=sys.stderr)
            return None
        if out.exists():
            return out.read_text(encoding="utf-8")
        # Fall back to stdout if the command only prints the build.
        return proc.stdout or None


def _write_report(path: Path, report: Dict[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    md = _render_markdown(report)
    path.write_text(md, encoding="utf-8")
    path.with_suffix(".json").write_text(
        json.dumps(report, indent=2), encoding="utf-8",
    )
    print(f"  -> {path}")


def _render_markdown(report: Dict[str, object]) -> str:
    ln = []
    ln.append("# Reversing evidence benchmark\n")
    ln.append(f"Generated: {report['generated']}  ")
    ln.append(f"Source: {len(str(report['source']))} bytes, "
              f"{report['runs']} vault builds, "
              f"target `{report['target']}`, preset `{report['preset']}`.\n")
    ln.append("Heuristics are the low-cost greps an analyst fires first; "
              "lower `recoverability` (0..1) means less structure stood out "
              "to a textual sweep.  `cross_fingerprint` is the byte-level "
              "structural similarity between two builds of the same source "
              "at different seeds (lower = builds look less alike).\n")
    ln.append("| metric | description |")
    ln.append("|---|---|")
    for m in report["metric_descriptions"]:
        ln.append(f"| `{m['name']}` | {m['desc']} |")
    ln.append("")
    v = report["vault"]
    ln.append("## Vault-obf\n")
    ln.append(f"- aggregate recoverability: **{v['recoverability']}** "
              f"(per-build: {', '.join(str(x) for x in v['per_run_recoverability'])})\n")
    ln.append("| run | size | recoverability | sentinels | ids | op== | "
              "handlers | seq-frame | while |")
    ln.append("|---|---|---|---|---|---|---|---|---|")
    for i, run in enumerate(v["runs"]):
        m = run["metrics"]
        ln.append(
            f"| {i} | {run['size_kb']:.1f} KB | {run['recoverability']} | "
            f"{len(m['leaked_sentinels'])} | {len(m['leaked_ids'])} | "
            f"{m['op_ladder_count']} | {m['handler_closures']} | "
            f"{'yes' if m['sequential_frame'] else 'no'} | {m['while_loops']} |"
        )
    ln.append("")
    seeds = ", ".join(str(s) for s in report["seeds"])
    ln.append(f"- seeds used: `{seeds}`")
    ln.append(f"- cross-build fingerprint (same source, two seeds): "
              f"**{v.get('cross_fingerprint')}**\n")
    if report.get("choco") is not None:
        c = report["choco"]
        ln.append("## Reference obfuscator (choco)\n")
        ln.append(f"- recoverability: **{c['recoverability']}**  ")
        ln.append(f"- size: {c['size_kb']:.1f} KB\n")
        m = c["metrics"]
        ln.append("| sentinels | ids | op== | handlers | seq-frame | while |")
        ln.append("|---|---|---|---|---|---|")
        ln.append(
            f"| {len(m['leaked_sentinels'])} | {len(m['leaked_ids'])} | "
            f"{m['op_ladder_count']} | {m['handler_closures']} | "
            f"{'yes' if m['sequential_frame'] else 'no'} | {m['while_loops']} |"
        )
        ratio = None
        if v["recoverability"] > 0:
            ratio = round(c["recoverability"] / v["recoverability"], 2)
        ln.append(f"\n- choco/vault recoverability ratio: **{ratio}** (higher "
                  f"= vault is harder to grep-recover)\n")
    else:
        ln.append("_No choco run configured "
                  "(`--choco-command`); vault-only report._\n")
    return "\n".join(ln) + "\n"


_METRIC_DESCRIPTIONS = [
    {"name": "sentinels", "desc": "benchmark sentinel literals quoted "
     "verbatim in the output (0 is the goal)"},
    {"name": "ids", "desc": "source identifiers that survive verbatim"},
    {"name": "op==", "desc": "opcode-dispatch comparison sites "
     "(`op==N` cascade recognisability)"},
    {"name": "handlers", "desc": "anonymous five-argument closures matching "
     "the VM handler-closure signature"},
    {"name": "seq-frame", "desc": "sequential `local a=1..local k=11` "
     "frame-slot locator block surviving in the output"},
    {"name": "while", "desc": "`while` loop occurrences (interpreter loop "
     "surface)"},
]


def main(argv: List[str]) -> int:
    preset = "strong"
    target = "lua51"
    seeds = 5
    base_seed = 1
    minify = True
    choco_cmd: Optional[str] = None
    out_path = Path("docs/evidence/reversing-bench")

    args = iter(argv)
    for arg in args:
        if arg == "--preset":
            preset = next(args)
        elif arg == "--target":
            target = next(args)
        elif arg == "--seeds":
            seeds = int(next(args))
        elif arg == "--base-seed":
            base_seed = int(next(args))
        elif arg == "--choco-command":
            choco_cmd = next(args)
        elif arg == "--out":
            out_path = Path(next(args))
        elif arg == "--minify":
            minify = True
        elif arg == "--no-minify":
            minify = False
        else:
            print(f"unknown flag: {arg}", file=sys.stderr)
            return 2

    print(f"reversing_bench: preset={preset} target={target} runs={seeds}")
    print(f"building {seeds} vault outputs ...")
    runs = []
    outputs: List[str] = []
    for i in range(seeds):
        seed = base_seed + i
        out = _run_vault(BENCH_SOURCE, preset, target, seed, minify)
        outputs.append(out)
        metrics = _score(out)
        rec = _recoverability(metrics)
        runs.append({
            "seed": seed,
            "size_kb": round(len(out.encode("utf-8")) / 1024, 1),
            "recoverability": rec,
            "metrics": metrics,
        })
        print(f"  seed {seed}: {len(out)} bytes, recoverability {rec}")

    cross = None
    if len(outputs) > 1:
        cross = round(SequenceMatcher(None, outputs[-2], outputs[-1]).ratio(), 3)
        print(f"  cross-build fingerprint (last two seeds): {cross}")

    vault_block = {
        "recoverability": round(
            sum(r["recoverability"] for r in runs) / len(runs), 3
        ),
        "cross_fingerprint": cross,
        "per_run_recoverability": [r["recoverability"] for r in runs],
        "runs": runs,
    }

    choco_block = None
    if choco_cmd:
        print("running reference obfuscator ...")
        choco_out = _run_choco(BENCH_SOURCE, choco_cmd)
        if choco_out:
            cm = _score(choco_out)
            choco_block = {
                "recoverability": _recoverability(cm),
                "size_kb": round(len(choco_out.encode("utf-8")) / 1024, 1),
                "metrics": cm,
            }
    else:
        print("no --choco-command, skipping reference comparison")

    report = {
        "generated": __import__("datetime").datetime.now().isoformat(timespec="seconds"),
        "source": BENCH_SOURCE,
        "runs": seeds,
        "target": target,
        "preset": preset,
        "seeds": list(range(base_seed, base_seed + seeds)),
        "metric_descriptions": _METRIC_DESCRIPTIONS,
        "vault": vault_block,
        "choco": choco_block,
    }

    _write_report(Path(str(out_path) + ".md"), report)
    print(f"done. aggregate recoverability: {vault_block['recoverability']}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))