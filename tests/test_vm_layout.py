"""VM frame-layout tests.

The protected-VM-state option permutes the numeric meaning of every frame
slot locator (``K_P``..``K_M`` = 1..11 by default) between builds, and the
frame constructor tables are always keyed by those locators rather than
positionally addressed.  These tests render the runtime directly through
``build_runtime_source`` with a fixed name map so the locator values are
exact and greppable.
"""

from __future__ import annotations

import re

import pytest

from vault.vm.runtime import build_runtime_source

# Fixed name map so the locator identifiers are predictable in the output.
LOC_IDS = {
    "KP": "fp1", "KI": "fp2", "KR": "fp3", "KE": "fp4",
    "KN": "fp5", "KO": "fp6", "KU": "fp7", "KV": "fp8",
    "KB": "fp9", "KD": "fp10", "KM": "fp11",
}
SEQ = list(range(1, 12))


def _render(seed: int, protected: bool) -> str:
    from vault.vm.runtime import RUNTIME_NAMES

    full = {}
    for i, nm in enumerate(RUNTIME_NAMES):
        full[nm] = LOC_IDS.get(nm, f"gx{i}")
    cfg = {"seed": seed, "protected_vm_state": protected}
    return build_runtime_source(full, cfg)


def _slots(text: str, tag: str) -> int:
    m = re.search(r"local " + tag + r"=(\d+)", text)
    assert m, f"locator {tag} not found"
    return int(m.group(1))


def _layout(text: str) -> list:
    return [_slots(text, f"fp{i}") for i in range(1, 12)]


def test_low_uses_sequential_layout():
    txt = _render(seed=7, protected=False)
    assert _layout(txt) == SEQ
    # sequential meaning: FP1 == slot 1, FP2 == slot 2, ...
    assert [_slots(txt, f"fp{i}") for i in range(1, 12)] == SEQ


@pytest.mark.parametrize("seed", [1, 7, 31337])
def test_protected_shuffles_layout(seed):
    txt = _render(seed=seed, protected=True)
    layout = _layout(txt)
    assert sorted(layout) == SEQ  # still a bijection over 1..11
    assert layout != SEQ  # but no longer identity


def test_protected_layout_varies_by_seed():
    a = _layout(_render(seed=1, protected=True))
    b = _layout(_render(seed=2, protected=True))
    assert a != b


def test_protected_layout_deterministic():
    a = _render(seed=99, protected=True)
    b = _render(seed=99, protected=True)
    assert a == b
    assert _layout(a) == _layout(b)


def test_frames_are_keyed_not_positional():
    for seed, protected in ((5, False), (5, True), (42, True)):
        txt = _render(seed=seed, protected=protected)
        # Bootstrap frame plus the CALL-handler frame are built with the
        # keyed locators, so no positional frame constructor survives.
        assert "[fp1]=pr" in txt or "fp1]=pr" in txt
        assert "{pr,1,{},{},0,{},upcells" not in txt
        assert "{box[1],1,{}" not in txt
        # and every slot locator is declared exactly once
        for i in range(1, 12):
            assert len(re.findall(r"local fp%d=\d+" % i, txt)) == 1