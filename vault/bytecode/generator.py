"""IR to bytecode-image generation.

The generator takes the list of IR prototypes produced by the IR builder and
renders them into a compact :class:`BytecodeImage`:

* instructions are flattened into ``[op,a,b,c,d,e]`` integer tuples,
* logical opcode codes are optionally permuted per build,
* constant pools are shuffled with instruction operand remapping,
* prototype ordering is optionally shuffled with child-reference remapping.

All randomization is driven by a :class:`DeterministicRandom` seeded from the
build seed, making builds reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from vault.bytecode.instructions import OPCODE_LIST, OPCODE_COUNT, OPCODE_NAMES
from vault.ir.builder import IRInstr, IRProto, IRBuilder
from vault.utils.random import DeterministicRandom


@dataclass
class ProtoImage:
    """Serialized prototype record."""

    proto_id: int
    params: int
    is_vararg: bool
    maxstack: int
    constants: List[object] = field(default_factory=list)
    code: List[int] = field(default_factory=list)
    children: List[int] = field(default_factory=list)
    upvals: List[tuple] = field(default_factory=list)


@dataclass
class BytecodeImage:
    """The full compiled bytecode image."""

    protos: List[ProtoImage] = field(default_factory=list)
    opmap: List[int] = field(default_factory=list)  # logical code -> emitted code
    protomap: Dict[int, int] = field(default_factory=dict)  # ir id -> emitted id
    seed_int: int = 0


class BytecodeGenerator:
    """Renders IR prototypes into a :class:`BytecodeImage`."""

    def __init__(
        self,
        rng: DeterministicRandom,
        preset_config=None,
    ) -> None:
        self.rng = rng
        self.preset = preset_config

    def generate(self, ir_protos: List[IRProto]) -> BytecodeImage:
        image = BytecodeImage(seed_int=self.rng.seed_int())

        # opcode permutation
        codes = list(range(OPCODE_COUNT))
        if self.preset is None or self.preset.get("opcode_permute", True):
            self.rng.shuffle(codes)
        image.opmap = codes

        # prototype order permutation
        n = len(ir_protos)
        order = list(range(n))
        if self.preset is not None and self.preset.get("proto_shuffle", False) and n > 1:
            self.rng.shuffle(order)
        for new_id, old_id in enumerate(order):
            image.protomap[old_id] = new_id

        for old_id in range(n):
            proto = ir_protos[old_id]
            new_id = image.protomap[old_id]
            pim = self._emit_proto(proto, image)
            image.protos.append(pim)
        # protos must be sorted by new_id
        image.protos.sort(key=lambda p: p.proto_id)
        return image

    def _emit_proto(self, proto: IRProto, image: BytecodeImage) -> ProtoImage:
        new_id = image.protomap[proto.proto_id]
        pim = ProtoImage(
            proto_id=new_id,
            params=proto.params,
            is_vararg=proto.is_vararg,
            maxstack=proto.maxstack,
        )
        # shuffle constants and build remap
        const_indexing = list(range(len(proto.constants)))
        if self.preset is not None and self.preset.get("const_shuffle", True) and len(const_indexing) > 1:
            self.rng.shuffle(const_indexing)
        remap = {(idx): new_idx for new_idx, idx in enumerate(const_indexing)}
        pim.constants = [proto.constants[i] for i in const_indexing]

        # shuffle children (they are proto ids)
        child_remap = [image.protomap[c] for c in proto.children]

        # shuffle upvalue descriptor order and build remap for SETUPVAL/GETUPVAL
        upval_order = list(range(len(proto.upvaldescs)))
        if self.preset is not None and self.preset.get("upval_shuffle", True) and len(upval_order) > 1:
            self.rng.shuffle(upval_order)
        upval_remap = {old: new for new, old in enumerate(upval_order)}
        pim.upvals = [
            (bool(proto.upvaldescs[i].instack), proto.upvaldescs[i].idx)
            for i in upval_order
        ]

        # emit instructions
        for ins in proto.instructions:
            pim.code.extend(self._emit_instruction(ins, image, remap))
        pim.children = list(child_remap)
        return pim

    def _emit_instruction(self, ins: IRInstr, image: BytecodeImage, remap) -> List[int]:
        op = OPCODE_NAMES[ins.op]
        mapped = image.opmap[op]
        a, b, c, d, e = ins.a, ins.b, ins.c, ins.d, ins.e
        # remap constant indices
        if ins.op in ("LOADCONST", "LOADGLOBAL", "STOREGLOBAL"):
            b = remap[b]
        # CLOSURE's b holds a child proto id -> PT index (1-based, emitted order)
        if ins.op == "CLOSURE":
            b = image.protomap[b] + 1
        # NOP / MARK handled naturally (d holds resolved pc for MARK too)
        return [mapped, a, b, c, d, e]