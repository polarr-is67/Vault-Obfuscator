"""Bytecode encoding and data protection.

The encoder renders a :class:`~vault.bytecode.generator.BytecodeImage` into
the encoded payload that the embedded VM decodes at runtime.  Nothing
resembling original source survives; constant pools are shuffled and
arithmetically encoded, instruction words are offset by a per-build key
stream, and independent integrity checksums are computed over distinct
regions of the payload.

Every transform is driven by a deterministic PRNG, so ``--seed`` builds are
byte-for-byte reproducible.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Tuple

from vault.bytecode.generator import BytecodeImage
from vault.utils.random import DeterministicRandom

#: Checked-sum modulus (a prime; safe under double arithmetic).
SUM_MOD = (1 << 31) - 1

#: Position of the payload records in the runtime `Q` table: [1]=LCG params,
#: [2]=integrity, [3]=metamethod keys, [4]=error messages, [5..]=prototypes.
META_RECORD_IDX = 3
MSG_RECORD_IDX = 4
PROTO_RECORD_BASE = 5


@dataclass
class EncodedProto:
    """One encoded prototype blob, ready to be embedded as Lua data."""

    proto_id: int
    params: int
    is_vararg: bool
    maxstack: int
    children: List[int] = field(default_factory=list)
    upvals: List[Tuple[int, int]] = field(default_factory=list)
    code_blob: List[int] = field(default_factory=list)
    const_blob: List[int] = field(default_factory=list)


@dataclass
class DecodeParams:
    """Parameters the VM must know to decode the payload."""

    lcg_a: int
    lcg_c: int
    lcg_m: int
    lcg_s0: int
    stride: int
    str_shift: int
    int_mul: int
    int_add: int
    seed: int = 0
    chk_muls: List[int] = field(default_factory=list)
    chk_salts: List[int] = field(default_factory=list)


@dataclass
class EncodedPayload:
    """The fully encoded bytecode payload."""

    protos: List[EncodedProto] = field(default_factory=list)
    params: DecodeParams = None
    meta_keys: List[str] = field(default_factory=list)
    messages: List[str] = field(default_factory=list)
    meta_blob: List[int] = field(default_factory=list)
    msg_blob: List[int] = field(default_factory=list)
    checksums: List[int] = field(default_factory=list)


def _lcg_step(s: int, a: int, c: int, m: int) -> int:
    return (s * a + c) % m


class BytecodeEncoder:
    """Encodes a :class:`BytecodeImage` into an :class:`EncodedPayload`."""

    def __init__(self, rng: DeterministicRandom, preset_config=None) -> None:
        self.rng = rng
        self.preset = preset_config or {}

    # -- helpers ---------------------------------------------------------

    def _derive(self, lo: int, hi: int) -> int:
        return self.rng.randint(lo, hi)

    # -- main ------------------------------------------------------------

    def encode(
        self,
        image: BytecodeImage,
        meta_keys: List[str] | None = None,
        messages: List[str] | None = None,
    ) -> EncodedPayload:
        seed = image.seed_int
        lcg_a = self._derive(0x1001, 0x7FFF) | 1  # odd
        lcg_c = self._derive(0x11, 0xFFFF)
        lcg_m = (1 << 31) - 1
        lcg_s0 = (seed ^ self._derive(0, 0x7FFFFFFF)) % lcg_m
        stride = self._derive(3, 97) | 1

        str_shift = self._derive(0, 200)
        int_mul = self._derive(3, 4093) * 2 + 1
        int_add = self._derive(0, 1024)

        payload = EncodedPayload(
            protos=[],
            params=DecodeParams(
                lcg_a=lcg_a,
                lcg_c=lcg_c,
                lcg_m=lcg_m,
                lcg_s0=lcg_s0,
                stride=stride,
                str_shift=str_shift,
                int_mul=int_mul,
                int_add=int_add,
                seed=seed,
            ),
            meta_keys=list(meta_keys or []),
            messages=list(messages or []),
        )

        nregions = self.preset.get("integrity_regions", 3)
        payload.params.chk_muls = [self._derive(3, 4095) * 2 + 1 for _ in range(nregions)]
        payload.params.chk_salts = [self._derive(0, 4095) for _ in range(nregions)]

        for epi, pi in enumerate(image.protos):
            epr = self._encode_proto(pi, image, payload.params, PROTO_RECORD_BASE + epi)
            payload.protos.append(epr)

        payload.meta_blob = self._encode_record(
            payload.meta_keys, payload.params, META_RECORD_IDX
        )
        payload.msg_blob = self._encode_record(
            payload.messages, payload.params, MSG_RECORD_IDX
        )

        payload.checksums = self._compute_checksums(payload, payload.params)
        return payload

    def _encode_proto(
        self, pi, image, params: DecodeParams, record_index: int
    ) -> EncodedProto:
        epr = EncodedProto(
            proto_id=pi.proto_id,
            params=pi.params,
            is_vararg=pi.is_vararg,
            maxstack=pi.maxstack,
            children=list(pi.children),
            upvals=list(pi.upvals),
        )
        s0_i = (params.lcg_s0 + record_index * params.stride) % params.lcg_m

        # instruction stream encoding
        s = s0_i
        code = []
        for w in pi.code:
            s = _lcg_step(s, params.lcg_a, params.lcg_c, params.lcg_m)
            delta = s % 131072
            code.append(w + delta)
        epr.code_blob = code

        # constant blob encoding
        consts = []
        s = s0_i
        for c in pi.constants:
            s = _lcg_step(s, params.lcg_a, params.lcg_c, params.lcg_m)
            consts.extend(self._encode_const(c, params))
        epr.const_blob = consts
        return epr

    def _encode_record(self, values, params: DecodeParams, record_index: int) -> List[int]:
        out = []
        s0_i = (params.lcg_s0 + record_index * params.stride) % params.lcg_m
        s = s0_i
        for v in values:
            s = _lcg_step(s, params.lcg_a, params.lcg_c, params.lcg_m)
            out.extend(self._encode_const(v, params))
        return out

    def _encode_const(self, value, params: DecodeParams) -> List[int]:
        out: List[int] = []
        if value is None:
            out.append(0)
        elif value is False:
            out.append(1)
        elif value is True:
            out.append(2)
        elif isinstance(value, float):
            if value == int(value) and abs(value) < (1 << 52):
                out.append(3)
                out.append(int(value) * params.int_mul + params.int_add)
            else:
                out.extend(self._encode_float(value, params))
        elif isinstance(value, str):
            out.append(5)
            data = value.encode("utf-8")
            shift = params.str_shift
            out.append(len(data))
            for byte in data:
                out.append((byte - shift) % 256)
        else:
            raise TypeError(f"cannot encode constant {value!r}")
        return out

    def _encode_float(self, value: float, params: DecodeParams) -> List[int]:
        """Encode a non-integral float exactly.

        Rational reconstruction is bounded by ``2^24`` which covers the
        decimals typically found in scripts.  Values that cannot be
        represented within the denominator bound fall back to a plain float
        literal (tag 7).
        """
        from fractions import Fraction
        f = Fraction(value).limit_denominator(1 << 24)
        if f == Fraction(value) and f.denominator != 1:
            return [6, int(f.numerator), int(f.denominator)]
        return [7, value]

    # -- integrity -------------------------------------------------------

    def _region_lists(self, payload: EncodedPayload) -> List[List[int]]:
        code_all: List[int] = []
        const_all: List[int] = []
        meta: List[int] = []
        for p in payload.protos:
            code_all.extend(p.code_blob)
            const_all.extend(p.const_blob)
            meta.extend([p.params, 1 if p.is_vararg else 0, p.maxstack])
            meta.extend(p.children)
            for instack, idx in p.upvals:
                meta.extend([1 if instack else 0, idx])
        return [code_all, const_all, meta]

    def _compute_checksums(self, payload: EncodedPayload, params: DecodeParams) -> List[int]:
        regions = self._region_lists(payload)
        nregions = len(params.chk_muls)
        # Derived regions are stride-samples of existing regions, mirroring
        # the runtime's `RGN` implementation exactly.
        while len(regions) < nregions:
            k = len(regions) - 3
            base = regions[k % 2]
            stride = 2 * k + 3
            start = k % 2
            regions.append(base[start::stride])
        checksums = []
        for i, region in enumerate(regions):
            m = params.chk_muls[i]
            chk = 0
            for w in region:
                chk = (chk * m + w) % SUM_MOD
            checksums.append((chk + params.chk_salts[i]) % SUM_MOD)
        return checksums