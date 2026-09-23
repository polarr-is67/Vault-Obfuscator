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

#: Version of the VM runtime + payload protocol. Baked into every build and
#: checked at load time so a payload produced by an older/newer emitter fails
#: cleanly instead of mis-running.
VM_VERSION = 3

#: Position of the payload records in the runtime `Q` table:
#: [1]=LCG params, [2]=integrity, [3]=metamethod keys, [4]=error messages,
#: [5]=build metadata (VM version / seed / secret), [6..]=prototypes.
META_RECORD_IDX = 3
MSG_RECORD_IDX = 4
METADATA_RECORD_IDX = 5
PROTO_RECORD_BASE = 6


def mix_integrity_mul(m: int, secret: int) -> int:
    """Build-specific mix of a checksum multiplier with the build secret.

    Mirrored exactly by the VM's ``VER`` implementation so both sides agree.
    """
    v = (m + (secret % 997) + 1) % SUM_MOD
    return 1 if v == 0 else v


def mix_integrity_salt(s: int, secret: int) -> int:
    """Build-specific mix of a checksum salt with the build secret."""
    return (s + (secret % 4093)) % SUM_MOD


@dataclass
class EncodedProto:
    """One encoded prototype blob, ready to be embedded as Lua data."""

    proto_id: int
    params: int
    is_vararg: bool
    maxstack: int
    #: Constant-recording scheme applied to this prototype's constant blob
    #: (0 plain, 1 affine-minus / xor'd strings, 2 affine-plus / reversed
    #: strings).  Chosen per build when ``diverse_consts`` is enabled.
    cmode: int = 0
    #: When 1, operand words inside every full 6-word instruction group are
    #: stored in the build's shuffled semantic order (``params.cw``).
    cgrp: int = 0
    children: List[int] = field(default_factory=list)
    upvals: List[Tuple[int, int]] = field(default_factory=list)
    code_blob: List[int] = field(default_factory=list)
    const_blob: List[int] = field(default_factory=list)
    #: Physical-instruction-order map (1-based) for the ``scrambled`` family;
    #: empty otherwise.  Stored as the sixth record field and decoded verbatim
    #: into ``pr.oo`` so the interpreter can thread through a non-sequential
    #: decoded stream.
    order: List[int] = field(default_factory=list)
    #: Checksum the VM can re-derive over the *decoded* instruction stream to
    #: catch post-decode tampering of the bytecode (bytecode integrity check).
    xsum: int = 0


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

    # -- instruction-word encoding ---------------------------------------
    #: Per-build odd multiplier folded into the LCG state before deriving an
    #: instruction's delta stream.  A value of 1 disables the extra layer.
    code_mul: int = 1
    #: Per-build modulus for the instruction delta stream (a power of two).
    #: Larger moduli widen the per-instruction offset and thus the entropy a
    #: static reader sees between builds.
    code_mod: int = 1 << 17
    #: Per-field stride added to the running delta when ``encoding_layers``
    #: is at least 2, so each of the six operand words of one instruction
    #: carries a distinct offset.
    field_step: int = 1
    #: ``1`` = one shared delta per instruction (classic additive encoding);
    #: ``2`` = a fresh field delta per operand word.
    encoding_layers: int = 1
    #: Per-build permutation applied to the constant/record type tags so the
    #: byte layout never exposes the fixed tag numbers.  ``tag_perm[t]`` is
    #: the value emitted in place of original tag ``t``; the VM inverts it.
    tag_perm: List[int] = field(default_factory=list)
    #: Per-build additive key embedded in every binary blob header so the
    #: same value bytes decouple across build seeds and across records.
    pack: int = 0
    #: Per-build string-byte XOR key used by constant schemes 1 and 2.
    const_xor: int = 0
    #: Per-build semantic-order permutation of the six operand words inside a
    #: full instruction group; used when a prototype's ``cgrp`` flag is set.
    #: ``cw[stored_slot]`` is the semantic offset (0..5) placed there.
    cw: List[int] = field(default_factory=lambda: list(range(6)))


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
    #: Build metadata record: [vm_version, flags, secret, xsum_mul, xsum_add].
    metadata: List[int] = field(default_factory=list)


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

        # Instruction-word encoding parameters.  ``code_mod`` is a build-random
        # power of two; ``code_mul`` (odd) decorrelates the delta stream from
        # the raw LCG state; ``field_step`` gives each operand word its own
        # offset when the preset asks for the two-layer encoding.
        code_mod = 1 << self._derive(17, 20)
        code_mul = self._derive(3, 0xFFFF) | 1
        encoding_layers = 2 if self.preset.get("encoding_layers", 1) >= 2 else 1
        # A zero ``field_step`` collapses the per-field delta to the classic
        # single-delta encoding while keeping the decoder loop uniform.
        field_step = self._derive(1, code_mod - 1) if encoding_layers >= 2 else 0

        # Per-build permutation of the eight constant/record type tags.  The
        # VM reconstructs the inverse from the same array, so a build's blob
        # bytes never expose the canonical tag numbering.
        tag_perm = list(range(8))
        self.rng.shuffle(tag_perm)

        # Per-build binary-payload keys and the operand-order permutation.
        cw = list(range(6))
        self.rng.shuffle(cw)
        pack = self._derive(1, 255)
        const_xor = self._derive(1, 255)

        # Build-specific secret bonded to the payload's own LCG parameters so
        # it can never be transplanted across builds.
        secret = self._derive(1, 0x7FFFFFFF)
        xsum_mul = self._derive(3, 4093) * 2 + 1
        xsum_add = self._derive(0, 4095)

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
                code_mul=code_mul,
                code_mod=code_mod,
                field_step=field_step,
                encoding_layers=encoding_layers,
                tag_perm=tag_perm,
                pack=pack,
                const_xor=const_xor,
                cw=cw,
            ),
            meta_keys=list(meta_keys or []),
            messages=list(messages or []),
        )

        nregions = self.preset.get("integrity_regions", 3)
        payload.params.chk_muls = [self._derive(3, 4095) * 2 + 1 for _ in range(nregions)]
        payload.params.chk_salts = [self._derive(0, 4095) for _ in range(nregions)]

        meta_flags = self._meta_flags()
        payload.metadata = [
            VM_VERSION,
            meta_flags,
            secret,
            xsum_mul,
            xsum_add,
        ]

        for epi, pi in enumerate(image.protos):
            epr = self._encode_proto(pi, image, payload.params, PROTO_RECORD_BASE + epi, payload.metadata)
            payload.protos.append(epr)

        payload.meta_blob = self._encode_record(
            payload.meta_keys, payload.params, META_RECORD_IDX
        )
        payload.msg_blob = self._encode_record(
            payload.messages, payload.params, MSG_RECORD_IDX
        )

        payload.checksums = self._compute_checksums(payload, payload.params, payload.metadata)
        return payload

    def _meta_flags(self) -> int:
        """Opaque bitmask of hardening flags for the per-build metadata."""
        bits = {
            "watchdog": 1,
            "anti_debug": 2,
            "unexpected_hook_detection": 4,
            "env_sanity": 8,
            "runtime_versioning": 16,
            "protected_vm_state": 32,
            "vm_state_validation": 64,
            "bytecode_integrity": 128,
            "controlled_failures": 256,
            "binary_payload": 512,
            "diverse_consts": 1024,
        }
        flags = 0
        for key, bit in bits.items():
            if self.preset.get(key, False):
                flags |= bit
        return flags

    def _encode_proto(
        self, pi, image, params: DecodeParams, record_index: int, metadata: List[int]
    ) -> EncodedProto:
        epr = EncodedProto(
            proto_id=pi.proto_id,
            params=pi.params,
            is_vararg=pi.is_vararg,
            maxstack=pi.maxstack,
            cmode=0,
            cgrp=0,
            children=list(pi.children),
            upvals=list(pi.upvals),
            order=list(pi.order),
        )
        if self.preset.get("diverse_consts", False):
            epr.cmode = self._derive(0, 2)
            epr.cgrp = self._derive(0, 1)
        s0_i = (params.lcg_s0 + record_index * params.stride) % params.lcg_m

        # instruction stream encoding
        #
        # Words are encoded in groups of six (one instruction).  One LCG step
        # per group seeds a delta stream: the base delta is ``(s * code_mul)``
        # reduced modulo the build's ``code_mod``, and each of the six operand
        # words advances the delta by the build's ``field_step``.  With a
        # layer-1 build ``field_step`` is zero, so all six words share the
        # delta and the encoding degrades to the classic additive scheme.
        #
        # When ``cgrp`` is set, a full group's operand words are placed in the
        # build's shuffled semantic order (``params.cw``), so the same group
        # of instructions has a distinct byte arrangement per record/build.
        s = s0_i
        code: List[int] = []
        words = pi.code
        nwords = len(words)
        wi = 0
        while wi < nwords:
            s = _lcg_step(s, params.lcg_a, params.lcg_c, params.lcg_m)
            base = (s * params.code_mul) % params.lcg_m
            delta = base % params.code_mod
            take = 6 if wi + 6 <= nwords else nwords - wi
            if epr.cgrp and take == 6:
                for k in range(6):
                    code.append(words[wi + params.cw[k]] + delta)
                    delta = (delta + params.field_step) % params.code_mod
            else:
                for k in range(take):
                    code.append(words[wi + k] + delta)
                    delta = (delta + params.field_step) % params.code_mod
            wi += take
        epr.code_blob = code

        # Bytecode-integrity checksum over the *decoded* words: the runtime
        # decodes ``blob[k] - (s % 131072)`` back to ``w``, so it can re-derive
        # this exact value at runtime to catch tampering after decode.
        xmul, xadd = metadata[3], metadata[4]
        xsum = 0
        for w in pi.code:
            xsum = (xsum * xmul + w + xadd) % SUM_MOD
        epr.xsum = xsum

        # constant blob encoding
        consts = []
        s = s0_i
        for c in pi.constants:
            s = _lcg_step(s, params.lcg_a, params.lcg_c, params.lcg_m)
            consts.extend(self._encode_const(c, params, epr.cmode))
        epr.const_blob = consts
        return epr

    def _encode_record(self, values, params: DecodeParams, record_index: int) -> List[int]:
        out = []
        s0_i = (params.lcg_s0 + record_index * params.stride) % params.lcg_m
        s = s0_i
        for v in values:
            s = _lcg_step(s, params.lcg_a, params.lcg_c, params.lcg_m)
            out.extend(self._encode_const(v, params, 0))
        return out

    def _encode_const(self, value, params: DecodeParams, mode: int = 0) -> List[int]:
        perm = params.tag_perm or list(range(8))
        sx = params.const_xor
        int_mul = params.int_mul
        int_add = params.int_add

        def tg(t: int) -> int:
            return perm[t]

        out: List[int] = []
        if value is None:
            out.append(tg(0))
        elif value is False:
            out.append(tg(1))
        elif value is True:
            out.append(tg(2))
        elif isinstance(value, (int, float)):
            if value == int(value) and abs(value) < (1 << 52):
                iv = int(value)
                if mode == 1:
                    enc = iv * int_mul - int_add
                elif mode == 2:
                    enc = iv * int_mul + int_add + sx
                else:
                    enc = iv * int_mul + int_add
                if enc <= -(1 << 52) or enc >= (1 << 52):
                    # The multiplicative form overflows the exact double /
                    # blob range.  Carry the value itself through the tag-6
                    # rational form with denominator 1, which stays exact for
                    # every constant magnitude we accept (|v| < 2**52).
                    if mode == 1:
                        out.extend([tg(6), 1, iv])
                    else:
                        out.extend([tg(6), iv, 1])
                else:
                    out.append(tg(3))
                    out.append(enc)
            else:
                out.extend(self._encode_float(float(value), params, tg, mode))
        elif isinstance(value, str):
            out.append(tg(5))
            data = value.encode("utf-8")
            shift = params.str_shift
            out.append(len(data))
            if mode == 2:
                # reversed byte order with the affine shift.
                for byte in reversed(data):
                    out.append((byte - shift) % 256)
            elif mode == 1:
                # affine shift plus the per-build xor key.
                for byte in data:
                    out.append((byte - shift + sx) % 256)
            else:
                for byte in data:
                    out.append((byte - shift) % 256)
        else:
            raise TypeError(f"cannot encode constant {value!r}")
        return out

    def _encode_float(self, value: float, params: DecodeParams, tg, mode: int = 0) -> List[int]:
        """Encode a non-integral float exactly.

        Rational reconstruction is bounded by ``2^24`` which covers the
        decimals typically found in scripts.  Values that cannot be
        represented within the denominator bound fall back to a plain float
        literal (the original tag 7).
        """
        from fractions import Fraction
        f = Fraction(value).limit_denominator(1 << 24)
        if f == Fraction(value) and f.denominator != 1:
            if mode == 1:
                # numerator/denominator swapped; the runtime reverses it.
                return [tg(6), int(f.denominator), int(f.numerator)]
            return [tg(6), int(f.numerator), int(f.denominator)]
        return [tg(7), value]

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

    def _compute_checksums(self, payload: EncodedPayload, params: DecodeParams, metadata: List[int]) -> List[int]:
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
        use_secret = self.preset.get("build_specific_keys", True)
        secret = metadata[2] if use_secret else 0
        for i, region in enumerate(regions):
            m = mix_integrity_mul(params.chk_muls[i], secret) if use_secret else params.chk_muls[i]
            chk = 0
            for w in region:
                chk = (chk * m + w) % SUM_MOD
            salt = mix_integrity_salt(params.chk_salts[i], secret) if use_secret else params.chk_salts[i]
            checksums.append((chk + salt) % SUM_MOD)
        return checksums