"""Assembly of the final obfuscator output.

The emitter stitches together the four compile products into one Lua script:

1. the encoded payload ``Q`` (params, integrity data, build metadata,
   constant and code blobs),
2. the runtime implementation with generated identifiers,
3. the dispatch chain matching the build's permuted opcode codes,
4. the protection fragments (load-time integrity, watchdog, anti-debug,
   VM-state validation, environment sanity).

Dispatch is emitted in one of three build-selected strategies:

* ``cascade`` -- a flat ``if/elseif`` ladder in random order,
* ``tree``    -- a balanced binary decision tree over opcode codes,
* ``table``   -- a per-op handler table built once and called per dispatch.

The result is rendered through a safe token-preserving minifier so the
obfuscated script stays compact without risking the integrity of string
literals.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from vault import VaultError
from vault.bytecode.encoder import (
    PROTO_RECORD_BASE,
    SUM_MOD,
    VM_VERSION,
    EncodedPayload,
)
from vault.bytecode.generator import BytecodeImage
from vault.bytecode.instructions import OPCODE_LIST, OPCODE_COUNT
from vault.presets.config import get_preset
from vault.protection import (
    build_anti_debug,
    build_env_sanity,
    build_load_checks,
    build_state_validation,
    build_watchdog,
    build_watchdog_head,
)
from vault.protection.fail import failure_body
from vault.transforms.identifiers import IdentifierGenerator, IdentifierPolicy
from vault.utils.luaval import (
    LuaRaw,
    build_blob_alphabet,
    can_blob,
    encode_int_blob,
    lua_quote_string,
    lua_table,
    lua_value,
)
from vault.utils.random import DeterministicRandom
from vault.vm.runtime import RUNTIME_NAMES, VMRuntimeBuilder

#: Metamethod keys, decoded into ``MKT`` at load time (index 1..12).
DEFAULT_META_KEYS: List[str] = [
    "__add", "__sub", "__mul", "__div", "__mod", "__pow",
    "__unm", "__concat", "__len", "__eq", "__lt", "__le",
]

#: Error message templates, decoded into ``EMT`` at load time (index 1..12).
DEFAULT_MESSAGES: List[str] = [
    "integrity check failed",
    "attempt to perform arithmetic on a %s value",
    "attempt to concatenate a %s value",
    "attempt to index a %s value",
    "attempt to call a %s value",
    "attempt to compare values",
    "'for' step is zero",
    "attempt to get length of a %s value",
    "unknown opcode in VM",
    "invalid register access",
    "debugger hook detected",
    "execution aborted by integrity guard",
]


@dataclass
class ObfuscationOptions:
    """Top-level options for a single obfuscation build."""

    seed: int
    target: str = "lua51"
    preset: str = "low"
    pretty: Optional[bool] = None
    minify: Optional[bool] = None
    debug: bool = False
    overrides: Optional[Dict[str, Any]] = None


def minify_lua(source: str) -> str:
    """A conservative Lua minifier.

    Removes comments and collapses whitespace outside of string literals
    without ever altering string content or token boundaries.
    """
    n = len(source)
    i = 0
    out: List[str] = []

    def read_long(src: str, start: int) -> int:
        """Return the index *after* a long bracketed sequence starting at
        ``start`` (which points at ``[[`` or ``[=[``), or -1 when unterminated."""
        j = start
        if src.startswith("[[", j):
            level = 0
            j += 2
        else:
            level = 0
            j += 1
            while j < n and src[j] == "=":
                level += 1
                j += 1
            if j < n and src[j] == "[":
                j += 1
            else:
                return start
        while j < n:
            if src[j] == "]":
                k = j + 1
                eq = 0
                while k < n and src[k] == "=":
                    eq += 1
                    k += 1
                if k < n and src[k] == "]" and eq == level:
                    return k + 1
                j += 1
            else:
                j += 1
        return -1

    while i < n:
        if source.startswith("--", i):
            # long comment
            br = None
            if source.startswith("--[[", i):
                br = read_long(source, i + 2)
            elif source.startswith("--[=", i):
                j = i + 2
                while j < n and source[j] == "=":
                    j += 1
                if j < n and source[j] == "[":
                    br = read_long(source, i + 2)
            if br is not None and br >= 0:
                i = br
                continue
            while i < n and source[i] != "\n":
                i += 1
            continue
        if source[i] in "\"'":
            q = source[i]
            out.append(q)
            i += 1
            while i < n:
                if source[i] == "\\":
                    out.append(source[i])
                    i += 1
                    if i < n:
                        out.append(source[i])
                        i += 1
                    continue
                if source[i] == q:
                    out.append(q)
                    i += 1
                    break
                out.append(source[i])
                i += 1
            continue
        if source.startswith("[[", i) or source.startswith("[=", i):
            end = read_long(source, i)
            if end >= 0:
                out.append(source[i:end])
                i = end
                continue
        if source[i] in " \t\r\n":
            j = i
            while j < n and source[j] in " \t\r\n":
                j += 1
            # keep one space between two word characters so that distinct
            # identifiers/keywords/numbers never merge into one token
            def _word_char(ch: str) -> bool:
                return ch == "_" or ch.isalnum()

            if (
                j < n
                and out
                and _word_char(source[j])
                and _word_char(out[-1])
            ):
                out.append(" ")
            i = j
            continue
        out.append(source[i])
        i += 1
    return "".join(out)


class VMOmitter:
    """Assembles the final obfuscated script."""

    def __init__(self, options: ObfuscationOptions) -> None:
        self.options = options
        self._strategy = "cascade"
        self._cfg: dict = {}

    # ------------------------------------------------------------------
    # dispatch chain
    # ------------------------------------------------------------------

    def _finalize(self, n: Dict[str, str], text: str) -> str:
        """Substitute the shared handler tokens with generated identifiers."""
        text = text.replace("wreg(", n["WREG"] + "(")
        text = text.replace("retD(", n["RETD"] + "(")
        text = text.replace("PT[", n["PT"] + "[")
        for tok in ("KP", "KI", "KR", "KE", "KN", "KO", "KU", "KV", "KB", "KD", "KM"):
            text = text.replace("K_" + tok[-1], n[tok])
        return text

    def _tree_walk(
        self,
        n: Dict[str, str],
        codes: List[int],
        handler_for,
        lo: int,
        hi: int,
    ) -> str:
        if lo == hi:
            code = codes[lo]
            return "if op==%d then\n%s\nelse\nend" % (code, handler_for(code))
        mid = (lo + hi) // 2
        left = self._tree_walk(n, codes, handler_for, lo, mid)
        right = self._tree_walk(n, codes, handler_for, mid + 1, hi)
        return "if op<%d then\n%s\nelse\n%s\nend" % (codes[mid + 1], left, right)

    def _build_dispatch(
        self, n: Dict[str, str], opmap: List[int], rng: DeterministicRandom
    ) -> str:
        strategy = self._strategy

        def handler_for(code: int) -> str:
            name = OPCODE_LIST[opmap.index(code)]
            return self._finalize(n, self._handler(n, name))

        if strategy == "tree":
            return self._tree_walk(n, sorted(opmap), handler_for, 0, OPCODE_COUNT - 1)

        if strategy == "table":
            return (
                f"local tb_{name_part(n)}=@DPL@[op]\n"
                f"if tb_{name_part(n)} then if tb_{name_part(n)}(I,cd,cs,regs,sk) then av=1 end end"
            ).replace("@DPL@", n["DPL"])

        # cascade: a ladder in build-randomized order.
        order = list(range(OPCODE_COUNT))
        rng.shuffle(order)
        parts: List[str] = []
        for idx in order:
            name = OPCODE_LIST[idx]
            code = opmap[idx]
            parts.append(f"if op=={code} then\n{self._handler(n, name)}")
        parts = [p[3:] if i > 0 else p for i, p in enumerate(parts)]
        chain = "\nelseif ".join(parts) + "\nelse\nend"
        return self._finalize(n, chain)

    def _build_dispatch_table(
        self, n: Dict[str, str], opmap: List[int], rng: DeterministicRandom
    ) -> str:
        """Handler table for the ``table`` dispatch strategy."""
        dpl = n["DPL"]
        lines = [f"local {dpl}={{}}"]
        order = list(range(OPCODE_COUNT))
        rng.shuffle(order)
        prologue = (
            f"local a2=I[{n['KI']}]+1\n"
            f"local b2=a2+1\n"
            f"local c2=b2+1\n"
            f"local d2=c2+1\n"
            f"local e2=d2+1\n"
        )
        for idx in order:
            name = OPCODE_LIST[idx]
            code = opmap[idx]
            body = self._finalize(n, self._handler(n, name))
            body = body.replace("av=1", "return 1")
            lines.append(
                f"{dpl}[{code}]=function(I,cd,cs,regs,sk)\n{prologue}{body}\nend"
            )
        return "\n".join(lines)

    def _handler(self, n: Dict[str, str], name: str) -> str:
        if name == "LOADCONST":
            return "do wreg(I,cd[a2],cs[cd[b2]+1]) end"
        if name == "LOADNIL":
            return "do wreg(I,cd[a2],nil) end"
        if name == "LOADBOOL":
            return "do wreg(I,cd[a2],cd[b2]==1) end"
        if name == "MOVE":
            return "do wreg(I,cd[a2],regs[cd[b2]]) end"
        if name == "LOADGLOBAL":
            return f"do wreg(I,cd[a2],{n['ENV']}[cs[cd[b2]+1]]) end"
        if name == "STOREGLOBAL":
            return f"do {n['ENV']}[cs[cd[b2]+1]]=regs[cd[a2]] end"
        if name == "GETUPVAL":
            return "do wreg(I,cd[a2],I[K_U][cd[b2]][1]) end"
        if name == "SETUPVAL":
            return (
                "do\n"
                "local cv=I[K_U][cd[b2]]\n"
                "local nv=regs[cd[a2]]\n"
                "cv[1]=nv\n"
                "if cv.regs then cv.regs[cv.idx]=nv end\n"
                "end"
            )
        arith = {
            "ADD": ("__add", 2),
            "SUB": ("__sub", 2),
            "MUL": ("__mul", 2),
            "DIV": ("__div", 2),
            "MOD": ("__mod", 2),
            "POW": ("__pow", 2),
        }
        if name in arith:
            fname = {
                "ADD": "BADD", "SUB": "BSUB", "MUL": "BMUL",
                "DIV": "BDIV", "MOD": "BMOD", "POW": "BPOW",
            }[name]
            return (
                f"do local rv,ok={n[fname]}(regs[cd[b2]],regs[cd[c2]])\n"
                f"if ok then wreg(I,cd[a2],rv)\n"
                f"else {n['ER']}(({n['EMT']}[2]):gsub('%%s',{n['TS']}(regs[cd[b2]]))) end end"
            )
        if name == "EDIV":
            return (
                f"do local xv=regs[cd[b2]]; local yv=regs[cd[c2]]\n"
                f"if {n['NUM']}(xv) and {n['NUM']}(yv) then wreg(I,cd[a2],{n['FLR']}(xv/yv))\n"
                f"else {n['ER']}(({n['EMT']}[2]):gsub('%%s',{n['TS']}(xv))) end end"
            )
        if name == "CONCAT":
            return (
                f"do local rv,ok={n['BCC']}(regs[cd[b2]],regs[cd[c2]])\n"
                f"if ok then wreg(I,cd[a2],rv)\n"
                f"else {n['ER']}(({n['EMT']}[3]):gsub('%%s',{n['TS']}(regs[cd[b2]]))) end end"
            )
        if name == "NEG":
            return (
                f"do local rv,ok={n['BNEG']}(regs[cd[b2]])\n"
                f"if ok then wreg(I,cd[a2],rv)\n"
                f"else {n['ER']}(({n['EMT']}[2]):gsub('%%s',{n['TS']}(regs[cd[b2]]))) end end"
            )
        if name == "NOT":
            return "do wreg(I,cd[a2],not regs[cd[b2]]) end"
        if name == "LEN":
            return (
                f"do local rv,ok={n['BLEN']}(regs[cd[b2]])\n"
                f"if ok then wreg(I,cd[a2],rv)\n"
                f"else {n['ER']}(({n['EMT']}[8]):gsub('%%s',{n['TS']}(regs[cd[b2]]))) end end"
            )
        if name == "EQ":
            return f"do wreg(I,cd[a2],{n['BEQ']}(regs[cd[b2]],regs[cd[c2]])) end"
        if name in ("LT", "LE"):
            fname = "BLT" if name == "LT" else "BLE"
            return (
                f"do local rv,ok={n[fname]}(regs[cd[b2]],regs[cd[c2]])\n"
                f"if ok then wreg(I,cd[a2],rv)\n"
                f"else {n['ER']}({n['EMT']}[6]) end end"
            )
        if name == "JMP":
            return "do I[K_I]=cd[d2]*6+1; av=1 end"
        if name == "JMPIFTRUE":
            return "do if regs[cd[a2]] then I[K_I]=cd[d2]*6+1; av=1 end end"
        if name == "JMPIFFALSE":
            return "do if not regs[cd[a2]] then I[K_I]=cd[d2]*6+1; av=1 end end"
        if name == "FCHECK":
            return (
                "do\n"
                "local iv=regs[cd[a2]]; local lv=regs[cd[b2]]; local sv=regs[cd[c2]]\n"
                f"if sv==0 then {n['ER']}({n['EMT']}[7]) end\n"
                "if (sv>0 and iv>lv) or (sv<0 and iv<lv) then\n"
                "I[K_I]=cd[d2]*6+1; av=1\n"
                "end\n"
                "end"
            )
        if name == "FADD":
            return "do wreg(I,cd[a2],regs[cd[a2]]+regs[cd[b2]]) end"
        if name == "CALL":
            return self._handler_call(n)
        if name == "RETURN":
            return (
                "do\n"
                "local rres={}\n"
                "local blk=cd[a2]; local nn2=cd[b2]\n"
                "for i=1,nn2 do rres[i]=regs[blk+i-1] end\n"
                "retD(I,rres,nn2,sk); av=1\n"
                "end"
            )
        if name == "RETURNDYN":
            return "do retD(I,I[K_E],I[K_N],sk); av=1 end"
        if name == "RETURNMIX":
            return (
                "do\n"
                "local blk=cd[a2]; local fn2=cd[b2]; local rn=I[K_N]\n"
                "local rres={}\n"
                "for i=1,fn2 do rres[i]=regs[blk+i-1] end\n"
                "local er=I[K_E]\n"
                "for i=1,rn do rres[fn2+i]=er[i] end\n"
                "retD(I,rres,fn2+rn,sk); av=1\n"
                "end"
            )
        if name == "GETTABLE":
            return "do wreg(I,cd[a2],regs[cd[b2]][regs[cd[c2]]]) end"
        if name == "SETTABLE":
            return "do regs[cd[a2]][regs[cd[b2]]]=regs[cd[c2]] end"
        if name == "NEWTABLE":
            return "do wreg(I,cd[a2],{}) end"
        if name == "CLOSURE":
            return self._handler_closure(n)
        if name == "VARARG":
            return (
                "do\n"
                "local vr2=I[K_V]\n"
                "if cd[b2]==1 then\nwreg(I,cd[a2],vr2[1])\n"
                "else\nI[K_E]=vr2; I[K_N]=#vr2\n"
                "end\n"
                "end"
            )
        if name == "GETRET":
            return "do wreg(I,cd[a2],I[K_E][cd[b2]]) end"
        if name in ("MARK", "NOP"):
            return "do end"
        raise AssertionError(f"no handler for {name}")

    def _handler_call(self, n: Dict[str, str]) -> str:
        return (
            "do\n"
            "local fro=regs[cd[a2]]\n"
            "local bag=cd[b2]\n"
            "local nwrgs=cd[c2]\n"
            "local oum=cd[e2]\n"
            "local tmod=oum>=3\n"
            "local md=oum%3\n"
            f"local ft={n['TY']}(fro)\n"
            "if ft=='function' then\n"
            f"local box={n['REG']}[fro]\n"
            "if box then\n"
            "local p2=box[1]\n"
            "local n2f={p2,1,{},{},0,{},box[2],{},I,cd[d2],md}\n"
            "local rg2=n2f[K_R]\n"
            "local vr2=n2f[K_V]\n"
            "for i=1,nwrgs do\n"
            "local av3=regs[bag+i-1]\n"
            "if i<=p2.params then rg2[i-1]=av3 else vr2[#vr2+1]=av3 end\n"
            "end\n"
            "if tmod then\n"
            "local res2=I[K_E]\n"
            "local rn2=I[K_N]\n"
            "for i=1,rn2 do vr2[#vr2+1]=res2[i] end\n"
            "end\n"
            "sk[#sk+1]=n2f; av=1\n"
            "else\n"
            "local tt,nn\n"
            "if tmod then\n"
            "local cb={}\n"
            "for i=1,nwrgs do cb[i]=regs[bag+i-1] end\n"
            "local res2=I[K_E]\n"
            "local rn2=I[K_N]\n"
            "for i=1,rn2 do cb[nwrgs+i]=res2[i] end\n"
            f"tt,nn={n['COLL']}({n['CALLF']}(fro,cb,1,nwrgs+rn2))\n"
            "else\n"
            f"tt,nn={n['COLL']}({n['CALLF']}(fro,regs,bag,nwrgs))\n"
            "end\n"
            "if md==1 then\n"
            "wreg(I,cd[d2],tt[1])\n"
            "elseif md==2 then\n"
            "I[K_E]=tt; I[K_N]=nn\n"
            "if cd[d2]~=0 then wreg(I,cd[d2],tt[1]) end\n"
            "end\n"
            "end\n"
            "else\n"
            f"{n['ER']}(({n['EMT']}[5]):gsub('%%s',{n['TS']}(fro)))\n"
            "end\n"
            "end"
        )

    def _handler_closure(self, n: Dict[str, str]) -> str:
        return (
            "do\n"
            "local p2=PT[cd[b2]]\n"
            "local kv2=p2.kv\n"
            "local cel={}\n"
            "local opn=I[K_O]\n"
            "local upcv=I[K_U]\n"
            "for zi=1,#kv2 do\n"
            "local desc=kv2[zi]\n"
            "local ii=desc[1]\n"
            "local kk=desc[2]\n"
            "if ii==1 then\n"
            "local cell=opn[kk]\n"
            "if not cell then\n"
            "cell={regs=regs,idx=kk}\n"
            "cell[1]=regs[kk]\n"
            "opn[kk]=cell\n"
            "end\n"
            "cel[zi-1]=cell\n"
            "else\n"
            "cel[zi-1]=upcv[kk]\n"
            "end\n"
            "end\n"
            f"wreg(I,cd[a2],{n['MK']}(p2,cel))\n"
            "end"
        )

    # ------------------------------------------------------------------
    # payload assembly
    # ------------------------------------------------------------------

    def _blob(self, values) -> LuaRaw:
        """Render an integer array as a decoder call ``D"..."`` (or, when the
        values fall outside the encoding's exact range, a plain table)."""
        vals = list(values)
        if can_blob(vals):
            literal = lua_quote_string(encode_int_blob(vals, self._alphabet))
            return LuaRaw(self._blob_name + literal)
        return LuaRaw(lua_value(vals))

    def _render_payload(self, payload: EncodedPayload) -> str:
        p = payload.params
        b = self._blob
        q: List[object] = [
            b([
                p.lcg_a, p.lcg_c, p.lcg_m, p.lcg_s0,
                p.stride, p.str_shift, p.int_mul, p.int_add,
            ]),
            [b(p.chk_muls), b(p.chk_salts), b(payload.checksums)],
            [len(payload.meta_keys), b(payload.meta_blob)],
            [len(payload.messages), b(payload.msg_blob)],
            b(payload.metadata),
        ]
        for epr in payload.protos:
            upv_flat: List[int] = []
            for instack, idx in epr.upvals:
                upv_flat.append(1 if instack else 0)
                upv_flat.append(idx)
            q.append(
                [
                    b([
                        epr.params,
                        1 if epr.is_vararg else 0,
                        epr.maxstack,
                        len(epr.code_blob),
                        len(epr.const_blob),
                        epr.xsum,
                    ]),
                    b(epr.children),
                    b(upv_flat),
                    b(epr.code_blob),
                    b(epr.const_blob),
                ]
            )
        return lua_value(q)

    # ------------------------------------------------------------------
    # hardening expression fragments
    # ------------------------------------------------------------------

    def _ver_expr(self, n: Dict[str, str], cfg: dict) -> tuple:
        """Return ``(mul_expr, salt_expr)`` for the integrity checksum."""
        if cfg.get("build_specific_keys", True):
            mul = f"{n['MIXM']}(muls[r+1],q[5][3])"
            salt = f"(salts[r+1]+(q[5][3]%4093))%{n['MN']}"
        else:
            mul = "muls[r+1]"
            salt = "salts[r+1]"
        return mul, salt

    def _meta(self, cfg: dict, payload: EncodedPayload) -> dict:
        return {
            "xsum_mul": payload.metadata[3],
            "xsum_add": payload.metadata[4],
            "sv_threshold": (
                int(cfg.get("watchdog_threshold", 0)) or 200
            ) * 4,
        }

    def _run_site(self, n: Dict[str, str], cfg: dict) -> str:
        """The invocation at the very end of the script."""
        call = f"{n['RUN']}({n['PT']}[@@MAIN@@],{{}},0,{{}})"
        if not cfg.get("controlled_failures", False):
            return call
        return (
            f"local {n['WOK']},{n['WA']},{n['WB']}={n['PC']}(function()\n"
            f"  return {call}\n"
            "end)\n"
            f"if {n['WOK']} then return {n['WA']},{n['WB']} end\n"
            f"if {n['TY']}({n['WA']})=='table' and {n['WA']}=={n['SENT']} then "
            f"{n['ER']}({n['EMT']}[12]) end\n"
            f"{n['ER']}({n['WA']},0)\n"
        )

    # ------------------------------------------------------------------
    # assemble
    # ------------------------------------------------------------------

    def emit(self, image: BytecodeImage, payload: EncodedPayload) -> str:
        opts = self.options
        assert payload.params.seed == image.seed_int or image.seed_int != 0
        rng = DeterministicRandom(opts.seed)
        preset = get_preset(opts.preset, opts.overrides or None)
        if opts.pretty is not None:
            preset.pretty = opts.pretty
        if opts.minify is not None:
            preset.minify = opts.minify
        if preset.pretty:
            preset.minify = False

        cfg = dict(preset.__dict__)
        self._cfg = cfg
        self._strategy = cfg.get("dispatch", "cascade")
        policy = IdentifierGenerator.policy_for(str(cfg.get("identifier_policy", "medium")))
        meta = self._meta(cfg, payload)

        # Build a probe of every Lua identifier that will appear in the
        # assembled output so generated names can never shadow template
        # locals (e.g. ``pr``, ``cd``, ``cs``) or handler block locals.
        stub_map = {sem: sem for sem in RUNTIME_NAMES}
        probe_runtime = VMRuntimeBuilder(cfg).build(stub_map)
        probe_dispatch = self._build_dispatch(stub_map, image.opmap, rng)
        probe_dispatch_table = (
            self._build_dispatch_table(stub_map, image.opmap, rng)
            if self._strategy == "table"
            else ""
        )
        probe_parts = " ".join([
            probe_runtime,
            probe_dispatch,
            probe_dispatch_table,
            build_watchdog(stub_map, cfg, meta),
            build_watchdog_head(stub_map, cfg, meta),
            build_load_checks(stub_map, cfg),
            build_anti_debug(stub_map, cfg),
            build_state_validation(stub_map, cfg, meta),
            build_env_sanity(stub_map, cfg),
            self._run_site(stub_map, cfg),
        ])
        reserved = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", probe_parts))

        gen = IdentifierGenerator(rng, policy, reserved=reserved)
        name_map: Dict[str, str] = {}
        for semantic in RUNTIME_NAMES:
            name_map[semantic] = gen.next(semantic)

        builder = VMRuntimeBuilder(cfg)
        runtime = builder.build(name_map)

        dispatch = self._build_dispatch(name_map, image.opmap, rng)
        dispatch_table = (
            self._build_dispatch_table(name_map, image.opmap, rng)
            if self._strategy == "table"
            else ""
        )
        watchdog = build_watchdog(name_map, cfg, meta)
        watchdog_head = build_watchdog_head(name_map, cfg, meta)
        load_checks = build_load_checks(name_map, cfg)
        adb = build_anti_debug(name_map, cfg)
        sv = build_state_validation(name_map, cfg, meta)
        envs = build_env_sanity(name_map, cfg)

        # Derive the payload-string alphabet from a dedicated seed stream so
        # its ordering is stable regardless of how much entropy the dispatch
        # and identifier passes above happen to consume.
        self._blob_name = name_map["BLOB"]
        self._alphabet = build_blob_alphabet(
            DeterministicRandom("vault-blob-alphabet:%d" % opts.seed)
        )

        q = self._render_payload(payload)
        main_id = image.protomap[0] + 1
        ver_mul, ver_salt = self._ver_expr(name_map, cfg)
        secret = payload.metadata[2]

        out = runtime
        out = out.replace("@@ALPHA@@", lua_quote_string(self._alphabet))
        out = out.replace("@@Q@@", q)
        out = out.replace("@@DISP@@", dispatch)
        out = out.replace("@@WK@@", watchdog)
        out = out.replace("@@WKHEAD@@", "\n".join(filter(None, [watchdog_head, dispatch_table])))
        out = out.replace("@@SV@@", sv)
        out = out.replace("@@ENVS@@", envs)
        out = out.replace("@@CKL@@", load_checks)
        out = out.replace("@@ADB@@", adb)
        out = out.replace("@@PBASE@@", str(PROTO_RECORD_BASE))
        out = out.replace("@@PT0@@", str(PROTO_RECORD_BASE - 1))
        out = out.replace("@@VMVER@@", str(VM_VERSION))
        out = out.replace("@@VERML@@", ver_mul)
        out = out.replace("@@VERST@@", ver_salt)
        out = out.replace("@@VR1BODY@@", failure_body(name_map, cfg))
        out = out.replace("@@VERBODY@@", failure_body(name_map, cfg))
        out = out.replace(
            "@@SENTLIT@@",
            lua_table([(secret * 31 + 7) % SUM_MOD, (secret * 131 + 13) % SUM_MOD]),
        )
        out = out.replace("@@RUNSITE@@", self._run_site(name_map, cfg))
        out = out.replace("@@MAIN@@", str(main_id))

        if preset.minify:
            out = minify_lua(out)
        return out


def name_part(n: Dict[str, str]) -> str:
    """A stable, reserved-safe identifier fragment for table dispatch locals."""
    # The exact letters do not matter; whatever is emitted is scanned by the
    # probe so generated identifiers will never collide with it.
    return n.get("TMPSLOT_LABEL", "clde")