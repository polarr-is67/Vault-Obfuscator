"""Assembly of the final obfuscator output.

The emitter stitches together the four compile products into one Lua script:

1. the encoded payload ``Q`` (params, integrity data, build metadata,
   constant and code blobs),
2. the runtime implementation with generated identifiers,
3. the dispatch chain matching the build's permuted opcode codes,
4. the protection fragments (load-time integrity, watchdog, anti-debug,
   VM-state validation, environment sanity).

Dispatch is emitted in one of four build-selected strategies:

* ``cascade`` -- a flat ``if/elseif`` ladder in random order,
* ``tree``    -- a balanced binary decision tree over opcode codes,
* ``table``   -- a per-op handler table built once and called per dispatch,
* ``indirect`` -- a handler table keyed by build-random indices plus an
  opcode->key remap blob, so the dispatch surface never names an opcode and
  the loop advance is a plain arithmetic update rather than a
  recognisable ``if av==0 then ip=ip+6`` pair.

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
from vault.presets.config import get_preset, resolve_shapes
from vault.protection import (
    build_anti_debug,
    build_env_sanity,
    build_load_checks,
    build_self_check,
    build_state_validation,
    build_watchdog,
    build_watchdog_head,
    self_source_hash,
)
from vault.protection.selfcheck import HASH_PREFIX, HASH_SENTINEL
from vault.protection.fail import failure_body
from vault.transforms.identifiers import IdentifierGenerator, IdentifierPolicy
from vault.utils.luaval import (
    LuaRaw,
    build_blob_alphabet,
    can_blob,
    encode_binary_blob,
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

#: Innocent-looking filler strings interleaved between scattered payload
#: chunk variables so the assembled payload reads like ordinary string
#: initialisers rather than one contiguous encoded blob.  The mix includes
#: plain filler phrases, impressively long words and deliberately ridiculous
#: ones so the decoy locals do not look machine-generated.
_DECOY_PHRASES: List[str] = [
    "example",
    "blah alot of text",
    "just some filler",
    "hello there",
    "nothing to see here",
    "sample data follows",
    "a long line of words",
    "some random words now",
    "the quick brown fox",
    "placeholder value",
    "more text to read",
    "arbitrary string",
    "learning lua today",
    "keep it simple",
    "this is a decoy",
    "supercalifragilisticexpialidocious",
    "antidisestablishmentarianism",
    "floccinaucinihilipilification",
    "pneumonoultramicroscopicsilicovolcanoconiosis",
    "uncharacteristically",
    "counterrevolutionarist",
    "incomprehensibilities",
    "sesquipedalianism",
    "hippopotomonstrosesquippedaliophobia",
    "electroencephalographically",
    "pseudopseudohypoparathyroidism",
    "wumbo",
    "gobbledygook",
    "thingamajig",
    "doohickey",
    "whatchamacallit",
    "flabbergasted",
    "kerfuffle",
    "wobblegong",
    "brouhaha",
    "malarkey",
    "balderdash",
    "fuddy-duddy",
    "higgledy-piggledy",
    "dillydally",
    "poppycock",
    "cockamamie",
    "gobsmacked",
    "skedaddle",
    "nincompoop",
    "flibbertigibbet",
    "scallywag",
    "codswallop",
    "tomfoolery",
    "lollygagging",
    "cantankerous",
    "gubbins",
]

#: Maximum number of scattered payload chunk/decoys ``local`` variables the
#: emitter will produce at the top level.  Bounded so the chunk locals plus
#: the runtime's own locals stay under Lua 5.1's per-function 200-local
#: limit; bigger blobs get scattered first, the rest stay single literals.
SCATTER_LOCAL_BUDGET = 96


def _single_quote_literal(lit: str) -> str:
    """Re-render a double-quoted Lua literal with single quotes.

    Used to vary how payload/decoy strings are written.  The blob alphabet
    and decoy phrases never contain ``"`` or ``\\``, so the double-quoted
    body has no backslash escapes and only ``'`` needs turning into ``\\'``.
    """
    if not (lit[:1] == '"' and lit[-1:] == '"'):
        return lit
    return "'" + lit[1:-1].replace("'", "\\'") + "'"


class _PendingBlob:
    """Placeholder for an encoded blob inside the unrendered payload tree."""

    __slots__ = ("values", "rid")

    def __init__(self, values, rid: int) -> None:
        self.values = values
        self.rid = rid


def _walk_pends(node, acc: List["_PendingBlob"] = None) -> List["_PendingBlob"]:
    """Collect every pending blob in a payload tree, in creation order."""
    if acc is None:
        acc = []
    if isinstance(node, _PendingBlob):
        acc.append(node)
    elif isinstance(node, (list, tuple)):
        for v in node:
            _walk_pends(v, acc)
    return acc


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
        self._family = "classic"
        self._noise = 0

    # ------------------------------------------------------------------
    # VM-family handler rendering
    # ------------------------------------------------------------------

    def _soa_rewrite(self, text: str) -> str:
        """Rewrite a handler body for the register families.

        The word-stride handlers read every operand field out of the flat
        ``cd`` stream by word offset (``cd[a2]`` .. ``cd[e2]``).  In the
        register families the decode has already split those fields into
        parallel arrays, so the handler reads the pre-fetched ``ca``/``cb``/
        ``cc``/``cq``/``ce`` locals, and jump targets collapse from
        ``cd[d2]*6+1`` (word index) to ``cq+1`` (instruction index).
        """
        text = text.replace("cd[d2]*6+1", "cq+1")
        text = text.replace("cd[a2]", "ca")
        text = text.replace("cd[b2]", "cb")
        text = text.replace("cd[c2]", "cc")
        text = text.replace("cd[d2]", "cq")
        text = text.replace("cd[e2]", "ce")
        return text

    def _handler_family(self, n: Dict[str, str], name: str) -> str:
        """Handler text for the current VM family (raw, pre-``_finalize``)."""
        body = self._handler(n, name)
        if self._family != "classic":
            body = self._soa_rewrite(body)
        return body

    def _closure_prologue(self, n: Dict[str, str]) -> str:
        """Operand fetch prologue inside a dispatch handler closure.

        Table/indirect dispatch handlers are standalone ``function(I,cd,cs,
        regs,sk)`` closures, so they cannot rely on the interpreter loop's
        bindings: the prologue re-derives the operand locals from the frame.
        """
        if self._family == "classic":
            return (
                f"local a2=I[{n['KI']}]+1\n"
                f"local b2=a2+1\n"
                f"local c2=b2+1\n"
                f"local d2=c2+1\n"
                f"local e2=d2+1\n"
            )
        return (
            f"local pr=I[{n['KP']}]\n"
            f"local FL=pr.ff\n"
            f"local ip=I[{n['KI']}]\n"
            "local ph=(pr.oo and pr.oo[ip]) or ip\n"
            "local ca=FL[2][ph]\n"
            "local cb=FL[3][ph]\n"
            "local cc=FL[4][ph]\n"
            "local cq=FL[5][ph]\n"
            "local ce=FL[6][ph]\n"
        )

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
        rng: DeterministicRandom,
    ) -> str:
        if lo == hi:
            code = codes[lo]
            return "if op==%d then\n%s\nelse\nend" % (code, handler_for(code))
        # Jitter the split point within the middle half so every build gets a
        # different decision-tree shape while remaining near-balanced.
        span = hi - lo
        if span >= 2:
            jitter = max(1, span // 4)
            mid = (lo + hi) // 2 + rng.randint(-jitter, jitter)
            if mid < lo:
                mid = lo
            if mid > hi - 1:
                mid = hi - 1
        else:
            mid = lo
        left = self._tree_walk(n, codes, handler_for, lo, mid, rng)
        right = self._tree_walk(n, codes, handler_for, mid + 1, hi, rng)
        return "if op<%d then\n%s\nelse\n%s\nend" % (codes[mid + 1], left, right)

    def _build_dispatch(
        self, n: Dict[str, str], opmap: List[int], rng: DeterministicRandom
    ) -> str:
        strategy = self._strategy

        def handler_for(code: int) -> str:
            name = OPCODE_LIST[opmap.index(code)]
            return self._finalize(n, self._handler_family(n, name))

        if strategy == "tree":
            return self._tree_walk(
                n, sorted(opmap), handler_for, 0, OPCODE_COUNT - 1, rng
            )

        if strategy == "table":
            return (
                f"local tb_{name_part(n)}=@DPL@[op]\n"
                f"if tb_{name_part(n)} then if tb_{name_part(n)}(I,cd,cs,regs,sk) then av=1 end end"
            ).replace("@DPL@", n["DPL"])

        if strategy == "indirect":
            # The opcode is never compared with anything: it is translated
            # through a remap blob into a build-random handler-table key.
            x = name_part(n)
            return (
                f"local m{x}={n['DPL']}[(op and {n['RM']}[op+1]) or 0]\n"
                f"if m{x} then if m{x}(I,cd,cs,regs,sk) then av=1 end "
                f"else {n['ER']}({n['EMT']}[9]) end"
            )

        # cascade: a ladder in build-randomized order.
        order = list(range(OPCODE_COUNT))
        rng.shuffle(order)
        parts: List[str] = []
        for idx in order:
            name = OPCODE_LIST[idx]
            code = opmap[idx]
            parts.append(f"if op=={code} then\n{self._handler_family(n, name)}")
        parts = [p[3:] if i > 0 else p for i, p in enumerate(parts)]
        chain = "\nelseif ".join(parts)
        # Dispatch noise: dead ``op==<huge>`` ladder edges that no opcode ever
        # satisfies.  They only exercise the comparison plumbing, so the
        # dispatcher still reads as a dense mapping of *something* without the
        # ladder being exactly one comparison per real opcode.
        for _ in range(self._noise):
            junk = 9000 + rng.randint(0, 9999)
            chain += f"\nelseif op=={junk} then av=0"
        chain += "\nelse\nend"
        return self._finalize(n, chain)

    def _build_dispatch_table(
        self, n: Dict[str, str], opmap: List[int], rng: DeterministicRandom
    ) -> str:
        """Handler table for the ``table`` dispatch strategy."""
        dpl = n["DPL"]
        lines = [f"local {dpl}={{}}"]
        order = list(range(OPCODE_COUNT))
        rng.shuffle(order)
        prologue = self._closure_prologue(n)
        for idx in order:
            name = OPCODE_LIST[idx]
            code = opmap[idx]
            body = self._finalize(n, self._handler_family(n, name))
            body = body.replace("av=1", "return 1")
            lines.append(
                f"{dpl}[{code}]=function(I,cd,cs,regs,sk)\n{prologue}{body}\nend"
            )
        for _ in range(self._noise):
            junk = 9000 + rng.randint(0, 9999)
            lines.append(
                f"{dpl}[{junk}]=function(I,cd,cs,regs,sk) return 0 end"
            )
        return "\n".join(lines)

    def _build_dispatch_indirect(
        self, n: Dict[str, str], opmap: List[int], rng: DeterministicRandom
    ) -> tuple:
        """Handler table + opcode->key remap for the ``indirect`` strategy.

        Every opcode is replaced in the emitted text by a build-random table
        key, and a small decoded blob maps instruction codes back to those
        keys.  The loop therefore never compares ``op`` against a literal
        code, never contains an elseif ladder, and shows no dense ordering of
        the opcodes.  Returns ``(header_text, remap_values)``; the remap
        literal is rendered by the caller once the blob pipeline is ready.
        """
        size = OPCODE_COUNT
        keys = list(range(1, size + 1))
        rng.shuffle(keys)
        rm = [0] * (max(opmap) + 1)
        for idx, code in enumerate(opmap):
            rm[code] = keys[idx]

        dpl = n["DPL"]
        prologue = self._closure_prologue(n)
        lines = [f"local {n['RM']}=@@RMLIT@@", f"local {dpl}={{}}"]
        order = list(range(size))
        rng.shuffle(order)
        for idx in order:
            name = OPCODE_LIST[idx]
            body = self._finalize(n, self._handler_family(n, name))
            body = body.replace("av=1", "return 1")
            lines.append(
                f"{dpl}[{keys[idx]}]=function(I,cd,cs,regs,sk)\n{prologue}{body}\nend"
            )
        for _ in range(self._noise):
            junk = 9000 + rng.randint(0, 9999)
            lines.append(
                f"{dpl}[{junk}]=function(I,cd,cs,regs,sk) return 0 end"
            )
        return "\n".join(lines), rm

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
        if name in ("ISTBL", "ISTRG"):
            want = "table" if name == "ISTBL" else "string"
            return f"do wreg(I,cd[a2],{n['TY']}(regs[cd[b2]])=='{want}') end"
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
            "local n2f={[K_P]=p2,[K_I]=1,[K_R]={},[K_E]={},[K_N]=0,[K_O]={},[K_U]=box[2],[K_V]={},[K_B]=I,[K_D]=cd[d2],[K_M]=md}\n"
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

    def _prep_blob(self, values, rid: int = 0) -> tuple:
        """Encode an integer array, returning ``(kind, literal, raw, key)``.

        ``kind`` is ``"BIN"`` (binary container), ``"D"`` (printable
        alphabet) or ``"RAW"`` (plain table literal fallback); ``literal``
        is the already-quoted Lua literal, ``raw`` the unquoted byte string
        it decodes to (``None`` for ``"RAW"``) and ``key`` the offset the
        decoder subtracts per blob (``0`` for ``"BIN"``/``"RAW"``, their
        container embeds its own key).  ``rid`` selects the per-blob delta
        so identical value sets differ across records.

        When ``scattered_payload`` is on, the binary container is skipped in
        favour of the printable alphabet: the binary byte stream is
        inherently non-printable, so it would render as walls of ``\\ddd``
        escapes and defeat the point of scattering the payload.
        """
        vals = list(values)
        if self._binary and not self._scatter and can_blob(vals):
            key = (self._pack * (rid - 1)) % 256
            blob = encode_binary_blob(vals, self._bin_rng, key)
            if blob is not None:
                raw = blob.decode("latin-1")
                return ("BIN", lua_quote_string(raw), raw, 0)
        if can_blob(vals):
            # Keep the delta small and only when every value stays far below
            # 2**52 after the shift, so base-45 arithmetic stays exact.  The
            # offset is rid-driven even when the build's ``pack`` constant is
            # zero, so identical value sets never share a literal.
            delta = 0
            if all(-(1 << 50) < v < (1 << 50) for v in vals):
                offset = self._pack * 37 + 7
                delta = (offset + (rid - 1) * 233) % 977 + 1
            raw = encode_int_blob(vals, self._alphabet, delta)
            return ("D", lua_quote_string(raw), raw, delta)
        return ("RAW", lua_value(vals), None, 0)

    def _scatter_blob(
        self, raw: str, decoder_name: str, delta: int = 0
    ):
        """Break a raw blob string into ``local`` chunks with decoys.

        The raw bytes are split into pieces that are re-escaped
        independently, so the concatenation of the decoded chunk literals is
        byte-for-byte what the original single literal produced.  Decoy
        locals are interleaved so the payload does not read as one data
        blob.  The definition lines are shuffled (they all precede the
        decode call, so the concat operands still appear in byte order),
        quote styles alternate, and neighbouring definitions sometimes merge
        onto one line so the region does not repeat one fixed shape.

        Returns ``(LuaRaw, used_locals)`` or ``None`` when scattering the
        blob would exceed (or make us exceed) the local-variable budget.
        """
        rng = self._scat_rng
        estimated = len(raw) // 18 + 1 + int((len(raw) // 18 + 1) * 0.6) + 1
        if estimated > self._scat_budget:
            return None
        pieces: List[str] = []
        i = 0
        n = len(raw)
        while i < n:
            width = rng.randint(18, 44)
            pieces.append(raw[i : i + width])
            i += width
        if len(pieces) < 2:
            return None
        names = [self._gen.next() for _ in pieces]
        defs: List[str] = []
        for j, name in enumerate(names):
            if rng.random() < 0.6:
                decoy = lua_quote_string(rng.choice(_DECOY_PHRASES))
                defs.append("local %s=%s" % (self._gen.next(), decoy))
            defs.append("local %s=%s" % (name, lua_quote_string(pieces[j])))
        if len(defs) > self._scat_budget:
            return None
        # Vary the *definition* order and quoting; the decode line below
        # re-assembles the chunk variables in byte order.
        rng.shuffle(defs)
        for k, d in enumerate(defs):
            if rng.random() < 0.5:
                eq = d.index("=")
                defs[k] = d[: eq + 1] + _single_quote_literal(d[eq + 1 :])
        rendered: List[str] = []
        idx = 0
        while idx < len(defs):
            if idx + 1 < len(defs) and rng.random() < 0.35:
                rendered.append(defs[idx] + " " + defs[idx + 1])
                idx += 2
            else:
                rendered.append(defs[idx])
                idx += 1
        self._qdefs.extend(rendered)
        return (
            LuaRaw("%s(%s,%d)" % (decoder_name, "..".join(names), delta)),
            len(defs),
        )

    def _render_blob(
        self, kind: str, literal: str, raw: str, decoder_name: str, key: int = 0
    ) -> LuaRaw:
        """Wrap one prepared blob literal as a decoder call, scattering it."""
        if (
            self._scatter
            and self._scat_budget > 0
            and len(literal) > 40
        ):
            r = self._scatter_blob(raw, decoder_name, key)
            if r is not None:
                ref, used = r
                self._scat_budget -= used
                return ref
        return LuaRaw("%s(%s,%d)" % (decoder_name, literal, key))

    def _render_payload(self, payload: EncodedPayload) -> str:
        p = payload.params
        perm = list(p.tag_perm) or list(range(8))
        counter = [0]

        def b(values) -> "_PendingBlob":
            counter[0] += 1
            return _PendingBlob(values, counter[0])

        q: List[object] = [
            b([
                p.lcg_a, p.lcg_c, p.lcg_m, p.lcg_s0,
                p.stride, p.str_shift, p.int_mul, p.int_add,
                p.code_mul, p.code_mod, p.field_step,
                *perm,
                p.pack, p.const_xor,
                *p.cw,
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
                        epr.cmode,
                        epr.cgrp,
                    ]),
                    b(epr.children),
                    b(upv_flat),
                    b(epr.code_blob),
                    b(epr.const_blob),
                    b(epr.order),
                ]
            )
        # Pre-encode every blob (the deterministic walk order feeds the
        # per-blob binary keys), then decide, longest first, which blobs are
        # worth scattering under the fixed local-variable budget so the chunk
        # locals plus the runtime never exceed Lua 5.1's per-function limit.
        pends = _walk_pends(q)
        info: Dict[int, tuple] = {}
        for pb in pends:
            info[pb.rid] = self._prep_blob(pb.values, pb.rid)

        decided: Dict[int, LuaRaw] = {}
        for pb in sorted(
            pends,
            key=lambda x: len(info[x.rid][1]) if info[x.rid][0] != "RAW" else 0,
            reverse=True,
        ):
            kind, lit, raw, key = info[pb.rid]
            if kind == "RAW":
                decided[pb.rid] = LuaRaw(lit)
                continue
            decided[pb.rid] = self._render_blob(
                kind, lit, raw, self._bin_name if kind == "BIN" else self._blob_name, key
            )

        def render(node):
            if isinstance(node, _PendingBlob):
                return decided[node.rid]
            if isinstance(node, (list, tuple)):
                # Rendered sub-tables must stay verbatim Lua text, so they are
                # wrapped in LuaRaw; otherwise the outer table literal would
                # quote them back into string values.
                return LuaRaw(lua_table([render(v) for v in node]))
            return node

        return render(q)

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

    def _alpha_literal(self) -> str:
        """Render the payload alphabet as a concatenation of 2-3 literals.

        Splitting the single 90-character alphabet literal into pieces with
        mixed quote styles stops the decoder preamble from reading as one
        big fixed "data table" every build.
        """
        rng = DeterministicRandom(
            "vault-alpha:%d" % int(self._cfg.get("seed", 0))
        )
        alpha = self._alphabet
        parts: List[str] = []
        lo = 0
        while lo < len(alpha):
            width = rng.randint(28, 36)
            hi = min(len(alpha), lo + width)
            lit = lua_quote_string(alpha[lo:hi])
            parts.append(_single_quote_literal(lit) if rng.random() < 0.5 else lit)
            lo = hi
        return "..".join(parts)

    def _decoys(self, gen: IdentifierGenerator, rng: DeterministicRandom, cfg: dict) -> str:
        """Build build-random unused locals/functions.

        The definitions are never called; they exist so the size and shape of
        the emitted script do not track the source's own structure.  Names come
        from the shared identifier generator so they blend with the runtime's
        generated identifiers and cannot collide.
        """
        max_n = int(cfg.get("decoy_helpers", 0))
        if max_n <= 0:
            return ""
        count = rng.randint(0, max_n)
        parts: List[str] = []
        for _ in range(count):
            name = gen.next()
            k1 = rng.randint(1, 4096)
            k2 = rng.randint(1, 32)
            k3 = rng.randint(0, 8192)
            # Vary the helper shape so decoy functions do not all use one
            # arithmetic-loop template.
            shape = rng.randint(0, 3)
            if shape == 0:
                op = rng.choice(("+", "-", "*", "%"))
                parts.append(
                    "local function %s()\n"
                    "  local s=%d\n"
                    "  for i=1,%d do s=s%si end\n"
                    "  if s>%d then return s end\n"
                    "  return -s\n"
                    "end" % (name, k1, k2, op, k3)
                )
            elif shape == 1:
                parts.append(
                    "local function %s()\n"
                    "  local s={}\n"
                    "  for i=1,%d do s[i]=i*%d end\n"
                    "  return #s+%d\n"
                    "end" % (name, k2, k1 % 97 + 2, k3)
                )
            else:
                parts.append(
                    "local function %s()\n"
                    "  local t={}\n"
                    "  for k=1,%d do t[k]=k end\n"
                    "  return function() return #t end\n"
                    "end" % (name, k2)
                )
            kind = rng.randint(0, 2)
            if kind == 0:
                sname = gen.next()
                slen = rng.randint(3, 28)
                sval = "".join(chr(rng.randint(97, 122)) for _ in range(slen))
                parts.append('local %s="%s"' % (sname, sval))
            elif kind == 1:
                tname = gen.next()
                items = []
                for bi in range(rng.randint(2, 5)):
                    if bi % 2 == 0:
                        items.append(str(rng.randint(1, 4096)))
                    else:
                        items.append(lua_quote_string(rng.choice(_DECOY_PHRASES)))
                parts.append("local %s={%s}" % (tname, ", ".join(items)))
        return "\n".join(parts)

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
        if opts.minify is not None:
            preset.minify = bool(opts.minify)
            if preset.minify:
                preset.pretty = False
        if opts.pretty is not None:
            preset.pretty = bool(opts.pretty)
            if preset.pretty:
                preset.minify = False

        # Resolve any per-build 'auto' choices (VM family, dispatch strategy)
        # now so this emitter agrees with the pipeline on one concrete shape.
        resolve_shapes(preset, opts.seed)

        cfg = dict(preset.__dict__)
        self._cfg = cfg
        self._strategy = cfg.get("dispatch", "cascade")
        self._family = cfg.get("vm_family", "classic")
        self._noise = int(cfg.get("dispatch_noise", 0))
        policy = IdentifierGenerator.policy_for(str(cfg.get("identifier_policy", "medium")))
        cfg["seed"] = int(payload.params.seed)
        meta = self._meta(cfg, payload)

        # Build a probe of every Lua identifier that will appear in the
        # assembled output so generated names can never shadow template
        # locals (e.g. ``pr``, ``cd``, ``cs``) or handler block locals.
        stub_map = {sem: sem for sem in RUNTIME_NAMES}
        probe_runtime = VMRuntimeBuilder(cfg).build(stub_map)
        probe_dispatch = self._build_dispatch(stub_map, image.opmap, rng)
        probe_dispatch_table = ""
        if self._strategy == "table":
            probe_dispatch_table = self._build_dispatch_table(stub_map, image.opmap, rng)
        elif self._strategy == "indirect":
            probe_dispatch_table = self._build_dispatch_indirect(
                stub_map, image.opmap, rng
            )[0]
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
            build_self_check(stub_map, cfg),
            self._run_site(stub_map, cfg),
        ])
        reserved = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", probe_parts))

        gen = IdentifierGenerator(rng, policy, reserved=reserved)
        name_map: Dict[str, str] = {}
        for semantic in RUNTIME_NAMES:
            name_map[semantic] = gen.next(semantic)
        decoys = self._decoys(gen, rng, cfg)

        builder = VMRuntimeBuilder(cfg)
        runtime = builder.build(name_map)

        dispatch = self._build_dispatch(name_map, image.opmap, rng)
        dispatch_table = ""
        if self._strategy == "table":
            dispatch_table = self._build_dispatch_table(name_map, image.opmap, rng)
        elif self._strategy == "indirect":
            dispatch_table, rm_vals = self._build_dispatch_indirect(
                name_map, image.opmap, rng
            )
        watchdog = build_watchdog(name_map, cfg, meta)
        watchdog_head = build_watchdog_head(name_map, cfg, meta)
        load_checks = build_load_checks(name_map, cfg)
        adb = build_anti_debug(name_map, cfg)
        sv = build_state_validation(name_map, cfg, meta)
        envs = build_env_sanity(name_map, cfg)
        selfcheck = build_self_check(name_map, cfg)

        # Derive the payload-string alphabet and the binary-blob scheme
        # stream from dedicated seed inputs so their ordering is stable
        # regardless of how much entropy the dispatch and identifier passes
        # above happen to consume.
        self._binary = bool(cfg.get("binary_payload", False))
        self._pack = int(payload.params.pack)
        self._bin_rng = DeterministicRandom("vault-binary-fmt:%d" % opts.seed)
        self._blob_name = name_map["BLOB"]
        self._bin_name = name_map["BIN"]
        self._alphabet = build_blob_alphabet(
            DeterministicRandom("vault-blob-alphabet:%d" % opts.seed)
        )

        self._gen = gen
        self._scat_rng = DeterministicRandom("vault-scatter:%d" % opts.seed)
        self._scatter = bool(cfg.get("scattered_payload", False))
        self._scat_budget = SCATTER_LOCAL_BUDGET if self._scatter else 0
        self._qdefs: List[str] = []
        q = self._render_payload(payload)

        if self._strategy == "indirect":
            # The remap blob is rendered here, after the binary-blob pipeline
            # is live, so it uses the same decoder scheme as the records.
            rk, rl, rr, rd = self._prep_blob(rm_vals, 0)
            if rk == "RAW":
                rm_ref = LuaRaw(rl)
            else:
                rm_ref = self._render_blob(
                    rk,
                    rl,
                    rr,
                    self._bin_name if rk == "BIN" else self._blob_name,
                    rd,
                )
            dispatch_table = dispatch_table.replace("@@RMLIT@@", str(rm_ref))
        qdefs = "\n".join(self._qdefs)
        self._qdefs = []
        main_id = image.protomap[0] + 1
        ver_mul, ver_salt = self._ver_expr(name_map, cfg)
        secret = payload.metadata[2]

        out = runtime
        out = out.replace("@@DECOYS@@", decoys)
        out = out.replace("@@QDEFS@@", qdefs)
        out = out.replace("@@ALPHA@@", self._alpha_literal())
        out = out.replace("@@Q@@", q)
        out = out.replace("@@DISP@@", dispatch)
        out = out.replace("@@WK@@", watchdog)
        out = out.replace("@@WKHEAD@@", "\n".join(filter(None, [watchdog_head, dispatch_table])))
        out = out.replace("@@SV@@", sv)
        out = out.replace("@@ENVS@@", envs)
        out = out.replace("@@CKL@@", load_checks)
        out = out.replace("@@SELFCHK@@", selfcheck)
        out = out.replace("@@SELFHASH@@", lua_quote_string(HASH_SENTINEL))
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

        if cfg.get("self_file_check", False):
            digest = self_source_hash(out)
            out = out.replace(
                lua_quote_string(HASH_SENTINEL),
                lua_quote_string(HASH_PREFIX + digest),
            )
        return out


def name_part(n: Dict[str, str]) -> str:
    """A stable, reserved-safe identifier fragment for table dispatch locals."""
    # The exact letters do not matter; whatever is emitted is scanned by the
    # probe so generated identifiers will never collide with it.
    return n.get("TMPSLOT_LABEL", "clde")