"""Generation of the embedded Lua-5.1-compatible VM runtime.

The runtime is produced as Lua source text with ``@@PLACEHOLDER@@`` markers
that :class:`~vault.vm.emitter.VMOmitter` fills with build-specific generated
identifiers, opcode constants and payload data.

Architecture
------------
Each function prototype is a record ``{consts, code, params, maxstack,
upvals, kids}``.  Frames are tables:

  [1] proto       [2] instruction word index   [3] registers     [4] results
  [5] result count[6] open upvalue cells        [7] captured cells [8] varargs
  [9] caller frame[10] result destination reg   [11] result mode

The slot locators ([1]..[11] above) are addressed through the generated
``K_P``..``K_M`` locators, which the emitter renames per build so the frame
layout never appears in the output as conventional identifiers.

A single ``while`` loop dispatches over the top frame of a frame stack:
``CALL`` pushes a callee frame, ``RETURN`` delivers results into the caller
and pops.  Closures are Lua functions that launch a nested invocation of the
loop when invoked from outside the VM.

The environment is captured at load time so the hostile environment cannot
redirect the VM through replaced globals.
"""

from __future__ import annotations

from typing import Dict

from vault.utils.random import DeterministicRandom

#: Semantic names used inside the runtime; the emitter maps each to a
#: build-specific generated identifier.
RUNTIME_NAMES: list = [
    "ENV", "SM", "GM", "RG", "RS", "TS", "SEL", "UNPK", "PC", "ER",
    "TY", "CHR", "FLR",
    "REG",
    "MKT", "EMT",
    "BLOB",
    "BIN",
    "Q",
    "PT",
    "RDK",
    "DKC",
    # decode configuration shared by the record/constant decoders
    "PM", "SH", "IM", "IA", "CMUL", "CMOD", "FST", "TR",
    # binary-payload string key and operand-order permutation
    "SX", "CW",
    "NUM", "TRYM", "BADD", "BSUB", "BMUL", "BDIV", "BMOD", "BPOW",
    "BNEG", "BCC", "BLEN", "BEQ", "BLT", "BLE",
    "CALLF", "COLL", "COLLT", "UNPR",
    # non-linear interpreter: separate instruction-execution stage
    "EXEC",
    "WREG", "RETD",
    "CS", "RGN", "VER", "VERONE", "MN",
    "MIXM",
    "WDOG", "WDOGN",
    "RUN", "MK",
    "ADBG",
    # frame slot locators (renamed per build)
    "KP", "KI", "KR", "KE", "KN", "KO", "KU", "KV", "KB", "KD", "KM",
    # controlled-failure machinery
    "SENT", "KILL",
    # self-source hash literal (used only when self_file_check is enabled)
    "SHP",
    # hardening helpers (generated always; used only when the matching
    # protection is enabled)
    "SVC", "DPL", "BXC", "HOOK",
    # outer invocation wrapper
    "WOK", "WA", "WB",
    # step width shared by the process (JMP targets) and the auto-advance;
    # kept separate from the literal so the interpreter advance is not a
    # recognisable ``if av==0 then ip=ip+6`` pair
    "SZ",
    # split-variant result of one instruction execution (the non-linear
    # runner reads the frame ip only after the nested executor returned)
    "SZR",
    # indirect dispatch: opcode -> handler-key remap blob
    "RM",
]


class VMRuntimeBuilder:
    """Builds the runtime Lua source for one obfuscation build.

    The produced source is a template with ``@@PLACEHOLDER@@`` markers that
    :class:`~vault.vm.emitter.VMOmitter` fills in with build-specific data.
    """

    def __init__(self, preset_config=None) -> None:
        self.preset_config = preset_config or {}

    def names(self) -> list:
        """The semantic names that a generated name map must cover."""
        return list(RUNTIME_NAMES)

    def build(self, name_map) -> str:
        """Render the runtime source with identifiers from ``name_map``."""
        return build_runtime_source(name_map, self.preset_config)


#: Shared interpreter preamble: frame setup, register writes, return delivery
#: and the watchdog/state counters.  Both interpreter variants share it so the
#: two forms differ only in how fetch and dispatch are organised.  The
#: ``@@KADJ@@``/``@@SZVAL@@`` markers are resolved per VM family: the classic
#: word-stride family uses ``6``/``6``, the register/instruction-index
#: families (soa/threaded/scrambled) use ``1``/``1``.
_RUN_HEAD = """
@RUN@=function(pr, args, na, upcells)
  -- The frame is constructed with keyed slot locators (not a positional
  -- literal) so that the protected-VM-state option can shuffle the numeric
  -- meaning of every [[1]..[11]] slot between builds.
  local sk = { {[@KP@]=pr,[@KI@]=1,[@KR@]={},[@KE@]={},[@KN@]=0,[@KO@]={},[@KU@]=upcells,[@KV@]={},[@KB@]=nil,[@KD@]=0,[@KM@]=0} }
  local tlr, tln
  local I=sk[1]
  local rg2=I[@KR@]
  local vr2=I[@KV@]
  local params=pr.params
  for i=1,na do
    if i<=params then rg2[i-1]=args[i] else vr2[#vr2+1]=args[i] end
  end
  local function @WREG@(I, r, v)
    local c0=I[@KO@][r]
    if c0 then c0[1]=v end
    I[@KR@][r]=v
  end
  local function @RETD@(I, results, nn, sk)
    local back=I[@KB@]
    local opn=I[@KO@]
    for k0,c0 in pairs(opn) do c0.regs=nil end
    sk[#sk]=nil
    if back then
      local dm=I[@KM@]
      if dm==1 then
        local d2=I[@KD@]
        back[@KR@][d2]=results[1]
        local o6=back[@KO@][d2]
        if o6 then o6[1]=results[1] end
      elseif dm==2 then
        back[@KE@]=results
        back[@KN@]=nn
        local d2=I[@KD@]
        if d2~=0 then
          back[@KR@][d2]=results[1]
          local o6=back[@KO@][d2]
          if o6 then o6[1]=results[1] end
        end
      end
      back[@KI@]=back[@KI@]+@@KADJ@@
    else
      tlr=results
      tln=nn
    end
  end
  local @WDOG@=0
  local @WDOGN@=0
  local @SVC@=0
  local @SZ@=@@SZVAL@@
  @@WKHEAD@@
"""

#: Field-array fetch for the register families (soa / threaded / scrambled).
#: The decoded stream is split into six parallel arrays on ``pr.ff`` and the
#: instruction pointer is an *instruction index*: operands are field lookups by
#: position, and the ``scrambled`` family threads every fetch through the
#: encoded physical-order map ``pr.oo``.  Requires ``I`` and ``pr`` in scope;
#: binds ``cd`` to the opcode field so the shared dispatch/state-validation
#: fragments keep working.
_SOA_FETCH = """
local FL=pr.ff
local ip=I[@KI@]
local ph=(pr.oo and pr.oo[ip]) or ip
local cd=FL[1]
local op=FL[1][ph]
local ca=FL[2][ph]
local cb=FL[3][ph]
local cc=FL[4][ph]
local cq=FL[5][ph]
local ce=FL[6][ph]
"""

#: Classic single-loop interpreter: fetch, decode, dispatch and execute all
#: live in one `while` body.
_RUN_LINEAR = """
  while #sk>0 do
    local I=sk[#sk]
    local pr=I[@KP@]
    local cs=pr.kc
    local cd=pr.kd
    local regs=I[@KR@]
    @@FETCH@@
    local av=0
    @@WK@@
    @@SV@@
    @@DISP@@
    @@NILG@@
    @@ADV@@
  end
  return tlr, tln
end
"""

#: Non-linear interpreter: frame fetch and instruction execution are separate
#: functions and the loop only sequences them.  The dispatch surface an
#: analyst reads is no longer a single contiguous fetch/switch/advance block.
_RUN_SPLIT = """
  local function @EXEC@(I,pr,cs,regs)
    @@EFETCH@@
    local av=0
    @@WK@@
    @@SV@@
    @@DISP@@
    return av
  end
  while #sk>0 do
    local I=sk[#sk]
    local pr=I[@KP@]
    local cs=pr.kc
    local regs=I[@KR@]
    @@LOP@@
    @@NILG@@
    local @SZR@=@EXEC@(I,pr,cs,regs)
    @@ADVR@@
  end
  return tlr, tln
end
"""

#: Fetch for the classic family: the instruction pointer addresses a word and
#: every operand is the following word of the flat stream.
_CLASSIC_FETCH = """
    local op=cd[I[@KI@]]
    local a2=I[@KI@]+1
    local b2=a2+1
    local c2=b2+1
    local d2=c2+1
    local e2=d2+1
"""

#: Field-family fetch for the non-linear runner (``@@EFETCH@@``).
_SOA_EFETCH = """
  local FL=pr.ff
  local ip=I[@KI@]
  local ph=(pr.oo and pr.oo[ip]) or ip
  local cd=FL[1]
  local op=FL[1][ph]
  local ca=FL[2][ph]
  local cb=FL[3][ph]
  local cc=FL[4][ph]
  local cq=FL[5][ph]
  local ce=FL[6][ph]
"""

#: Loop-level pieces of the non-linear runner.  ``@@LOP@@`` binds what the
#: nil-guard and the executor need; the classic family passes the fetched
#: words through locals while the field families recompute the op code.
_CLASSIC_LOP = "    local cd=pr.kd\n    local op=cd[I[@KI@]]\n"
_SOA_LOP = (
    "\n    local FL=pr.ff\n"
    "    local ph9=(pr.oo and pr.oo[I[@KI@]]) or I[@KI@]\n"
    "    local cd=FL[1]\n"
    "    local op=FL[1][ph9]\n"
)

_CLASSIC_EFETCH = "  local cd=pr.kd\n  local op=cd[I[@KI@]]\n  local a2=I[@KI@]+1\n" \
    "  local b2=a2+1\n  local c2=b2+1\n  local d2=c2+1\n  local e2=d2+1\n"


def _advance_for(family: str, result_var: str) -> str:
    """Advance statement for one VM family (``av`` / ``result_var`` skip set)."""
    if family == "threaded":
        # Fallthrough reads the successor id from the per-proto next table;
        # there is no arithmetic auto-advance at all.
        return "if %s==0 then I[@KI@]=pr.nx[I[@KI@]] end" % result_var
    return "I[@KI@]=I[@KI@]+(@SZ@-@SZ@*%s)" % result_var


def _family_interpreter(r, nonlinear: bool, nil_guard: bool, family: str) -> str:
    """Render one interpreter variant for the build's VM family."""
    sz = 1 if family != "classic" else 6
    head = _RUN_HEAD.replace("@@KADJ@@", str(sz)).replace("@@SZVAL@@", str(sz))
    field = family != "classic"
    fetch = _SOA_FETCH if field else _CLASSIC_FETCH
    body_tpl = _RUN_SPLIT if nonlinear else _RUN_LINEAR
    if nonlinear:
        efetch = _SOA_EFETCH if field else _CLASSIC_EFETCH
        lop = _SOA_LOP if field else _CLASSIC_LOP
        advr = _advance_for(family, "@SZR@")
        body = body_tpl.replace("@@EFETCH@@", efetch).replace("@@LOP@@", lop)
        body = body.replace("@@ADVR@@", advr)
    else:
        adv = _advance_for(family, "av")
        body = body_tpl.replace("@@FETCH@@", fetch)
        body = body.replace("@@ADV@@", adv)
    if nil_guard:
        body = body.replace("@@NILG@@", "if op==nil then @ER@(@EMT@[9]) end")
    else:
        body = body.replace("@@NILG@@", "  ")
    return r(head + body)


def _layout_decode(r, family: str) -> str:
    """Layout transform run after prototype decode for the register families.

    Splits every proto's flat decoded word stream into six parallel field
    arrays (opcode, a, b, c, d, e) held on ``pr.ff`` and overrides ``pr.nb``
    from "word count" to "instruction count" so the shared state-validation
    bounds checks keep comparing against the right axis.  The threaded
    family additionally materialises a successor table on ``pr.nx`` that the
    loop reads instead of an arithmetic auto-advance.
    """
    if family == "classic":
        return ""
    nx_body = "true" if family == "threaded" else "false"
    nx_block = (
        "    if " + nx_body + " then\n"
        "      local NX={}\n"
        "      for gi=1,n3 do NX[gi]=gi+1 end\n"
        "      pr.nx=NX\n"
        "    end\n"
    )
    return r("""
do
  local PTA=@PT@
  local FLRA=@FLR@
  for l_i=1,#PTA do
    local pr=PTA[l_i]
    local nb2=pr.nb
    local n3=FLRA(nb2/6)
    local FL={}
    for fi=1,6 do FL[fi]={} end
    for gi=1,n3 do
      local base=(gi-1)*6
      FL[1][gi]=pr.kd[base+1]
      FL[2][gi]=pr.kd[base+2]
      FL[3][gi]=pr.kd[base+3]
      FL[4][gi]=pr.kd[base+4]
      FL[5][gi]=pr.kd[base+5]
      FL[6][gi]=pr.kd[base+6]
    end
    pr.ff=FL
    pr.nb=n3
""" + nx_block + """  end
end""")


def _interpreter_source(r, nonlinear: bool, nil_guard: bool = True,
                        family: str = "classic") -> str:
    """Render the interpreter, choosing the linear or split variant.

    ``nil_guard`` selects whether the loop keeps its literal
    ``if op==nil ...`` check.  The indirect dispatch strategy folds that
    check into its handler lookup, so the guard text is dropped there to
    avoid the recognisable fetch-guard-advance trio.
    """
    return _family_interpreter(r, nonlinear, nil_guard, family)


def build_runtime_source(name_map: Dict[str, str], preset_config=None) -> str:
    """Render the runtime Lua source with identifiers substituted.

    ``preset_config`` selects structural variants of the interpreter (for
    example the non-linear fetch/execute split); it may be a plain mapping or
    a :class:`~vault.presets.config.PresetConfig`.
    """

    def _cfg(key: str, default=False):
        if preset_config is None:
            return default
        if isinstance(preset_config, dict):
            return preset_config.get(key, default)
        return getattr(preset_config, key, default)

    import re

    def r(text: str) -> str:
        def _rep(match):
            return name_map.get(match.group(1), match.group(0))

        return re.sub(r"(?<!@)@([A-Za-z0-9_]+)@(?!@)", _rep, text)

    L: list = []
    # Capture the *real* global environment.  On stock Lua ``_G`` is that
    # environment, but on Roblox/Luau ``_G`` is a separate, empty shared table
    # -- the standard library and the script's own globals live in the
    # function environment returned by ``getfenv``.  Reading everything from
    # ``_G`` there yields nil (e.g. ``_G.table.unpack`` -> index nil), so we
    # prefer ``getfenv()`` when it exists and fall back to ``_G`` on Lua 5.2+
    # (no getfenv), where ``_G`` is already correct.
    L.append(r("local @ENV@=(getfenv and getfenv())or _G"))
    # Remaining environment captures only read @ENV@, so their order carries
    # no meaning; shuffle it per build so the bootstrap prefix does not read
    # identically in every output.
    env_lines = [
        r("local @SM@=@ENV@.setmetatable"),
        r("local @GM@=@ENV@.getmetatable"),
        r("local @RG@=@ENV@.rawget"),
        r("local @RS@=@ENV@.rawset"),
        r("local @TS@=@ENV@.tostring"),
        r("local @SEL@=@ENV@.select"),
        r("local @UNPK@=@ENV@.unpack or @ENV@.table.unpack"),
        r("local @PC@=@ENV@.pcall"),
        r("local @ER@=@ENV@.error"),
        r("local @TY@=@ENV@.type"),
        r("local @CHR@=@ENV@.string.char"),
        r("local @FLR@=@ENV@.math.floor"),
    ]
    try:
        seed = int(_cfg("seed"))
    except (TypeError, ValueError):
        seed = 0
    DeterministicRandom("vault-envshape:%d" % seed).shuffle(env_lines)
    L.extend(env_lines)

    # The weak-keys registry table: some builds spell the metatable differently
    # so its shape is not constant either.  All variants resolve to
    # ``__mode == 'k'``.
    reg_variants = [
        r("local @REG@=@SM@({}, {['__mode']='k'})"),
        r("local @REG@=@SM@({}, {__mode='k'})"),
        r("local @REG@=@SM@({}, {['_'..'_mode']='k'})"),
        r("local @REG@=@SM@({}, {['__'..'mode']='k'})"),
    ]
    L.append(DeterministicRandom("vault-envshape:%d" % (seed + 1)).choice(reg_variants))
    L.append(r("local @MKT@={}"))
    L.append(r("local @EMT@={}"))

    # Frame-slot locators.  The emitter maps each semantic to a generated
    # identifier, and the protected-VM-state option shuffles which numeric
    # slot each locator names.  The frame tables are always constructed with
    # these keyed locators (never as positional literals), so every build
    # assigns a different, non-sequential layout: an analyst grepping for a
    # contiguous [[1]..[11]] frame cannot recover the register / proto /
    # call-result slot meanings from the layout alone.
    frame_slots = ["KP", "KI", "KR", "KE", "KN", "KO", "KU", "KV", "KB", "KD", "KM"]
    slot_values = list(range(1, len(frame_slots) + 1))
    if _cfg("protected_vm_state", False):
        DeterministicRandom("vault-frameslot:%d" % seed).shuffle(slot_values)
    for _name, _value in zip(frame_slots, slot_values):
        L.append(r(f"local @{_name}@={_value}"))

    # ------------------------------------------------------------------
    # controlled-failure sentinel
    #
    # Every security abort (integrity, version mismatch, hook detection,
    # state corruption) routes through @KILL@, which raises a build-specific
    # sentinel table.  The outer invocation wrapper recognizes the sentinel
    # and reports one clean opaque error; any other error raised by the
    # program is passed through untouched so user-facing diagnostics survive.
    # ------------------------------------------------------------------
    L.append(r("local @SENT@"))
    L.append(r("local function @KILL@() error(@SENT@) end"))

    # ------------------------------------------------------------------
    # payload string decoder
    #
    # Numeric payload arrays are embedded as opaque printable strings rather
    # than bare number tables.  Each character carries one base-45 digit plus
    # a continuation flag; values are zig-zag encoded so negatives round-trip.
    # An optional per-blob ``k`` offset is subtracted after decoding, so every
    # record's literal differs even when two arrays hold the same integers.
    # This must be defined before @Q@ is built, since @Q@ calls it.
    # ------------------------------------------------------------------
    L.append(r("""
local @BLOB@
do
  local AL=@@ALPHA@@
  local RV={}
  for qi=1,#AL do RV[AL:byte(qi)]=qi-1 end
  @BLOB@=function(s,k)
    local ot={}
    local kq=k or 0
    local qn=#s
    local qi=1
    local qj=1
    while qi<=qn do
      local ac=0
      local mv=1
      while true do
        local bp=RV[s:byte(qi)]; qi=qi+1
        local dg=bp%45
        ac=ac+dg*mv
        if bp<45 then break end
        mv=mv*45
      end
      local xv
      if ac%2==0 then xv=ac/2 else xv=-(ac+1)/2 end
      ot[qj]=xv-kq; qj=qj+1
    end
    return ot
  end
end"""))

    # ------------------------------------------------------------------
    # custom binary blob decoder
    #
    # Payload arrays are embedded as a proprietary byte container (not a
    # printable alphabet): a fixed magic byte, a format selector, a per-blob
    # additive key, then a field stream of signed LEB128 or fixed-width
    # little-endian fields.  The emitter rotates every body byte by ``-key``
    # before escaping into the Lua literal, so the transmitted bytes never
    # equal the decoded integers.
    # ------------------------------------------------------------------
    if _cfg("binary_payload"):
        L.append(r("""
local function @BIN@(s)
  if s:byte(1)~=206 then return {} end
  local fmt=s:byte(2)%4
  local k=s:byte(3)
  local i=4
  local ot={}
  local j=1
  if fmt==1 or fmt==2 then
    local w=2
    if fmt==2 then w=4 end
    while i<=#s do
      local z=0
      for m2=0,w-1 do z=z+((s:byte(i+m2)+k)%256)*(256^m2) end
      i=i+w
      if z%2==0 then ot[j]=z/2 else ot[j]=-(z+1)/2 end
      j=j+1
    end
  else
    while i<=#s do
      local r=0
      local sh=0
      while true do
        local b=(s:byte(i)+k)%256
        i=i+1
        r=r+(b%128)*(2^sh)
        sh=sh+7
        if b<128 then break end
      end
      if r%2==0 then ot[j]=r/2 else ot[j]=-(r+1)/2 end
      j=j+1
    end
  end
  return ot
end"""))

    L.append(r("@@QDEFS@@"))
    L.append(r("local @Q@=@@Q@@"))
    L.append(r("local @PT@={}"))

    # ------------------------------------------------------------------
    # decode configuration
    #
    # Q[1] is the decode-parameter record.  Besides the LCG and constant
    # codec fields it now carries the instruction-word encoding (multiplier,
    # modulus, per-field step) and a per-build permutation of the eight
    # constant/record type tags.  The inverse tag map is reconstructed once
    # here so the blob's bytes never expose the canonical tag numbering.
    # ------------------------------------------------------------------
    L.append(r("local @PM@=@Q@[1]"))
    L.append(r("local @SH@=@PM@[6]"))
    L.append(r("local @IM@=@PM@[7]"))
    L.append(r("local @IA@=@PM@[8]"))
    L.append(r("local @CMUL@=@PM@[9]"))
    L.append(r("local @CMOD@=@PM@[10]"))
    L.append(r("local @FST@=@PM@[11]"))
    L.append(r("local @TR@={}"))
    L.append(r("for i=1,8 do @TR@[@PM@[11+i]]=i-1 end"))
    if _cfg("diverse_consts"):
        L.append(r("local @SX@=@PM@[21]"))
        L.append(r("local @CW@={}"))
        L.append(r("for i=1,6 do @CW@[i]=@PM@[21+i] end"))

    # ------------------------------------------------------------------
    # per-build metadata / runtime versioning
    #
    # Q[5] carries [vm_version, flags, build_secret, xsum_mul, xsum_add].
    # The VM refuses to run a payload produced by a different VM revision
    # and bonds the integrity + bytecode checksums to the stored secret.
    # ------------------------------------------------------------------
    L.append(r("""
do
  local M5=@Q@[5]
  @SENT@=@@SENTLIT@@
  if M5[1]~=@@VMVER@@ then @@VERBODY@@ end
end"""))

    # ------------------------------------------------------------------
    # decode metamethod keys, error messages and payload prototypes
    # ------------------------------------------------------------------
    L.append(r("""
local function @RDK@(q, idx)
  local P=@PM@
  local A=P[1]; local C=P[2]; local M=P[3]; local S0=P[4]; local ST=P[5]
  local B=q[idx][2]
  local cnt=q[idx][1]
  local s=(S0+idx*ST)%M
  local t={}
  local bi=1
  for z=1,cnt do
    s=(s*A+C)%M
    local tg=@TR@[B[bi]]; bi=bi+1
    if tg==5 then
      local L2=B[bi]; bi=bi+1
      local str=''
      for u=1,L2 do
        str=str..@CHR@((B[bi]+@SH@)%256)
        bi=bi+1
      end
      t[z]=str
    elseif tg==7 then
      t[z]=B[bi]; bi=bi+1
    elseif tg==3 then
      t[z]=B[bi]; bi=bi+1
    else
      t[z]=tg
    end
  end
  return t
end"""))

    # ------------------------------------------------------------------
    # dedicated constant decoder
    #
    # Splitting constant decoding out of the record decoder means there is
    # no single obvious "decode everything" routine: record tags, string
    # shifts and integer arithmetic are all resolved here under the build's
    # own tag permutation and codec constants.
    # ------------------------------------------------------------------
    L.append(r("""
local function @DKC@(kb, bi, m)
  local tg=@TR@[kb[bi]]; bi=bi+1
  if tg==0 then return nil, bi end
  if tg==1 then return false, bi end
  if tg==2 then return true, bi end
  if tg==3 then
    local v=kb[bi]; bi=bi+1
    if m==1 then return (v+@IA@)/@IM@, bi end
    if m==2 then return (v-@IA@-@SX@)/@IM@, bi end
    return (v-@IA@)/@IM@, bi
  end
  if tg==5 then
    local L2=kb[bi]; bi=bi+1
    if m==2 then
      local tb={}
      for u=1,L2 do
        tb[u]=(kb[bi]+@SH@)%256
        bi=bi+1
      end
      local str=''
      for u=L2,1,-1 do str=str..@CHR@(tb[u]) end
      return str, bi
    end
    local str=''
    for u=1,L2 do
      local bv=(kb[bi]+@SH@)%256
      bi=bi+1
      if m==1 then bv=(bv-@SX@)%256 end
      str=str..@CHR@(bv)
    end
    return str, bi
  end
  if tg==6 then
    local n2, d2
    if m==1 then
      n2=kb[bi+1]; d2=kb[bi]
    else
      n2=kb[bi]; d2=kb[bi+1]
    end
    bi=bi+2
    return n2/d2, bi
  end
  if tg==7 then local v=kb[bi]; bi=bi+1; return v, bi end
  return nil, bi
end"""))

    L.append(r("""
do
  local t1=@RDK@(@Q@,3)
  for i=1,#t1 do @MKT@[i]=t1[i] end
  local t2=@RDK@(@Q@,4)
  for i=1,#t2 do @EMT@[i]=t2[i] end
  local P=@PM@
  local A=P[1]; local C=P[2]; local M=P[3]; local S0=P[4]; local ST=P[5]
  for i=@@PBASE@@,#@Q@ do
    local r=@Q@[i]
    local h=r[1]
    local pr={}
    pr.params=h[1]
    pr.maxstack=h[3]
    pr.cm=h[7]
    local nk=h[5]
    local kb=r[5]
    local bi=1
    local cst={}
    local s=(S0+i*ST)%M
    for z=1,nk do
      s=(s*A+C)%M
      local v
      v,bi=@DKC@(kb,bi,pr.cm)
      cst[z]=v
    end
    pr.kc=cst
    local nb=h[4]
    local kb2=r[4]
    local cd={}
    s=(S0+i*ST)%M
    local wi=1
    while wi<=nb do
      s=(s*A+C)%M
      local dlt=((s*@CMUL@)%M)%@CMOD@
      local lst=wi+5
      if lst>nb then lst=nb end
      if h[8]==1 and lst==wi+5 then
        local kz=1
        while kz<=6 do
          cd[wi+@CW@[kz]]=kb2[wi+kz-1]-dlt
          dlt=(dlt+@FST@)%@CMOD@
          kz=kz+1
        end
      else
        local z=wi
        while z<=lst do
          cd[z]=kb2[z]-dlt
          dlt=(dlt+@FST@)%@CMOD@
          z=z+1
        end
      end
      wi=wi+6
    end
    pr.kd=cd
    pr.nk=nk
    pr.nb=nb
    pr.xs=h[6]
    pr.oo=(r[6] or {})
    local wu=r[3]
    local kv={}
    bi=1
    for z=1,#wu do
      local ii=wu[bi]; local kk=wu[bi+1]; bi=bi+2
      kv[z]={ii,kk}
    end
    pr.kv=kv
    @PT@[i-@@PT0@@]=pr
  end
end"""))

    # ------------------------------------------------------------------
    # layout decode (soa / threaded / scrambled families)
    #
    # The register families do not keep the flat decoded stream as the live
    # view: it is split into parallel per-field arrays on ``pr.ff`` and the
    # instruction pointer becomes an instruction index.  ``pr.nb`` is
    # re-based to instruction count so the shared validation bounds and
    # ``#cd`` comparisons stay correct; ``pr.nx`` (threaded) and ``pr.oo``
    # (scrambled, decoded above) are the data the loop advances through.
    # ------------------------------------------------------------------
    L.append(_layout_decode(r, _cfg("vm_family", "classic")))

    # ------------------------------------------------------------------
    # integrity
    # ------------------------------------------------------------------
    L.append(r("local @MN@ = 2147483647"))

    L.append(r("""
local function @CS@(ws,mi,salt)
  local c=0
  for i=1,#ws do
    c=(c*mi+ws[i])%@MN@
  end
  return (c+salt)%@MN@
end"""))

    L.append(r("""
local function @RGN@(r,q)
  local acc={}
  if r==0 then
    for i=@@PBASE@@,#q do
      local w=q[i][4]
      for j=1,#w do acc[#acc+1]=w[j] end
    end
  elseif r==1 then
    for i=@@PBASE@@,#q do
      local w=q[i][5]
      for j=1,#w do acc[#acc+1]=w[j] end
    end
  elseif r==2 then
    for i=@@PBASE@@,#q do
      local w=q[i]
      local hh=w[1]
      acc[#acc+1]=hh[1]
      acc[#acc+1]=hh[2]
      acc[#acc+1]=hh[3]
      for j=1,#w[2] do acc[#acc+1]=w[2][j] end
      local wu=w[3]
      for j=1,#wu do acc[#acc+1]=wu[j] end
    end
  else
    local k=r-3
    local base=k%2
    local stride=2*k+3
    local start=k%2
    local src=@RGN@(base,q)
    local i=start+1
    while i<=#src do
      acc[#acc+1]=src[i]
      i=i+stride
    end
  end
  return acc
end"""))

    L.append(r("""
local function @MIXM@(m,sec)
  local z=(m+(sec%997)+1)%@MN@
  if z==0 then return 1 end
  return z
end"""))

    L.append(r("""
local function @VER@(r,q)
  local ws=@RGN@(r,q)
  local muls=q[2][1]
  local salts=q[2][2]
  local expc=q[2][3]
  return @CS@(ws,@@VERML@@,@@VERST@@)==expc[r+1]
end"""))

    L.append(r("""
local function @VERONE@(r,q)
  if not @VER@(r,q) then
    @@VR1BODY@@
  end
end"""))

    # ------------------------------------------------------------------
    # value helpers
    # ------------------------------------------------------------------
    L.append(r("local function @NUM@(x) return @TY@(x)=='number' end"))
    L.append(r("""
local function @TRYM@(x,y,k)
  local mx=@GM@(x)
  local mf=mx and mx[k]
  if not mf then
    local my=@GM@(y)
    mf=my and my[k]
  end
  return mf
end"""))

    for han, key, ops in (
        ("BADD", 1, "+"), ("BSUB", 2, "-"), ("BMUL", 3, "*"),
        ("BDIV", 4, "/"), ("BMOD", 5, "%"), ("BPOW", 6, "^"),
    ):
        L.append(r(f"""
local function @{han}@(x,y)
  if @NUM@(x) and @NUM@(y) then return x{ops}y, true end
  local mf=@TRYM@(x,y,@MKT@[{key}])
  if mf then return mf(x,y), true end
  return nil, false
end"""))
    L.append(r("""
local function @BNEG@(x)
  if @NUM@(x) then return -x, true end
  local mf=@TRYM@(x,x,@MKT@[7])
  if mf then return mf(x,x), true end
  return nil, false
end"""))
    L.append(r("""
local function @BCC@(x,y)
  local tx=@TY@(x); local ty=@TY@(y)
  if (tx=='number' or tx=='string') and (ty=='number' or ty=='string') then
    return @TS@(x)..@TS@(y), true
  end
  local mf=@TRYM@(x,y,@MKT@[8])
  if mf then return mf(x,y), true end
  return nil, false
end"""))
    L.append(r("""
local function @BLEN@(x)
  local tx=@TY@(x)
  if tx=='string' or tx=='table' then return #x, true end
  local mf=@TRYM@(x,x,@MKT@[9])
  if mf then return mf(x), true end
  return nil, false
end"""))
    L.append(r("""
local function @BEQ@(x,y)
  local tx=@TY@(x); local ty=@TY@(y)
  if tx=='table' and ty=='table' then
    local mx=@GM@(x); local my=@GM@(y)
    local fx=mx and mx[@MKT@[10]]
    local fy=my and my[@MKT@[10]]
    if fx and fy then return fx(x,y) end
    return x==y
  end
  return x==y
end"""))
    L.append(r("""
local function @BLT@(x,y)
  local tx=@TY@(x); local ty=@TY@(y)
  if tx=='number' and ty=='number' then return x<y, true end
  if tx=='string' and ty=='string' then return x<y, true end
  local mf=@TRYM@(x,y,@MKT@[11])
  if mf then return mf(x,y), true end
  return nil, false
end"""))
    L.append(r("""
local function @BLE@(x,y)
  local tx=@TY@(x); local ty=@TY@(y)
  if tx=='number' and ty=='number' then return x<=y, true end
  if tx=='string' and ty=='string' then return x<=y, true end
  local mf=@TRYM@(x,y,@MKT@[12])
  if mf then return mf(x,y), true end
  local mf2=@TRYM@(y,x,@MKT@[11])
  if mf2 then return not mf2(y,x), true end
  return nil, false
end"""))

    L.append(r("""
local function @CALLF@(f,t,base,n)
  if n==0 then return f() end
  return f(@UNPK@(t,base,base+n-1))
end"""))

    L.append("")
    L.append(r("""
local function @COLL@(...)
  local nn=@SEL@('#',...)
  local tt={}
  for i=1,nn do tt[i]=@SEL@(i,...) end
  return tt, nn
end"""))
    L.append(r("""
local function @UNPR@(t,n2)
  if n2==0 then return end
  return @UNPK@(t,1,n2)
end"""))
    L.append(r("local @MK@"))
    L.append(r("local @RUN@"))
    L.append(r("""
@MK@=function(pr, cells)
  local f
  f=function(...)
    local nn=@SEL@('#',...)
    local a2={}
    for i=1,nn do a2[i]=@SEL@(i,...) end
    local r2, n2=@RUN@(pr,a2,nn,cells or {})
    return @UNPR@(r2,n2)
  end
  @REG@[f]={pr, cells or {}}
  return f
end"""))

    # ------------------------------------------------------------------
    # the interpreter
    # ------------------------------------------------------------------
    L.append(_interpreter_source(
        r, _cfg("nonlinear_vm", False), _cfg("dispatch", "cascade") != "indirect",
        _cfg("vm_family", "classic"),
    ))

    # ------------------------------------------------------------------
    # environment sanity, load-time integrity probe, anti-debug and entry
    # ------------------------------------------------------------------
    L.append("@@DECOYS@@")
    L.append("@@ENVS@@")
    L.append("@@CKL@@")
    L.append("@@SELFCHK@@")
    L.append("@@ADB@@")
    L.append("@@RUNSITE@@")

    return "\n".join(L)