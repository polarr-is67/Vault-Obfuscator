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

#: Semantic names used inside the runtime; the emitter maps each to a
#: build-specific generated identifier.
RUNTIME_NAMES: list = [
    "ENV", "SM", "GM", "RG", "RS", "TS", "SEL", "UNPK", "PC", "ER",
    "TY", "CHR", "FLR",
    "REG",
    "MKT", "EMT",
    "BLOB",
    "Q",
    "PT",
    "RDK",
    "DKC",
    # decode configuration shared by the record/constant decoders
    "PM", "SH", "IM", "IA", "CMUL", "CMOD", "FST", "TR",
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
#: two forms differ only in how fetch and dispatch are organised.
_RUN_HEAD = """
@RUN@=function(pr, args, na, upcells)
  local sk = { {pr,1,{},{},0,{},upcells,{},nil,0,0} }
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
      back[@KI@]=back[@KI@]+6
    else
      tlr=results
      tln=nn
    end
  end
  local @WDOG@=0
  local @WDOGN@=0
  local @SVC@=0
  @@WKHEAD@@
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
    local op=cd[I[@KI@]]
    local a2=I[@KI@]+1
    local b2=a2+1
    local c2=b2+1
    local d2=c2+1
    local e2=d2+1
    local av=0
    @@WK@@
    @@SV@@
    @@DISP@@
    if op==nil then @ER@(@EMT@[9]) end
    if av==0 then I[@KI@]=I[@KI@]+6 end
  end
  return tlr, tln
end
"""

#: Non-linear interpreter: frame fetch and instruction execution are separate
#: functions and the loop only sequences them.  The dispatch surface an
#: analyst reads is no longer a single contiguous fetch/switch/advance block.
_RUN_SPLIT = """
  local function @EXEC@(I,pr,cd,cs,regs,op)
    local a2=I[@KI@]+1
    local b2=a2+1
    local c2=b2+1
    local d2=c2+1
    local e2=d2+1
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
    local cd=pr.kd
    local regs=I[@KR@]
    local op=cd[I[@KI@]]
    if op==nil then @ER@(@EMT@[9]) end
    if @EXEC@(I,pr,cd,cs,regs,op)==0 then I[@KI@]=I[@KI@]+6 end
  end
  return tlr, tln
end
"""


def _interpreter_source(r, nonlinear: bool) -> str:
    """Render the interpreter, choosing the linear or split variant."""
    body = _RUN_SPLIT if nonlinear else _RUN_LINEAR
    return r(_RUN_HEAD + body)


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
    L.append(r("local @SM@=@ENV@.setmetatable"))
    L.append(r("local @GM@=@ENV@.getmetatable"))
    L.append(r("local @RG@=@ENV@.rawget"))
    L.append(r("local @RS@=@ENV@.rawset"))
    L.append(r("local @TS@=@ENV@.tostring"))
    L.append(r("local @SEL@=@ENV@.select"))
    L.append(r("local @UNPK@=@ENV@.unpack or @ENV@.table.unpack"))
    L.append(r("local @PC@=@ENV@.pcall"))
    L.append(r("local @ER@=@ENV@.error"))
    L.append(r("local @TY@=@ENV@.type"))
    L.append(r("local @CHR@=@ENV@.string.char"))
    L.append(r("local @FLR@=@ENV@.math.floor"))

    L.append(r("local @REG@ = @SM@({}, {['__mode']='k'})"))
    L.append(r("local @MKT@={}"))
    L.append(r("local @EMT@={}"))

    # Frame-slot locators.  The emitter maps each semantic to a generated
    # identifier (and may shuffle their numeric meaning via the protected-VM-
    # state option), so the frame layout is not addressable by any fixed,
    # greppable name in the emitted file.
    L.append(r("local @KP@=1"))
    L.append(r("local @KI@=2"))
    L.append(r("local @KR@=3"))
    L.append(r("local @KE@=4"))
    L.append(r("local @KN@=5"))
    L.append(r("local @KO@=6"))
    L.append(r("local @KU@=7"))
    L.append(r("local @KV@=8"))
    L.append(r("local @KB@=9"))
    L.append(r("local @KD@=10"))
    L.append(r("local @KM@=11"))

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
    # This must be defined before @Q@ is built, since @Q@ calls it.
    # ------------------------------------------------------------------
    L.append(r("""
local @BLOB@
do
  local AL=@@ALPHA@@
  local RV={}
  for qi=1,#AL do RV[AL:byte(qi)]=qi-1 end
  @BLOB@=function(s)
    local ot={}
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
      ot[qj]=xv; qj=qj+1
    end
    return ot
  end
end"""))

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
local function @DKC@(kb, bi)
  local tg=@TR@[kb[bi]]; bi=bi+1
  if tg==0 then return nil, bi end
  if tg==1 then return false, bi end
  if tg==2 then return true, bi end
  if tg==3 then local v=kb[bi]; bi=bi+1; return (v-@IA@)/@IM@, bi end
  if tg==5 then
    local L2=kb[bi]; bi=bi+1
    local str=''
    for u=1,L2 do
      str=str..@CHR@((kb[bi]+@SH@)%256)
      bi=bi+1
    end
    return str, bi
  end
  if tg==6 then local num=kb[bi]; local den=kb[bi+1]; bi=bi+2; return num/den, bi end
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
    local nk=h[5]
    local kb=r[5]
    local bi=1
    local cst={}
    local s=(S0+i*ST)%M
    for z=1,nk do
      s=(s*A+C)%M
      local v
      v,bi=@DKC@(kb,bi)
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
      local z=wi
      while z<=lst do
        cd[z]=kb2[z]-dlt
        dlt=(dlt+@FST@)%@CMOD@
        z=z+1
      end
      wi=wi+6
    end
    pr.kd=cd
    pr.nk=nk
    pr.nb=nb
    pr.xs=h[6]
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
    L.append(_interpreter_source(r, _cfg("nonlinear_vm", False)))

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