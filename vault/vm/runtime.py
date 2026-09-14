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
    "Q",
    "PT",
    "RDK",
    "NUM", "TRYM", "BADD", "BSUB", "BMUL", "BDIV", "BMOD", "BPOW",
    "BNEG", "BCC", "BLEN", "BEQ", "BLT", "BLE",
    "CALLF", "COLL", "COLLT", "UNPR",
    "WREG", "RETD",
    "CS", "RGN", "VER", "VERONE", "MN",
    "WDOG", "WDOGN",
    "RUN", "MK",
    "ADBG",
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
        return build_runtime_source(name_map)


def build_runtime_source(name_map: Dict[str, str]) -> str:
    """Render the runtime Lua source with identifiers substituted."""

    import re

    def r(text: str) -> str:
        def _rep(match):
            return name_map.get(match.group(1), match.group(0))

        return re.sub(r"(?<!@)@([A-Za-z0-9_]+)@(?!@)", _rep, text)

    L: list = []
    L.append(r("local @ENV@=_G"))
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

    L.append("local K_P=1")
    L.append("local K_I=2")
    L.append("local K_R=3")
    L.append("local K_E=4")
    L.append("local K_N=5")
    L.append("local K_O=6")
    L.append("local K_U=7")
    L.append("local K_V=8")
    L.append("local K_B=9")
    L.append("local K_D=10")
    L.append("local K_M=11")

    L.append(r("local @Q@=@@Q@@"))
    L.append(r("local @PT@={}"))

    # ------------------------------------------------------------------
    # decode metamethod keys, error messages and payload prototypes
    # ------------------------------------------------------------------
    L.append(r("""
local function @RDK@(q, idx)
  local P=q[1]
  local A=P[1]; local C=P[2]; local M=P[3]; local S0=P[4]; local ST=P[5]
  local SH=P[6]
  local B=q[idx][2]
  local cnt=q[idx][1]
  local s=(S0+idx*ST)%M
  local t={}
  local bi=1
  for z=1,cnt do
    s=(s*A+C)%M
    local tg=B[bi]; bi=bi+1
    if tg==5 then
      local L2=B[bi]; bi=bi+1
      local str=''
      for u=1,L2 do
        str=str..@CHR@((B[bi]+SH)%256)
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

    L.append(r("""
do
  local t1=@RDK@(@Q@,3)
  for i=1,#t1 do @MKT@[i]=t1[i] end
  local t2=@RDK@(@Q@,4)
  for i=1,#t2 do @EMT@[i]=t2[i] end
  local P=@Q@[1]
  local A=P[1]; local C=P[2]; local M=P[3]; local S0=P[4]; local ST=P[5]
  local SH=P[6]; local IM=P[7]; local IA=P[8]
  for i=5,#@Q@ do
    local r=@Q@[i]
    local pr={}
    pr.params=r[1]
    pr.maxstack=r[3]
    local nk=r[5]
    local kb=r[9]
    local bi=1
    local cst={}
    local s=(S0+i*ST)%M
    for z=1,nk do
      s=(s*A+C)%M
      local tg=kb[bi]; bi=bi+1
      if tg==0 then
        cst[z]=nil
      elseif tg==1 then
        cst[z]=false
      elseif tg==2 then
        cst[z]=true
      elseif tg==3 then
        local v=kb[bi]; bi=bi+1
        cst[z]=(v-IA)/IM
      elseif tg==5 then
        local L2=kb[bi]; bi=bi+1
        local str=''
        for u=1,L2 do
          str=str..@CHR@((kb[bi]+SH)%256)
          bi=bi+1
        end
        cst[z]=str
      elseif tg==6 then
        local num=kb[bi]; bi=bi+1
        local den=kb[bi]; bi=bi+1
        cst[z]=num/den
      elseif tg==7 then
        cst[z]=kb[bi]; bi=bi+1
      else
        cst[z]=nil
      end
    end
    pr.kc=cst
    local nb=r[4]
    local kb2=r[8]
    local cd={}
    s=(S0+i*ST)%M
    for z=1,nb do
      s=(s*A+C)%M
      cd[z]=kb2[z]-(s%131072)
    end
    pr.kd=cd
    local wu=r[7]
    local kv={}
    bi=1
    for z=1,#wu do
      local ii=wu[bi]; local kk=wu[bi+1]; bi=bi+2
      kv[z]={ii,kk}
    end
    pr.kv=kv
    @PT@[i-4]=pr
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
    for i=5,#q do
      local w=q[i][8]
      for j=1,#w do acc[#acc+1]=w[j] end
    end
  elseif r==1 then
    for i=5,#q do
      local w=q[i][9]
      for j=1,#w do acc[#acc+1]=w[j] end
    end
  elseif r==2 then
    for i=5,#q do
      local w=q[i]
      acc[#acc+1]=w[1]
      acc[#acc+1]=w[2]
      acc[#acc+1]=w[3]
      for j=1,#w[6] do acc[#acc+1]=w[6][j] end
      local wu=w[7]
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
local function @VER@(r,q)
  local ws=@RGN@(r,q)
  local muls=q[2][1]
  local salts=q[2][2]
  local expc=q[2][3]
  return @CS@(ws,muls[r+1],salts[r+1])==expc[r+1]
end"""))

    L.append(r("""
local function @VERONE@(r,q)
  if not @VER@(r,q) then
    @ER@(@EMT@[1] or 'integrity check failed')
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

    # NOTE: @RP@ is substituted per-op in the emitter's dispatch table; here we
    # keep a placeholder that the emitter replaces with the operator of the
    # matched opcode (unused for the numeric fast path).
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
    L.append(r("""
@RUN@=function(pr, args, na, upcells)
  local sk = { {pr,1,{},{},0,{},upcells,{},nil,0,0} }
  local tlr, tln
  local I=sk[1]
  local rg2=I[K_R]
  local vr2=I[K_V]
  local params=pr.params
  for i=1,na do
    if i<=params then rg2[i-1]=args[i] else vr2[#vr2+1]=args[i] end
  end
  local function @WREG@(I, r, v)
    local c0=I[K_O][r]
    if c0 then c0[1]=v end
    I[K_R][r]=v
  end
  local function @RETD@(I, results, nn, sk)
    local back=I[K_B]
    local opn=I[K_O]
    for k0,c0 in pairs(opn) do c0.regs=nil end
    sk[#sk]=nil
    if back then
      local dm=I[K_M]
      if dm==1 then
        local d2=I[K_D]
        back[K_R][d2]=results[1]
        local o6=back[K_O][d2]
        if o6 then o6[1]=results[1] end
      elseif dm==2 then
        back[K_E]=results
        back[K_N]=nn
        local d2=I[K_D]
        if d2~=0 then
          back[K_R][d2]=results[1]
          local o6=back[K_O][d2]
          if o6 then o6[1]=results[1] end
        end
      end
      back[K_I]=back[K_I]+6
    else
      tlr=results
      tln=nn
    end
  end
  local @WDOG@=0
  local @WDOGN@=0
  while #sk>0 do
    local I=sk[#sk]
    local pr=I[K_P]
    local cs=pr.kc
    local cd=pr.kd
    local regs=I[K_R]
    local op=cd[I[K_I]]
    local a2=I[K_I]+1
    local b2=a2+1
    local c2=b2+1
    local d2=c2+1
    local e2=d2+1
    local av=0
    @@WK@@
    @@DISP@@
    if op==nil then @ER@(@EMT@[9]) end
    if av==0 then I[K_I]=I[K_I]+6 end
  end
  return tlr, tln
end"""))

    # ------------------------------------------------------------------
    # load-time integrity probe + anti-debug + entry
    # ------------------------------------------------------------------
    L.append("@@CKL@@")
    L.append("@@ADB@@")
    L.append(r("@RUN@(@PT@[@@MAIN@@],{},0,{})"))

    return "\n".join(L)