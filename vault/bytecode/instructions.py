"""Instruction set definition for the Vault-Obf VM.

Each logical opcode is assigned a stable integer code.  At build time the
codes can be permuted; the VM's dispatch table is generated to match.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List

OPCODE_LIST: List[str] = [
    "LOADCONST",    # 0   a=dst  b=const_idx
    "LOADNIL",      # 1   a=dst
    "LOADBOOL",     # 2   a=dst  b=boolval(0/1)
    "MOVE",         # 3   a=dst  b=src
    "LOADGLOBAL",   # 4   a=dst  b=global_name_const_idx
    "STOREGLOBAL",  # 5   a=src  b=global_name_const_idx
    "GETUPVAL",     # 6   a=dst  b=upval_idx
    "SETUPVAL",     # 7   a=src  b=upval_idx
    "ADD",          # 8   a=dst  b=left  c=right
    "SUB",          # 9   a=dst  b=left  c=right
    "MUL",          # 10  a=dst  b=left  c=right
    "DIV",          # 11  a=dst  b=left  c=right
    "MOD",          # 12  a=dst  b=left  c=right
    "POW",          # 13  a=dst  b=left  c=right
    "EDIV",         # 14  a=dst  b=left  c=right   (Luau floor division)
    "CONCAT",       # 15  a=dst  b=left  c=right
    "NEG",          # 16  a=dst  b=src
    "NOT",          # 17  a=dst  b=src
    "LEN",          # 18  a=dst  b=src
    "EQ",           # 19  a=dst  b=x  c=y    (result = x==y as bool)
    "LT",           # 20  a=dst  b=x  c=y
    "LE",           # 21  a=dst  b=x  c=y
    "JMP",          # 22  d=target_pc
    "JMPIFTRUE",    # 23  a=reg  d=target_pc
    "JMPIFFALSE",   # 24  a=reg  d=target_pc
    "FCHECK",       # 25  a=var  b=lim  c=step  d=target_pc
    "FADD",         # 26  a=var  b=step
    "CALL",         # 27  a=func  b=argblock  c=nargs  d=dst  e=mode
    "RETURN",       # 28  a=block  b=n
    "RETURNDYN",    # 29  (no operands; return frame.res)
    "RETURNMIX",    # 30  a=block  b=fixed_n  c=kind
    "GETTABLE",     # 31  a=dst  b=obj  c=key
    "SETTABLE",     # 32  a=tbl  b=key  c=val
    "NEWTABLE",     # 33  a=dst
    "CLOSURE",      # 34  a=dst  b=proto_id
    "VARARG",       # 35  a=dst  b=mode (1=single, 0=multi→frame.res)
    "GETRET",       # 36  a=dst  b=index
    "MARK",         # 37  label-anchor (decoded: d=target_pc, discards if wanted)
    "NOP",          # 38  no-op
    "ISTBL",        # 39  a=dst  b=reg   (dst = type(reg)=='table')
    "ISTRG",        # 40  a=dst  b=reg   (dst = type(reg)=='string')
]

OPCODE_COUNT = len(OPCODE_LIST)
OPCODE_NAMES = {name: idx for idx, name in enumerate(OPCODE_LIST)}
