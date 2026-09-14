"""Target packages for Vault-Obf."""

from vault.targets.lua51 import Lua51Target
from vault.targets.luau import LuauTarget

TARGETS = {
    "lua51": Lua51Target,
    "luau": LuauTarget,
}

__all__ = ["Lua51Target", "LuauTarget", "TARGETS"]