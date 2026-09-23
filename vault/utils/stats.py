"""Build statistics collection."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class BuildStats:
    """Statistics gathered during a compilation run.

    Attributes:
        source_size: Size of the input source in bytes.
        output_size: Size of the emitted protected script in bytes.
        bytecode_size: Approximate serialized bytecode size in bytes.
        instruction_count: Total number of instructions across all prototypes.
        constant_count: Total number of constants across all prototypes.
        function_count: Number of function prototypes.
        compile_time_ms: Wall-clock compile time in milliseconds.
        seed: The numeric seed used, when deterministic.
        preset: The preset name used.
        target: The target language name.
        source_lines: Number of lines in the source.
    """

    source_size: int = 0
    output_size: int = 0
    bytecode_size: int = 0
    instruction_count: int = 0
    constant_count: int = 0
    function_count: int = 0
    compile_time_ms: float = 0.0
    seed: Optional[int] = None
    preset: str = "low"
    target: str = "lua51"
    source_lines: int = 0
    vm_family: str = "classic"
    dispatch: str = "cascade"

    def to_dict(self) -> dict:
        """Return a JSON-serialisable dictionary."""
        return {
            "source_size": self.source_size,
            "output_size": self.output_size,
            "bytecode_size": self.bytecode_size,
            "instruction_count": self.instruction_count,
            "constant_count": self.constant_count,
            "function_count": self.function_count,
            "compile_time_ms": round(self.compile_time_ms, 3),
            "seed": self.seed,
            "preset": self.preset,
            "target": self.target,
            "source_lines": self.source_lines,
            "vm_family": self.vm_family,
            "dispatch": self.dispatch,
        }

    def format_cli(self) -> str:
        """Render a human-friendly summary for ``--stats`` output."""
        lines = [
            "Vault-Obf build statistics",
            "-------------------------",
            f"Target:              {self.target}",
            f"Preset:              {self.preset}",
            f"VM family:           {self.vm_family}",
            f"Dispatch:            {self.dispatch}",
            f"Seed:                {self.seed}",
            f"Source size:         {self.source_size} bytes ({self.source_lines} lines)",
            f"Output size:         {self.output_size} bytes",
            f"Bytecode size:       {self.bytecode_size} bytes",
            f"Instructions:        {self.instruction_count}",
            f"Constants:           {self.constant_count}",
            f"Functions:           {self.function_count}",
            f"Compile time:        {self.compile_time_ms:.1f} ms",
        ]
        return "\n".join(lines)