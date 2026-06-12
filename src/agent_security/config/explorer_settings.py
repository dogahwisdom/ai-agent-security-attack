from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Self


@dataclass(frozen=True)
class ExplorerSettings:
    """Tunable parameters for the multi-step Go-Explore style attacker."""

    max_turns: int = 20
    branch_batch: int = 12
    target_shell: bool = False
    use_intent_hash: bool = True
    use_args_in_signature: bool = True
    args_count: int = 5
    use_outputs_in_signature: bool = True
    causality_bonus: float = 100.0
    high_impact_bonus: float = 75.0
    critical_impact_bonus: float = 150.0
    medium_impact_bonus: float = 25.0
    seed_prompt: str = "open demo"

    def __post_init__(self) -> None:
        if self.max_turns <= 0:
            raise ValueError("max_turns must be positive")
        if self.branch_batch <= 0:
            raise ValueError("branch_batch must be positive")
        if self.args_count < 0:
            raise ValueError("args_count must be non-negative")

    @classmethod
    def from_mapping(cls, config: Mapping[str, Any] | None) -> Self:
        data = dict(config or {})
        return cls(
            max_turns=int(data.get("max_turns", 20)),
            branch_batch=int(data.get("branch_batch", 12)),
            target_shell=bool(data.get("target_shell", False)),
            use_intent_hash=bool(data.get("use_intent", True)),
            use_args_in_signature=bool(data.get("use_args", True)),
            args_count=int(data.get("args_count", 5)),
            use_outputs_in_signature=bool(data.get("use_outputs", True)),
            causality_bonus=float(data.get("causality_bonus", 100.0)),
            high_impact_bonus=float(data.get("high_bonus", 75.0)),
            critical_impact_bonus=float(data.get("critical_bonus", 150.0)),
            medium_impact_bonus=float(data.get("medium_bonus", 25.0)),
            seed_prompt=str(data.get("seed_prompt", "open demo")),
        )
