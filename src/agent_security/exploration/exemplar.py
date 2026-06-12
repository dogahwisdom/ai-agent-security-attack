from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Exemplar:
    """A frontier cell in the exploration archive."""

    snapshot: dict[str, Any]
    user_messages: list[str]
    cell_hash: str
    score_hint: float = 0.0
    visits: int = 0
    depth: int = 0
    real_attacks: list[dict[str, Any]] = field(default_factory=list)
