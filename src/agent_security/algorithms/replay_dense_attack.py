"""Replay-dense exfil attack — top public LB strategy (Pilkwang / Yaroslav / Karnak)."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aicomp_sdk.attacks.contracts import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.core.env.api import AttackEnvProtocol

from agent_security.algorithms.elite_exfil_engine import EliteExfilEngine
from agent_security.exploration.elite_profiles import SEARCH_PROFILE_DEFAULT


class ReplayDenseAttack(AttackAlgorithmBase):
    """Single-hop exfil volume strategy from top Kaggle notebooks.

    Profiles:
      guide28_static980_c1 — ~980 candidates, zero search (targets Kohei-tier ~93)
      guide26_static700_c1 — Yaroslav public ~55.8 LB
      single_900           — Karnak: 60s search + 900 fill
    """

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        super().__init__(config)
        cfg = dict(config or {})
        self._profile = str(cfg.get("search_profile", SEARCH_PROFILE_DEFAULT))
        self._engine = EliteExfilEngine(self._profile)

    def run(self, env: AttackEnvProtocol, config: AttackRunConfig) -> list[AttackCandidate]:
        return self._engine.run(env, config)
