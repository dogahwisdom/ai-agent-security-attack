"""Elite exfil attack — aggressive_safe profile targeting top-LB scores."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aicomp_sdk.attacks.contracts import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.core.env.api import AttackEnvProtocol

from agent_security.algorithms.elite_exfil_engine import EliteExfilEngine
from agent_security.exploration.elite_profiles import SEARCH_PROFILE_DEFAULT


class EliteExfilAttack(AttackAlgorithmBase):
    """Verify-and-keep exfil with bounded fill (public LB ~48 score tier pattern)."""

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        super().__init__(config)
        cfg = dict(config or {})
        self._profile = str(cfg.get("search_profile", SEARCH_PROFILE_DEFAULT))
        self._engine = EliteExfilEngine(self._profile)

    def run(self, env: AttackEnvProtocol, config: AttackRunConfig) -> list[AttackCandidate]:
        return self._engine.run(env, config)
