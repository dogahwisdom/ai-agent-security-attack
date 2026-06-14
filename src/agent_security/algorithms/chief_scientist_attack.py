"""Chief Scientist attack — timeout-safe elite exfil + template diversity."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aicomp_sdk.attacks.contracts import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.core.env.api import AttackEnvProtocol

from agent_security.algorithms.elite_exfil_engine import EliteExfilEngine
from agent_security.algorithms.template_probe_attack import TemplateProbeAttack
from agent_security.coordinators.candidate_merger import CandidateMerger
from agent_security.exploration.elite_profiles import SEARCH_PROFILE_DEFAULT
from agent_security.exploration.elite_scoring import _detail_priority
from agent_security.exploration.replay_budget import ReplayBudgetSelector


class ChiefScientistAttack(AttackAlgorithmBase):
    """Two-phase red-team strategy from top public LB analysis (48.6 tier).

    Phase 1 (elite): verify-and-keep exfil with bounded fill and replay hop cap.
    Phase 2 (templates): multi-predicate diversity from 16.980+ public notebooks.
    """

    ELITE_BUDGET_FRACTION = 0.82
    TEMPLATE_BUDGET_FRACTION = 0.18

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        super().__init__(config)
        cfg = dict(config or {})
        self._profile = str(cfg.get("search_profile", SEARCH_PROFILE_DEFAULT))
        self._elite = EliteExfilEngine(self._profile)
        self._template = TemplateProbeAttack(cfg)

    def run(self, env: AttackEnvProtocol, config: AttackRunConfig) -> list[AttackCandidate]:
        budget = float(config.time_budget_s)
        shared = {
            "max_steps": config.max_steps,
            "max_tool_hops": config.max_tool_hops,
        }
        elite_findings = self._elite.run(
            env,
            AttackRunConfig(time_budget_s=budget * self.ELITE_BUDGET_FRACTION, **shared),
        )
        elite_detail_map = {
            tuple(candidate.user_messages): detail
            for candidate, detail in zip(
                elite_findings,
                self._elite.last_run_details,
                strict=False,
            )
        }
        template_findings = self._template.run(
            env,
            AttackRunConfig(time_budget_s=budget * self.TEMPLATE_BUDGET_FRACTION, **shared),
        )
        merged = CandidateMerger.merge_streams(elite_findings, template_findings)
        return self._select_final(merged, elite_detail_map)

    def _select_final(
        self,
        findings: list[AttackCandidate],
        elite_detail_map: dict[tuple[str, ...], dict[str, Any]],
    ) -> list[AttackCandidate]:
        profile = self._elite._p
        target_n = int(profile["return_target_candidates"])
        max_hops = int(profile["default_max_hops"])
        aligned_details: list[dict[str, Any]] = []
        for candidate in findings:
            key = tuple(candidate.user_messages)
            if key in elite_detail_map:
                aligned_details.append(elite_detail_map[key])
            else:
                aligned_details.append(self._synthetic_detail(candidate))

        selector = ReplayBudgetSelector(
            hop_cap=int(profile["replay_hop_cap"]),
            min_return=int(profile["min_return_candidates"]),
            priority_fn=_detail_priority,
        )
        selected, selected_details = selector.select(
            findings,
            aligned_details,
            target_n=target_n,
            replay_max_hops=max_hops,
        )
        self._elite.last_run_details = selected_details
        return selected

    @staticmethod
    def _synthetic_detail(candidate: AttackCandidate) -> dict[str, Any]:
        chain_len = len(candidate.user_messages)
        return {
            "family": "template_diversity",
            "phase": "template_probe",
            "verified": True,
            "predicate_count": 1,
            "predicates": "template",
            "raw_predicate_weight": 16,
            "trace_cell_count": chain_len,
            "chain_len": chain_len,
            "url_count": 0,
            "message_head": " | ".join(candidate.user_messages)[:160],
            "priority": 45.0 + chain_len,
        }
