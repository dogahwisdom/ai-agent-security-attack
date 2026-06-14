"""Replay hop budgeting — keeps candidate volume high without notebook timeout."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from aicomp_sdk.attacks.contracts import AttackCandidate

from agent_security.exploration.elite_variants import _URL_RE


class ReplayHopEstimator:
    """Estimates evaluator replay cost per candidate."""

    @staticmethod
    def message_hops(message: str, replay_max_hops: int) -> int:
        url_count = len(_URL_RE.findall(str(message)))
        if url_count <= 0:
            return 1
        return max(1, min(int(replay_max_hops), url_count))

    @classmethod
    def candidate_hops(cls, candidate: AttackCandidate, replay_max_hops: int) -> int:
        return sum(
            cls.message_hops(str(message), replay_max_hops)
            for message in candidate.user_messages
        )


class ReplayBudgetSelector:
    """Selects top candidates under an estimated replay hop ceiling."""

    def __init__(
        self,
        *,
        hop_cap: int,
        min_return: int,
        priority_fn: Callable[[Mapping[str, Any]], float],
    ) -> None:
        self._hop_cap = int(hop_cap)
        self._min_return = int(min_return)
        self._priority_fn = priority_fn

    def select(
        self,
        findings: Sequence[AttackCandidate],
        details: Sequence[Mapping[str, Any]],
        *,
        target_n: int,
        replay_max_hops: int,
    ) -> tuple[list[AttackCandidate], list[dict[str, Any]]]:
        pairs = list(zip(findings, details, strict=False))
        pairs.sort(
            key=lambda item: self._priority_fn(item[1])
            + float(item[1].get("priority", 0.0) or 0.0),
            reverse=True,
        )
        if self._hop_cap <= 0:
            selected = pairs[:target_n]
            return self._pack(selected, replay_max_hops)

        selected: list[tuple[AttackCandidate, dict[str, Any]]] = []
        used_hops = 0
        for candidate, detail in pairs:
            if len(selected) >= target_n:
                break
            hops = ReplayHopEstimator.candidate_hops(candidate, replay_max_hops)
            if used_hops + hops > self._hop_cap and len(selected) >= self._min_return:
                continue
            kept = dict(detail)
            kept["estimated_replay_hops"] = hops
            selected.append((candidate, kept))
            used_hops += hops

        return self._pack(selected, replay_max_hops)

    @staticmethod
    def _pack(
        selected: Sequence[tuple[AttackCandidate, dict[str, Any]]],
        replay_max_hops: int,
    ) -> tuple[list[AttackCandidate], list[dict[str, Any]]]:
        findings: list[AttackCandidate] = []
        details: list[dict[str, Any]] = []
        for candidate, detail in selected:
            if "estimated_replay_hops" not in detail:
                detail = dict(detail)
                detail["estimated_replay_hops"] = ReplayHopEstimator.candidate_hops(
                    candidate, replay_max_hops
                )
            findings.append(candidate)
            details.append(detail)
        return findings, details
