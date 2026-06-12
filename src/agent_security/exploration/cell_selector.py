from __future__ import annotations

import random
from collections.abc import Iterable

from agent_security.exploration.exemplar import Exemplar


class CellSelector:
    """Selects the next archive cell to branch from."""

    def select(self, candidates: Iterable[Exemplar], rng: random.Random) -> Exemplar:
        pool = list(candidates)
        if not pool:
            raise ValueError("cannot select from an empty archive")

        max_visits = max(exemplar.visits for exemplar in pool) + 1
        max_score = max(exemplar.score_hint for exemplar in pool) + 1

        weights: list[float] = []
        for exemplar in pool:
            visit_weight = (max_visits - exemplar.visits) / max_visits
            score_weight = (exemplar.score_hint + 1) / max_score
            depth_weight = 1.0 / (1.0 + abs(exemplar.depth - 3))
            weights.append(visit_weight * 2.0 + score_weight * 1.5 + depth_weight * 0.5)

        threshold = rng.uniform(0.0, sum(weights))
        cumulative = 0.0
        for exemplar, weight in zip(pool, weights, strict=True):
            cumulative += weight
            if threshold <= cumulative:
                return exemplar

        return pool[-1]
