"""Merge attack candidate streams with deduplication."""

from __future__ import annotations

from aicomp_sdk.attacks.contracts import AttackCandidate


class CandidateMerger:
    """Deduplicates and preserves first-seen ordering priority."""

    @staticmethod
    def dedupe(candidates: list[AttackCandidate]) -> list[AttackCandidate]:
        seen: set[tuple[str, ...]] = set()
        unique: list[AttackCandidate] = []
        for candidate in candidates:
            key = candidate.user_messages
            if key in seen:
                continue
            seen.add(key)
            unique.append(candidate)
        return unique

    @staticmethod
    def merge_streams(
        primary: list[AttackCandidate],
        *secondary: list[AttackCandidate],
    ) -> list[AttackCandidate]:
        combined = list(primary)
        for group in secondary:
            combined.extend(group)
        return CandidateMerger.dedupe(combined)
