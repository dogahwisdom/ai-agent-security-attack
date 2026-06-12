from __future__ import annotations

from collections.abc import Iterable

from agent_security.exploration.exemplar import Exemplar


class FrontierArchive:
    """Stores discovered environment cells keyed by signature hash."""

    def __init__(self) -> None:
        self._cells: dict[str, Exemplar] = {}

    def __len__(self) -> int:
        return len(self._cells)

    def contains(self, cell_hash: str) -> bool:
        return cell_hash in self._cells

    def add(self, exemplar: Exemplar) -> None:
        self._cells[exemplar.cell_hash] = exemplar

    def values(self) -> Iterable[Exemplar]:
        return self._cells.values()

    def depth_distribution(self) -> dict[int, int]:
        counts: dict[int, int] = {}
        for exemplar in self._cells.values():
            counts[exemplar.depth] = counts.get(exemplar.depth, 0) + 1
        return dict(sorted(counts.items()))
