"""Kaggle submission entry point.

Must expose a class named ``AttackAlgorithm`` inheriting from ``AttackAlgorithmBase``.
"""

from __future__ import annotations

from agent_security.algorithms.multi_step_explorer import MultiStepExplorer

AttackAlgorithm = MultiStepExplorer

__all__ = ["AttackAlgorithm"]
