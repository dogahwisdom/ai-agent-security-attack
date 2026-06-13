"""Kaggle submission entry point.

Must expose a class named ``AttackAlgorithm`` inheriting from ``AttackAlgorithmBase``.
Set ``ATTACK_ALGORITHM=verify_keep`` to use the verify-and-keep strategy instead.
"""

from __future__ import annotations

import os

from agent_security.algorithms.template_probe_attack import TemplateProbeAttack
from agent_security.algorithms.verify_keep_attack import VerifyKeepAttack

_ALGORITHMS = {
    "template_probe": TemplateProbeAttack,
    "verify_keep": VerifyKeepAttack,
    "multi_step": None,  # lazy import for legacy Go-Explore explorer
}

_name = os.environ.get("ATTACK_ALGORITHM", "template_probe").strip().lower()

if _name == "multi_step":
    from agent_security.algorithms.multi_step_explorer import MultiStepExplorer

    AttackAlgorithm = MultiStepExplorer
else:
    AttackAlgorithm = _ALGORITHMS.get(_name, TemplateProbeAttack)

__all__ = ["AttackAlgorithm"]
