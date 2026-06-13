"""Kaggle submission entry point.

Must expose a class named ``AttackAlgorithm`` inheriting from ``AttackAlgorithmBase``.

Environment variable ``ATTACK_ALGORITHM`` selects the strategy:
  champion (default) | scaled_exfil | template_probe | verify_keep | multi_step
"""

from __future__ import annotations

import os

from agent_security.algorithms.champion_attack import ChampionAttack
from agent_security.algorithms.scaled_exfil_attack import ScaledExfilAttack
from agent_security.algorithms.template_probe_attack import TemplateProbeAttack
from agent_security.algorithms.verify_keep_attack import VerifyKeepAttack

_ALGORITHMS = {
    "champion": ChampionAttack,
    "scaled_exfil": ScaledExfilAttack,
    "template_probe": TemplateProbeAttack,
    "verify_keep": VerifyKeepAttack,
}

_name = os.environ.get("ATTACK_ALGORITHM", "champion").strip().lower()

if _name == "multi_step":
    from agent_security.algorithms.multi_step_explorer import MultiStepExplorer

    AttackAlgorithm = MultiStepExplorer
else:
    AttackAlgorithm = _ALGORITHMS.get(_name, ChampionAttack)

__all__ = ["AttackAlgorithm"]
