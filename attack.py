"""Kaggle submission entry point.

Must expose a class named ``AttackAlgorithm`` inheriting from ``AttackAlgorithmBase``.

Environment variables:
  ATTACK_ALGORITHM — chief (default) | elite | champion | scaled_exfil | ...
  SEARCH_PROFILE   — kaggle_champion (default) | bounded_adaptive_300 | ...
"""

from __future__ import annotations

import os

from agent_security.algorithms.champion_attack import ChampionAttack
from agent_security.algorithms.chief_scientist_attack import ChiefScientistAttack
from agent_security.algorithms.elite_exfil_attack import EliteExfilAttack
from agent_security.algorithms.scaled_exfil_attack import ScaledExfilAttack
from agent_security.algorithms.template_probe_attack import TemplateProbeAttack
from agent_security.algorithms.verify_keep_attack import VerifyKeepAttack
from agent_security.exploration.elite_profiles import SEARCH_PROFILE_DEFAULT

_ALGORITHMS = {
    "chief": ChiefScientistAttack,
    "elite": EliteExfilAttack,
    "champion": ChampionAttack,
    "scaled_exfil": ScaledExfilAttack,
    "template_probe": TemplateProbeAttack,
    "verify_keep": VerifyKeepAttack,
}

_name = os.environ.get("ATTACK_ALGORITHM", "chief").strip().lower()
_profile = os.environ.get("SEARCH_PROFILE", SEARCH_PROFILE_DEFAULT).strip()

_attack_config = {"search_profile": _profile} if _profile else None

if _name == "multi_step":
    from agent_security.algorithms.multi_step_explorer import MultiStepExplorer

    AttackAlgorithm = MultiStepExplorer
else:
    _cls = _ALGORITHMS.get(_name, ChiefScientistAttack)

    class AttackAlgorithm(_cls):  # type: ignore[misc,valid-type]
        def __init__(self, config=None):
            merged = dict(_attack_config or {})
            if config:
                merged.update(dict(config))
            super().__init__(merged or None)

__all__ = ["AttackAlgorithm"]
