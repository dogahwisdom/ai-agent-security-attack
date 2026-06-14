"""Tests for Chief Scientist attack."""

from agent_security.algorithms.chief_scientist_attack import ChiefScientistAttack


def test_chief_scientist_attack_instantiates() -> None:
    assert ChiefScientistAttack() is not None


def test_chief_scientist_accepts_profile_override() -> None:
    attack = ChiefScientistAttack({"search_profile": "bounded_adaptive_300"})
    assert attack._profile == "bounded_adaptive_300"
