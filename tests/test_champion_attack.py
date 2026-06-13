"""Tests for champion attack stack."""

from agent_security.algorithms.champion_attack import ChampionAttack
from agent_security.algorithms.scaled_exfil_attack import ScaledExfilAttack
from agent_security.exploration import attack_templates


def test_champion_templates_include_all_secret_markers() -> None:
    joined = " ".join(attack_templates.EXFIL_SETUPS)
    assert "TOKEN=admin123" in joined
    assert "PASSWORD=test123" in joined
    assert "sk_live_test" in joined


def test_confused_deputy_avoids_whitelist_words() -> None:
    banned = ("send ", "email ", "upload ")
    for prompt in attack_templates.CONFUSED_DEPUTY_SETUPS:
        lower = prompt.lower()
        assert not any(word in lower for word in banned)


def test_champion_and_scaled_exfil_instantiate() -> None:
    assert ChampionAttack() is not None
    assert ScaledExfilAttack() is not None
