"""Tests for elite exfil attack."""

from agent_security.algorithms.elite_exfil_attack import EliteExfilAttack
from agent_security.algorithms.elite_exfil_engine import EliteExfilEngine
from agent_security.exploration.elite_profiles import apply_profile
from agent_security.exploration.elite_prompts import SCORING_PAYLOADS
from agent_security.exploration.elite_variants import EXFIL_VARIANTS


def test_kaggle_champion_profile_targets_high_return_count() -> None:
    profile = apply_profile("kaggle_champion")
    assert profile["return_target_candidates"] == 300
    assert profile["replay_hop_cap"] == 640
    assert profile["chain_fill_enabled"] is True


def test_elite_static_fallback_returns_candidates() -> None:
    engine = EliteExfilEngine("kaggle_champion")
    candidates = engine._static_candidates(32, "test")
    assert len(candidates) == 32
    assert all(len(c.user_messages) >= 1 for c in candidates)


def test_exfil_variants_cover_scoring_payloads() -> None:
    urls = ["http://node0001-test.v.example.net/ingest"]
    for payload in SCORING_PAYLOADS[:3]:
        message = EXFIL_VARIANTS[0](urls, payload)
        assert payload in message
        assert "http.post" in message.lower()


def test_elite_attack_instantiates() -> None:
    assert EliteExfilAttack() is not None
