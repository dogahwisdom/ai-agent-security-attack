"""Tests for replay-dense attack profiles."""

from agent_security.algorithms.elite_exfil_engine import EliteExfilEngine
from agent_security.algorithms.replay_dense_attack import ReplayDenseAttack
from agent_security.exploration.elite_profiles import SEARCH_PROFILE_DEFAULT, apply_profile


def test_default_profile_is_guide28_static980() -> None:
    assert SEARCH_PROFILE_DEFAULT == "guide28_static980_c1"


def test_guide28_static980_profile_settings() -> None:
    profile = apply_profile("guide28_static980_c1")
    assert profile["return_target_candidates"] == 980
    assert profile["min_return_candidates"] == 980
    assert profile["endpoints_per_msg"] == 1
    assert profile["max_msg_chars"] == 140
    assert profile["search_fraction"] == 0.0


def test_replay_dense_static_fill_count() -> None:
    engine = EliteExfilEngine("guide28_static980_c1")
    findings = engine._static_candidates(980, "static")
    assert len(findings) == 980
    assert all(len(candidate.user_messages) == 1 for candidate in findings)


def test_replay_dense_attack_instantiates() -> None:
    attack = ReplayDenseAttack()
    assert attack._profile == SEARCH_PROFILE_DEFAULT
