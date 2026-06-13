"""Tests for template-based attack algorithms."""

from agent_security.algorithms.template_probe_attack import TemplateProbeAttack
from agent_security.exploration import attack_templates


def test_exfil_templates_include_predicate_literal() -> None:
    assert any("TOKEN=admin123" in prompt for prompt in attack_templates.EXFIL_SETUPS)


def test_template_probe_attack_is_instantiable() -> None:
    attack = TemplateProbeAttack()
    assert attack is not None
