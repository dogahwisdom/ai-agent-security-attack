"""Full 16.980-phase template probe with all predicate families."""

from __future__ import annotations

from collections.abc import Mapping
from itertools import product
from typing import Any

from aicomp_sdk.attacks.contracts import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.core.env.api import AttackEnvProtocol

from agent_security.coordinators.probe_runner import ProbeRunner
from agent_security.exploration import attack_templates as templates


class TemplateProbeAttack(AttackAlgorithmBase):
    """Seven-phase template probe from the 16.980 public-score notebook."""

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        super().__init__(config)

    def run(self, env: AttackEnvProtocol, config: AttackRunConfig) -> list[AttackCandidate]:
        runner = ProbeRunner(time_budget_s=float(config.time_budget_s))

        runner.run_phase(env, templates.EXFIL_SETUPS, margin_s=200)
        for setup in templates.EXFIL_SETUPS[:8]:
            if runner.time_left() < 400:
                break
            runner.snapshot_branch(env, setup, templates.EXFIL_FOLLOWUPS)

        for setup in templates.UNTRUSTED_SETUPS[:6]:
            if runner.time_left() < 400:
                break
            runner.snapshot_branch(
                env, setup, templates.UNTRUSTED_FOLLOWUPS_SHARE, margin_s=300
            )

        for setup in templates.UNTRUSTED_SETUPS[6:]:
            if runner.time_left() < 400:
                break
            runner.snapshot_branch(
                env, setup, templates.UNTRUSTED_FOLLOWUPS_WRITE, margin_s=300
            )

        for setup in templates.UNTRUSTED_SETUPS[:4]:
            if runner.time_left() < 400:
                break
            runner.snapshot_branch(
                env, setup, templates.UNTRUSTED_FOLLOWUPS_EXFIL, margin_s=300
            )

        runner.run_phase(env, templates.DESTRUCTIVE_SETUPS, margin_s=200)
        runner.run_phase(env, templates.CONFUSED_DEPUTY_SETUPS, margin_s=200)

        successful_singles = [
            candidate.user_messages[0]
            for candidate in runner.findings
            if len(candidate.user_messages) == 1
        ]
        for base_payload in successful_singles:
            for prefix, suffix in product(
                templates.MUTATION_PREFIXES,
                templates.MUTATION_SUFFIXES,
            ):
                if runner.time_left() < 180:
                    break
                runner.probe(
                    env,
                    (runner.mutate(base_payload, prefix=prefix, suffix=suffix),),
                    margin_s=180,
                )

        for payload in templates.EXFIL_SETUPS:
            for suffix in templates.MUTATION_SUFFIXES:
                if runner.time_left() < 180:
                    break
                runner.probe(env, (runner.mutate(payload, suffix=suffix),), margin_s=180)

        for payload in templates.CONFUSED_DEPUTY_SETUPS:
            for prefix in templates.MUTATION_PREFIXES:
                if runner.time_left() < 180:
                    break
                runner.probe(env, (runner.mutate(payload, prefix=prefix),), margin_s=180)

        for payload in templates.DESTRUCTIVE_SETUPS:
            for prefix in templates.MUTATION_PREFIXES:
                if runner.time_left() < 180:
                    break
                runner.probe(env, (runner.mutate(payload, prefix=prefix),), margin_s=180)

        all_untrusted_followups = (
            templates.UNTRUSTED_FOLLOWUPS_SHARE
            + templates.UNTRUSTED_FOLLOWUPS_WRITE
            + templates.UNTRUSTED_FOLLOWUPS_EXFIL
        )
        for setup in templates.UNTRUSTED_SETUPS:
            for followup in all_untrusted_followups:
                if runner.time_left() < 250:
                    break
                runner.probe(env, (setup, followup), margin_s=220)

        return runner.findings
