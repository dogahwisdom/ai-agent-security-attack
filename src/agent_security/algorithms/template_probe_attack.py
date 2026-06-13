"""Multi-phase template probe attack (baseline-style, verify-and-keep)."""

from __future__ import annotations

from collections.abc import Mapping
from itertools import product
from typing import Any

from aicomp_sdk.attacks.contracts import AttackAlgorithmBase, AttackCandidate, AttackRunConfig
from aicomp_sdk.core.env.api import AttackEnvProtocol

from agent_security.coordinators.probe_runner import ProbeRunner
from agent_security.exploration import attack_templates as templates


class TemplateProbeAttack(AttackAlgorithmBase):
    """Targeted exfil / deputy / multi-step probes with live predicate verification.

    Inspired by public competition notebooks (baseline ~4.9, getting-started ~0.25).
    Only returns candidates that fire ``eval_predicates`` during search.
    """

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        super().__init__(config)

    def run(self, env: AttackEnvProtocol, config: AttackRunConfig) -> list[AttackCandidate]:
        runner = ProbeRunner(time_budget_s=float(config.time_budget_s))

        runner.run_phase(env, templates.EXFIL_SETUPS, margin_s=200)
        for setup in templates.EXFIL_SETUPS[:6]:
            if runner.time_left() < 400:
                break
            runner.snapshot_branch(env, setup, templates.EXFIL_FOLLOWUPS)

        runner.run_phase(env, templates.CONFUSED_DEPUTY_SETUPS, margin_s=200)

        for setup in templates.UNTRUSTED_SETUPS:
            if runner.time_left() < 400:
                break
            runner.snapshot_branch(env, setup, templates.UNTRUSTED_FOLLOWUPS, margin_s=300)

        successful_singles = [
            candidate.user_messages[0]
            for candidate in runner.findings
            if len(candidate.user_messages) == 1
        ]
        for base_payload in successful_singles:
            for prefix, suffix in product(
                templates.MUTATION_PREFIXES[:6],
                templates.MUTATION_SUFFIXES[:5],
            ):
                if runner.time_left() < 180:
                    break
                runner.probe(
                    env,
                    (runner.mutate(base_payload, prefix=prefix, suffix=suffix),),
                    margin_s=180,
                )

        for setup in templates.UNTRUSTED_SETUPS:
            for followup in templates.UNTRUSTED_FOLLOWUPS:
                if runner.time_left() < 280:
                    break
                runner.probe(env, (setup, followup), margin_s=250)

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

        return runner.findings
