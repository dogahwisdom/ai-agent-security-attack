"""Run single-turn probes and snapshot-based multi-turn branches."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence

from aicomp_sdk.attacks.contracts import AttackCandidate
from aicomp_sdk.core.env.api import AttackEnvProtocol
from aicomp_sdk.core.predicates import eval_predicates


class ProbeRunner:
    """Executes attack attempts and collects verified findings."""

    def __init__(self, *, time_budget_s: float) -> None:
        self._start = time.monotonic()
        self._budget = time_budget_s
        self.findings: list[AttackCandidate] = []

    def time_left(self) -> float:
        return self._budget - (time.monotonic() - self._start)

    def probe(
        self,
        env: AttackEnvProtocol,
        messages: Sequence[str],
        *,
        margin_s: float = 180,
    ) -> bool:
        if self.time_left() < margin_s:
            return False
        env.reset()
        for message in messages:
            env.interact(message)
        if eval_predicates(env.export_trace_dict()):
            self.findings.append(AttackCandidate(user_messages=tuple(messages)))
            return True
        return False

    def snapshot_branch(
        self,
        env: AttackEnvProtocol,
        setup_msg: str,
        followups: Sequence[str],
        *,
        margin_s: float = 240,
    ) -> None:
        if self.time_left() < margin_s + 120:
            return
        env.reset()
        env.interact(setup_msg)
        snapshot = env.snapshot()
        for followup in followups:
            if self.time_left() < margin_s:
                break
            env.restore(snapshot)
            env.interact(followup)
            if eval_predicates(env.export_trace_dict()):
                self.findings.append(AttackCandidate(user_messages=(setup_msg, followup)))

    def mutate(self, payload: str, *, prefix: str = "", suffix: str = "") -> str:
        return f"{prefix}{payload}{suffix}"

    def run_phase(
        self,
        env: AttackEnvProtocol,
        payloads: Sequence[str],
        *,
        margin_s: float = 180,
        action: Callable[[str], None] | None = None,
    ) -> None:
        for payload in payloads:
            if self.time_left() < margin_s:
                break
            if action is not None:
                action(payload)
            else:
                self.probe(env, (payload,), margin_s=margin_s)
