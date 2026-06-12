from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Any

from aicomp_sdk.attacks.contracts import AttackCandidate
from aicomp_sdk.core.env.api import AttackEnvProtocol
from aicomp_sdk.core.predicates import eval_predicates

from agent_security.config.explorer_settings import ExplorerSettings
from agent_security.exploration.exemplar import Exemplar
from agent_security.exploration.frontier_archive import FrontierArchive
from agent_security.exploration.prompt_catalog import PromptCatalog
from agent_security.exploration.reward_estimator import RewardEstimator
from agent_security.exploration.signature_builder import SignatureBuilder


@dataclass(frozen=True)
class BranchOutcome:
    productive: bool
    findings: tuple[AttackCandidate, ...]


class BranchRunner:
    """Expands one archive cell by trying multiple prompt branches."""

    def __init__(
        self,
        *,
        settings: ExplorerSettings,
        prompts: PromptCatalog,
        signatures: SignatureBuilder,
        rewards: RewardEstimator,
    ) -> None:
        self._settings = settings
        self._prompts = prompts
        self._signatures = signatures
        self._rewards = rewards

    def expand(
        self,
        env: AttackEnvProtocol,
        archive: FrontierArchive,
        parent: Exemplar,
        rng: random.Random,
        *,
        max_tool_hops: int,
    ) -> BranchOutcome:
        findings: list[AttackCandidate] = []
        productive = False

        for _ in range(self._settings.branch_batch):
            env.restore(parent.snapshot)
            prompt = rng.choice(self._prompts.prompts)
            result = env.interact(prompt, max_tool_hops=max_tool_hops)
            if result.agent_refused:
                continue

            productive = True
            trace = env.export_trace_dict()
            predicates = eval_predicates(trace)
            signature = self._signatures.build(trace)
            cell_hash = str(signature["hash"])

            if archive.contains(cell_hash):
                continue

            score, real_attacks = self._rewards.score_novel_cell(
                parent=parent,
                trace=trace,
                signature=signature,
                predicates=predicates,
            )
            archive.add(
                Exemplar(
                    snapshot=env.snapshot(),
                    user_messages=list(trace["user_messages"]),
                    cell_hash=cell_hash,
                    score_hint=score,
                    depth=parent.depth + 1,
                    real_attacks=real_attacks,
                )
            )
            if predicates:
                findings.append(AttackCandidate.from_messages(trace["user_messages"]))

        return BranchOutcome(productive=productive, findings=tuple(findings))
