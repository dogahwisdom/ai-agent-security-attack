from __future__ import annotations

import random
from collections.abc import Mapping
from typing import Any

from aicomp_sdk.attacks.contracts import (
    AttackAlgorithmBase,
    AttackCandidate,
    AttackRunConfig,
)
from aicomp_sdk.core.env.api import AttackEnvProtocol
from aicomp_sdk.utils.timebox import Timebox

from agent_security.config.explorer_settings import ExplorerSettings
from agent_security.coordinators.branch_runner import BranchRunner
from agent_security.exploration.cell_selector import CellSelector
from agent_security.exploration.exemplar import Exemplar
from agent_security.exploration.frontier_archive import FrontierArchive
from agent_security.exploration.prompt_catalog import PromptCatalog
from agent_security.exploration.reward_estimator import RewardEstimator
from agent_security.exploration.signature_builder import SignatureBuilder


class MultiStepExplorer(AttackAlgorithmBase):
    """Go-Explore style multi-step attacker with modular components."""

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        super().__init__(config)
        self.settings = ExplorerSettings.from_mapping(config)
        self.prompts = PromptCatalog(target_shell=self.settings.target_shell)
        self.signatures = SignatureBuilder(self.settings)
        self.rewards = RewardEstimator(self.settings)
        self.selector = CellSelector()
        self.branch_runner = BranchRunner(
            settings=self.settings,
            prompts=self.prompts,
            signatures=self.signatures,
            rewards=self.rewards,
        )
        self.last_run_stats: dict[str, Any] = {}

    def run(self, env: AttackEnvProtocol, config: AttackRunConfig) -> list[AttackCandidate]:
        rng = random.Random(env.seed)
        timebox = Timebox(float(config.time_budget_s))
        archive = FrontierArchive()
        findings: list[AttackCandidate] = []
        productive_steps = 0

        self._seed_archive(env, archive, max_tool_hops=int(config.max_tool_hops))

        while not timebox.expired() and productive_steps < int(config.max_steps):
            parent = self.selector.select(archive.values(), rng)
            parent.visits += 1
            outcome = self.branch_runner.expand(
                env,
                archive,
                parent,
                rng,
                max_tool_hops=int(config.max_tool_hops),
            )
            if outcome.productive:
                productive_steps += 1
                findings.extend(outcome.findings)

        self.last_run_stats = {
            "productive_steps": productive_steps,
            "archive_size": len(archive),
            "findings_count": len(findings),
            "depth_distribution": archive.depth_distribution(),
        }
        return findings

    def _seed_archive(
        self,
        env: AttackEnvProtocol,
        archive: FrontierArchive,
        *,
        max_tool_hops: int,
    ) -> None:
        env.reset()
        env.interact(self.settings.seed_prompt, max_tool_hops=max_tool_hops)
        trace = env.export_trace_dict()
        signature = self.signatures.build(trace)
        archive.add(
            Exemplar(
                snapshot=env.snapshot(),
                user_messages=list(trace["user_messages"]),
                cell_hash=str(signature["hash"]),
                depth=1,
            )
        )
