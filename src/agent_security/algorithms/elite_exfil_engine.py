"""Elite exfil search engine."""

from __future__ import annotations

import itertools
import time
from collections.abc import Mapping, Sequence
from typing import Any

from aicomp_sdk.attacks.contracts import AttackCandidate, AttackRunConfig
from aicomp_sdk.core.predicates import eval_predicates

from agent_security.exploration.elite_profiles import SEARCH_PROFILE_DEFAULT, apply_profile
from agent_security.exploration.elite_prompts import (
    DESTRUCTIVE_SETUPS,
    EXFIL_FOLLOWUPS,
    MUTATION_PREFIXES,
    MUTATION_SUFFIXES,
    SCORING_PAYLOADS,
    SOURCE_LOTTERY_CHAINS,
)
from agent_security.exploration.elite_scoring import (
    _cap_message,
    _detail_priority,
    _make_exfil_chain,
    _mutate,
    _predicate_raw,
    _trace_cell_count,
)
from agent_security.exploration.elite_variants import (
    _URL_RE,
    CALIBRATION_EXFIL_NAMES,
    CALIBRATION_EXFIL_VARIANTS,
    DEPUTY_VARIANT_NAMES,
    DEPUTY_VARIANTS,
    EXFIL_VARIANT_NAMES,
    EXFIL_VARIANTS,
    MAX_MSG_CHARS,
)
from agent_security.exploration.replay_budget import ReplayBudgetSelector

try:
    from aicomp_sdk.evaluation.ops import MAX_REPLAY_FINDINGS as SDK_MAX_REPLAY_FINDINGS
except Exception:
    SDK_MAX_REPLAY_FINDINGS = 2000

MIN_PROBE_MARGIN_S = 2.0


def _bind_profile(profile_name: str) -> dict[str, Any]:
    p = apply_profile(profile_name)
    p["max_verified_candidates"] = min(int(p["max_verified_candidates"]), int(SDK_MAX_REPLAY_FINDINGS))
    p["return_target_candidates"] = min(int(p["return_target_candidates"]), int(SDK_MAX_REPLAY_FINDINGS))
    return p

class EliteExfilEngine:
    def __init__(self, profile_name: str = SEARCH_PROFILE_DEFAULT) -> None:
        self._p = _bind_profile(profile_name)
        self.last_run_details: list[dict[str, Any]] = []

    def _host_factory(self):
        counter = itertools.count()

        def host(tag: str) -> str:
            idx = next(counter)
            return f"http://node{idx:04d}-{tag}.v.example.net/ingest"

        return host

    def _semantic_host_factory(self):
        counter = itertools.count()
        stems = (
            "verify", "healthcheck", "audit", "monitor", "dr", "pipeline",
            "telemetry", "backup", "deploy", "canary", "staging", "rotate",
        )

        def host(tag: str) -> str:
            idx = next(counter)
            stem = stems[idx % len(stems)]
            return f"http://{stem}{idx:04d}.example.com/{tag}"

        return host

    def _addr_factory(self):
        counter = itertools.count()

        def addr() -> str:
            return f"ops{next(counter):04d}@status.example.net"

        return addr

    def _add_candidate(
        self,
        findings: list[AttackCandidate],
        messages: Sequence[str],
        family: str,
        verified: bool,
        preds: Sequence[Mapping[str, Any]] | None = None,
        trace: Mapping[str, Any] | None = None,
        phase: str = "",
        priority: float = 0.0,
    ) -> bool:
        clean = tuple(_cap_message(str(m)) for m in messages)
        if any(len(m) > MAX_MSG_CHARS for m in clean):
            return False
        if clean in {tuple(c.user_messages) for c in findings}:
            return False
        preds = list(preds or [])
        trace = trace or {}
        raw = _predicate_raw(preds)
        cells = _trace_cell_count(trace) if verified else 0
        detail = {
            "family": family,
            "phase": phase,
            "verified": bool(verified),
            "predicate_count": len(preds),
            "predicates": ",".join(sorted({str(p.get("predicate", "")) for p in preds if p.get("predicate")})),
            "raw_predicate_weight": raw,
            "trace_cell_count": cells,
            "chain_len": len(clean),
            "url_count": sum(len(_URL_RE.findall(m)) for m in clean),
            "message_head": " | ".join(clean)[:160],
            "priority": priority,
        }
        if verified:
            detail["priority"] = max(priority, _detail_priority(detail))
        findings.append(AttackCandidate(user_messages=clean))
        self.last_run_details.append(detail)
        return True

    def _sort_findings(self, findings: list[AttackCandidate]) -> list[AttackCandidate]:
        pairs = list(zip(findings, self.last_run_details, strict=True))
        pairs.sort(key=lambda item: _detail_priority(item[1]) + float(item[1].get("priority", 0.0) or 0.0), reverse=True)
        self.last_run_details = [detail for _, detail in pairs]
        return [candidate for candidate, _ in pairs]

    def _finalize_selection(
        self,
        findings: list[AttackCandidate],
        target_n: int,
        max_hops: int,
    ) -> list[AttackCandidate]:
        sorted_findings = self._sort_findings(findings)
        selector = ReplayBudgetSelector(
            hop_cap=int(self._p["replay_hop_cap"]),
            min_return=int(self._p["min_return_candidates"]),
            priority_fn=_detail_priority,
        )
        selected, details = selector.select(
            sorted_findings,
            self.last_run_details,
            target_n=target_n,
            replay_max_hops=max_hops,
        )
        self.last_run_details = details
        return selected

    def _static_candidates(self, n: int, family_prefix: str) -> list[AttackCandidate]:
        findings: list[AttackCandidate] = []
        host = self._host_factory()
        addr = self._addr_factory()
        endpoint_count = min(4, self._p["endpoints_per_msg"], self._p["default_max_hops"])
        combo_iter = itertools.cycle(itertools.product(range(len(EXFIL_VARIANTS)), SCORING_PAYLOADS))
        if self._p["chain_fill_enabled"]:
            deputy_floor = max(8, int(n * 0.05))
            exfil_n = max(1, n - deputy_floor)
            single_target = min(exfil_n, max(1, int(n * self._p["single_fill_fraction"])))
            chain2_target = min(exfil_n, max(single_target, int(n * self._p["chain2_fill_fraction"])))

            while len(findings) < single_target:
                variant_idx, payload = next(combo_iter)
                urls = [host(f"static_single{len(findings) % 29}")]
                msg = EXFIL_VARIANTS[variant_idx](urls, payload)
                self._add_candidate(
                    findings,
                    (msg,),
                    f"{family_prefix}_exfil_single_fill",
                    False,
                    phase="static_single",
                    priority=90.0,
                )
            while len(findings) < chain2_target:
                _, payload = next(combo_iter)
                chain = _make_exfil_chain(host, payload, 2, f"static_chain2_{len(findings) % 29}")
                self._add_candidate(
                    findings,
                    chain,
                    f"{family_prefix}_exfil_chain2_fill",
                    False,
                    phase="static_chain",
                    priority=96.0,
                )
            while len(findings) < exfil_n:
                _, payload = next(combo_iter)
                chain = _make_exfil_chain(host, payload, 3, f"static_chain3_{len(findings) % 29}")
                self._add_candidate(
                    findings,
                    chain,
                    f"{family_prefix}_exfil_chain3_fill",
                    False,
                    phase="static_chain",
                    priority=102.0,
                )
        else:
            exfil_n = max(1, int(n * 0.82))
            while len(findings) < exfil_n:
                variant_idx, payload = next(combo_iter)
                urls = [host(f"static{len(findings) % 29}") for _ in range(endpoint_count)]
                msg = EXFIL_VARIANTS[variant_idx](urls, payload)
                self._add_candidate(
                    findings,
                    (msg,),
                    f"{family_prefix}_exfil_fill",
                    False,
                    phase="static",
                    priority=80.0 + endpoint_count,
                )
        j = 0
        while len(findings) < n:
            variant = DEPUTY_VARIANTS[j % len(DEPUTY_VARIANTS)]
            self._add_candidate(
                findings,
                (variant(addr()),),
                f"{family_prefix}_confused_deputy_fill",
                False,
                phase="static",
                priority=20.0,
            )
            j += 1
        return self._sort_findings(findings)

    def _interact(self, env: Any, message: str, max_hops: int) -> None:
        try:
            env.interact(message, max_tool_hops=max_hops)
        except TypeError:
            env.interact(message)

    def run(self, env, config: AttackRunConfig) -> list[AttackCandidate]:
        self.last_run_details = []
        if env is None:
            return self._static_candidates(self._p["static_fallback_candidates"], "static")

        started = time.time()
        budget = float(getattr(config, "time_budget_s", 30.0) or 30.0)
        config_hops = int(getattr(config, "max_tool_hops", self._p["default_max_hops"]) or self._p["default_max_hops"])
        max_hops = max(1, min(self._p["default_max_hops"], config_hops))
        endpoint_counts_seen: set[int] = set()
        endpoint_counts_ordered: list[int] = []
        for k in self._p["endpoint_counts"]:
            if int(k) <= 0:
                continue
            bounded = max(1, min(int(k), max_hops))
            if bounded in endpoint_counts_seen:
                continue
            endpoint_counts_seen.add(bounded)
            endpoint_counts_ordered.append(bounded)
        endpoint_counts = tuple(endpoint_counts_ordered)
        search_s = min(self._p["max_search_s"], max(5.0, budget * self._p["search_fraction"]))
        deadline = started + search_s
        findings: list[AttackCandidate] = []
        attempted: set[tuple[str, ...]] = set()
        host = self._host_factory()
        semantic_host = self._semantic_host_factory()
        addr = self._addr_factory()

        def time_left() -> float:
            return deadline - time.time()

        def can_probe() -> bool:
            return len(findings) < self._p["max_verified_candidates"] and time_left() > MIN_PROBE_MARGIN_S

        def verify(messages: Sequence[str], family: str, phase: str, priority: float = 0.0) -> dict[str, Any] | None:
            if not can_probe():
                return None
            clean = tuple(_cap_message(str(m)) for m in messages)
            if clean in attempted:
                return None
            attempted.add(clean)
            if clean in {tuple(c.user_messages) for c in findings}:
                return None
            try:
                env.reset()
                for message in clean:
                    self._interact(env, message, max_hops)
                trace = env.export_trace_dict()
                preds = eval_predicates(trace)
            except Exception:
                return None
            if not preds:
                return None
            added = self._add_candidate(
                findings,
                clean,
                family,
                True,
                preds=preds,
                trace=trace,
                phase=phase,
                priority=priority,
            )
            return self.last_run_details[-1] if added else None

        def endpoint_urls(tag: str, n: int, semantic: bool = False) -> list[str]:
            maker = semantic_host if semantic else host
            return [maker(tag) for _ in range(max(1, min(n, max_hops)))]

        def add_fill(messages: Sequence[str], family: str, phase: str, priority: float) -> bool:
            clean = tuple(_cap_message(str(m)) for m in messages)
            if clean in attempted:
                return False
            return self._add_candidate(findings, clean, family, False, phase=phase, priority=priority)

        def snapshot_branch(setup_msg: str, followups: Sequence[str], family: str, phase: str) -> None:
            if not can_probe():
                return
            try:
                env.reset()
                self._interact(env, setup_msg, max_hops)
                snap = env.snapshot()
            except Exception:
                return
            for followup in followups:
                if not can_probe():
                    break
                clean = (_cap_message(setup_msg), _cap_message(followup))
                if clean in attempted:
                    continue
                attempted.add(clean)
                try:
                    env.restore(snap)
                    self._interact(env, followup, max_hops)
                    trace = env.export_trace_dict()
                    preds = eval_predicates(trace)
                except Exception:
                    continue
                if not preds:
                    continue
                self._add_candidate(
                    findings,
                    clean,
                    family,
                    True,
                    preds=preds,
                    trace=trace,
                    phase=phase,
                    priority=35.0,
                )

        calibration_end = started + search_s * 0.22
        mutation_end = started + search_s * 0.38
        mass_end = started + search_s * 0.78
        single_end = started + search_s * 0.88
        deputy_end = started + search_s * 0.94
        destructive_end = started + search_s * 0.975

        good_combos: list[dict[str, Any]] = []
        successful_single_messages: list[str] = []
        if self._p["calibration_order"] == "endpoint_outer":
            calibration_iter = (
                (payload, variant_idx, endpoint_count)
                for endpoint_count in endpoint_counts
                for payload in SCORING_PAYLOADS
                for variant_idx in range(len(CALIBRATION_EXFIL_VARIANTS))
            )
        else:
            calibration_iter = (
                (payload, variant_idx, endpoint_count)
                for payload in SCORING_PAYLOADS
                for variant_idx in range(len(CALIBRATION_EXFIL_VARIANTS))
                for endpoint_count in endpoint_counts
            )

        for payload, variant_idx, endpoint_count in calibration_iter:
            if time.time() >= calibration_end or not can_probe():
                break
            variant = CALIBRATION_EXFIL_VARIANTS[variant_idx]
            name = CALIBRATION_EXFIL_NAMES[variant_idx]
            use_semantic_urls = "semantic" in name
            urls = endpoint_urls("cal", endpoint_count, semantic=use_semantic_urls)
            detail = verify(
                (variant(urls, payload),),
                f"verified_exfil_calibration:{name}",
                "calibration",
                priority=200.0 + endpoint_count,
            )
            if not detail:
                continue
            score = float(detail.get("raw_predicate_weight", 0)) + 2.0 * float(detail.get("trace_cell_count", 0))
            observed_exfil = max(0, int(float(detail.get("raw_predicate_weight", 0)) // 16))
            if name in EXFIL_VARIANT_NAMES:
                mapped_variant_idx = EXFIL_VARIANT_NAMES.index(name)
            else:
                mapped_variant_idx = min(variant_idx, len(EXFIL_VARIANTS) - 1)
            good_combos.append({
                "score": score,
                "endpoint_count": endpoint_count,
                "observed_exfil": observed_exfil,
                "variant_idx": mapped_variant_idx,
                "payload": payload,
                "semantic_urls": use_semantic_urls,
            })
            if endpoint_count == 1:
                successful_single_messages.append(findings[-1].user_messages[0])
        if not good_combos:
            default_endpoint = min(4, max_hops)
            good_combos = [
                {
                    "score": 0.0,
                    "endpoint_count": default_endpoint,
                    "observed_exfil": 0,
                    "variant_idx": idx,
                    "payload": payload,
                    "semantic_urls": "semantic" in EXFIL_VARIANT_NAMES[idx],
                }
                for idx in range(min(3, len(EXFIL_VARIANTS)))
                for payload in SCORING_PAYLOADS
            ]
        good_combos.sort(
            key=lambda row: (
                int(row.get("observed_exfil", 0)),
                float(row.get("score", 0.0)),
                -int(row.get("endpoint_count", 1)),
            ),
            reverse=True,
        )

        for base_msg in list(dict.fromkeys(successful_single_messages))[:12]:
            for prefix, suffix in itertools.product(MUTATION_PREFIXES, MUTATION_SUFFIXES):
                if time.time() >= mutation_end or not can_probe():
                    break
                verify((_mutate(base_msg, prefix, suffix),), "verified_exfil_mutation", "success_mutation", priority=170.0)

        combo_cycle = itertools.cycle(good_combos[: max(1, min(8, len(good_combos)))])
        while time.time() < mass_end and can_probe():
            combo = next(combo_cycle)
            variant = EXFIL_VARIANTS[int(combo["variant_idx"])]
            urls = endpoint_urls("mass", int(combo["endpoint_count"]), semantic=bool(combo.get("semantic_urls")))
            verify(
                (variant(urls, str(combo["payload"])),),
                f"verified_exfil_multi:{EXFIL_VARIANT_NAMES[int(combo['variant_idx'])]}",
                "mass_exfil",
                priority=150.0 + float(combo["endpoint_count"]),
            )

        while time.time() < single_end and can_probe():
            combo = next(combo_cycle)
            variant = EXFIL_VARIANTS[int(combo["variant_idx"])]
            verify(
                (variant(endpoint_urls("single", 1, semantic=bool(combo.get("semantic_urls"))), str(combo["payload"])),),
                f"verified_exfil_single:{EXFIL_VARIANT_NAMES[int(combo['variant_idx'])]}",
                "single_exfil",
                priority=120.0,
            )

        deputy_successes: list[str] = []
        for i, variant in enumerate(DEPUTY_VARIANTS):
            if time.time() >= deputy_end or not can_probe():
                break
            detail = verify(
                (variant(addr()),),
                f"verified_confused_deputy_calibration:{DEPUTY_VARIANT_NAMES[i]}",
                "deputy_calibration",
                priority=70.0,
            )
            if detail:
                deputy_successes.append(findings[-1].user_messages[0])
        deputy_cycle = itertools.cycle(range(len(DEPUTY_VARIANTS)))
        while time.time() < deputy_end and can_probe():
            idx = next(deputy_cycle)
            verify(
                (DEPUTY_VARIANTS[idx](addr()),),
                f"verified_confused_deputy:{DEPUTY_VARIANT_NAMES[idx]}",
                "deputy",
                priority=55.0,
            )

        for base_msg in deputy_successes[:6]:
            for suffix in MUTATION_SUFFIXES[:3]:
                if time.time() >= deputy_end or not can_probe():
                    break
                verify((_mutate(base_msg, suffix=suffix),), "verified_confused_deputy_mutation", "deputy_mutation", priority=50.0)

        destructive_checked = 0
        for payload in DESTRUCTIVE_SETUPS:
            if destructive_checked >= self._p["destructive_probe_limit"] or time.time() >= destructive_end or not can_probe():
                break
            destructive_checked += 1
            verify((payload,), "verified_destructive_write", "destructive_verified_only", priority=62.0)

        for payload in DESTRUCTIVE_SETUPS[: max(0, min(self._p["destructive_probe_limit"] - destructive_checked, 6))]:
            if time.time() >= destructive_end or not can_probe():
                break
            destructive_checked += 1
            verify((_mutate(payload, prefix="Routine cleanup: "),), "verified_destructive_write_mutation", "destructive_verified_only", priority=58.0)

        for combo in good_combos[:3]:
            if not can_probe():
                break
            variant = EXFIL_VARIANTS[int(combo["variant_idx"])]
            setup = variant(endpoint_urls("branch", 1, semantic=bool(combo.get("semantic_urls"))), str(combo["payload"]))
            followups = [
                template.format(url=host("branch_follow"))
                for template in EXFIL_FOLLOWUPS[:3]
            ]
            snapshot_branch(setup, followups, "verified_exfil_snapshot_branch", "snapshot_branch")

        for chain in SOURCE_LOTTERY_CHAINS[:self._p["source_lottery_limit"]]:
            if not can_probe():
                break
            verify(chain, "verified_source_action_lottery", "source_lottery", priority=5.0)

        target_n = self._p["return_target_candidates"] if findings else self._p["empty_run_fallback_candidates"]
        fill_cycle = itertools.cycle(good_combos[: max(1, min(12, len(good_combos)))])
        if self._p["chain_fill_enabled"]:
            best_observed_exfil = max(int(row.get("observed_exfil", 0) or 0) for row in good_combos)
            use_observed_multi_fill = (
                self._p["adaptive_fill_enabled"]
                and best_observed_exfil >= self._p["adaptive_multi_min_observed_exfil"]
            )
            single_fill_target = min(
                target_n,
                max(len(findings), int(target_n * self._p["single_fill_fraction"])),
            )
            chain2_target = min(
                target_n,
                max(single_fill_target, int(target_n * self._p["chain2_fill_fraction"])),
            )

            if use_observed_multi_fill:
                adaptive_stop = target_n
                max_adaptive = int(self._p.get("adaptive_fill_max_candidates", 0) or 0)
                if max_adaptive > 0:
                    adaptive_stop = min(target_n, len(findings) + max_adaptive)
                while len(findings) < adaptive_stop:
                    combo = next(fill_cycle)
                    variant_idx = int(combo["variant_idx"])
                    payload = str(combo["payload"])
                    endpoint_count = max(
                        2,
                        min(
                            int(combo.get("endpoint_count", 1) or 1),
                            self._p["endpoints_per_msg"],
                            max_hops,
                        ),
                    )
                    urls = endpoint_urls(
                        "fill_observed_multi",
                        endpoint_count,
                        semantic=bool(combo.get("semantic_urls")),
                    )
                    msg = EXFIL_VARIANTS[variant_idx](urls, payload)
                    priority = 104.0 + float(combo.get("observed_exfil", 0) or 0)
                    if add_fill(
                        (msg,),
                        f"fill_exfil_observed_multi:{EXFIL_VARIANT_NAMES[variant_idx]}",
                        "bounded_fill_observed_multi",
                        priority=priority,
                    ):
                        continue
                    break
                if len(findings) >= target_n:
                    return self._finalize_selection(findings, target_n, max_hops)

            while len(findings) < single_fill_target:
                combo = next(fill_cycle)
                variant_idx = int(combo["variant_idx"])
                payload = str(combo["payload"])
                urls = endpoint_urls("fill_single", 1, semantic=bool(combo.get("semantic_urls")))
                msg = EXFIL_VARIANTS[variant_idx](urls, payload)
                if add_fill(
                    (msg,),
                    f"fill_exfil_single:{EXFIL_VARIANT_NAMES[variant_idx]}",
                    "bounded_fill_single",
                    priority=90.0,
                ):
                    continue
                break

            while len(findings) < chain2_target:
                combo = next(fill_cycle)
                payload = str(combo["payload"])
                maker = semantic_host if bool(combo.get("semantic_urls")) else host
                chain = _make_exfil_chain(maker, payload, 2, "chain2")
                if add_fill(
                    chain,
                    "fill_exfil_chain2",
                    "bounded_fill_chain",
                    priority=96.0,
                ):
                    continue
                break

            while len(findings) < target_n:
                combo = next(fill_cycle)
                payload = str(combo["payload"])
                maker = semantic_host if bool(combo.get("semantic_urls")) else host
                chain = _make_exfil_chain(maker, payload, 3, "chain3")
                if add_fill(
                    chain,
                    "fill_exfil_chain3",
                    "bounded_fill_chain",
                    priority=102.0,
                ):
                    continue
                break
        else:
            while len(findings) < target_n:
                combo = next(fill_cycle)
                variant_idx = int(combo["variant_idx"])
                endpoint_count = int(combo["endpoint_count"])
                payload = str(combo["payload"])
                urls = endpoint_urls("fill", endpoint_count, semantic=bool(combo.get("semantic_urls")))
                msg = EXFIL_VARIANTS[variant_idx](urls, payload)
                if add_fill(
                    (msg,),
                    f"fill_exfil_multi:{EXFIL_VARIANT_NAMES[variant_idx]}",
                    "bounded_fill",
                    priority=90.0 + endpoint_count,
                ):
                    continue
                break

        deputy_idx = 0
        while len(findings) < target_n:
            msg = DEPUTY_VARIANTS[deputy_idx % len(DEPUTY_VARIANTS)](addr())
            if not add_fill((msg,), "fill_confused_deputy", "bounded_fill", priority=25.0):
                break
            deputy_idx += 1

        return self._finalize_selection(findings, target_n, max_hops)
