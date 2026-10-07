#!/usr/bin/env python3
"""Predeclared CPU-only evidence driver for TDSC-01."""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable

import cryptography

from contextmark.bounds import (
    PrimitiveRates,
    closed_form_union,
    enumerate_union_probability,
    independent_model,
    query_caps,
    theorem_bound,
)
from contextmark.calibration import coverage_grid, equal_marginal_history_counterexample
from contextmark.campaigns import (
    mutation_campaign,
    negative_control,
    resume_continuity_audit,
    terminal_failure_audit,
    threshold_audit,
)
from contextmark.compiler import ContextMarkCompiler, make_demo_program
from contextmark.assurance_checks import assurance_checks
from contextmark.finite_model import (
    baseline_matrix,
    omission_matrix,
    safeguard_lattice,
    validate_omission_matrix,
    validate_safeguard_lattice,
)
import contextmark.threshold_backend as threshold_backend
from contextmark.threshold_backend import (
    ThresholdCarrierAdapter,
    binder as threshold_binder,
    read as threshold_read,
    read_candidates,
)

ROOT = Path(__file__).resolve().parent
OUTPUT = ROOT / "reproduced"
RAW = OUTPUT / "raw"
DERIVED = OUTPUT / "derived"
SEED = 20260718
GAMES = ("removal", "nontransfer", "unforgeability", "collusion")
EXPECTED_TESTS = 107


def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str] | None = None) -> None:
    rows = list(rows)
    if fieldnames is None:
        if not rows:
            raise ValueError("cannot infer fields from empty rows")
        fieldnames = list(rows[0])
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("empty sample")
    index = max(0, min(len(ordered) - 1, int((len(ordered) * fraction + 0.999999999)) - 1))
    return ordered[index]


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def run_tests() -> dict[str, Any]:
    command = [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-v"]
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env={**os.environ, "PYTHONPATH": str(ROOT) + os.pathsep + os.environ.get("PYTHONPATH", ""),
             "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUTF8": "1"},
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    output = completed.stdout + completed.stderr
    (RAW / "test-output.txt").write_text(output, encoding="utf-8")
    marker = f"Ran {EXPECTED_TESTS} tests"
    valid = completed.returncode == 0 and marker in output and output.rstrip().endswith("OK")
    summary = {
        "command": "PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python -m unittest discover -s tests -v",
        "deterministic_test_count": EXPECTED_TESTS,
        "passed": EXPECTED_TESTS if valid else 0,
        "failed": 0 if valid else 1,
        "returncode": completed.returncode,
        "valid": valid,
    }
    write_json(RAW / "test-summary.json", summary)
    if not valid:
        raise RuntimeError("unit test contract failed")
    return summary


def environment_record() -> dict[str, Any]:
    cpu_model = "unknown"
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.lower().startswith("model name"):
                cpu_model = line.split(":", 1)[1].strip()
                break
    return {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "seed": SEED,
        "python": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "cryptography": cryptography.__version__,
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_model": cpu_model,
        "logical_cpu_count": os.cpu_count(),
        "gpu_used": False,
        "model_api_used": False,
        "learned_model_used": False,
        "private_data_used": False,
        "human_evidence_used": False,
    }


def run_structural_campaigns() -> dict[str, Any]:
    mutations = mutation_campaign()
    write_csv(RAW / "mutation-campaign.csv", mutations)
    mutation_summary = {
        "case_count": len(mutations),
        "record_field_cases": sum(row["group"] == "record_field" for row in mutations),
        "chain_language_cases": sum(row["group"] == "chain_language" for row in mutations),
        "artifact_cases": sum(row["group"] == "artifact" for row in mutations),
        "rejected": sum(row["rejected"] for row in mutations),
        "valid": len(mutations) == 47 and all(row["rejected"] for row in mutations),
    }
    write_json(RAW / "mutation-campaign-summary.json", mutation_summary)

    omission = omission_matrix()
    omission_summary = validate_omission_matrix(omission)
    write_csv(RAW / "finite-attack-harness.csv", omission)
    write_json(RAW / "finite-attack-harness-summary.json", omission_summary)

    lattice = safeguard_lattice()
    lattice_summary = validate_safeguard_lattice(lattice)
    write_csv(RAW / "safeguard-lattice.csv", lattice)
    write_json(RAW / "safeguard-lattice-summary.json", lattice_summary)

    baselines = baseline_matrix()
    write_csv(RAW / "architecture-baselines.csv", baselines)
    baseline_counts = {
        name: sum(row["attack_succeeds"] for row in baselines if row["configuration"] == name)
        for name in ("detached_records", "host_bound_owner_mark", "signed_owner_mark", "context_mark_without_parents", "complete")
    }
    write_json(RAW / "architecture-baseline-summary.json", {
        "schema": "factorized-architecture-truth-table-v1",
        "evidence_kind": "truth_table_consistency",
        "shared_rule": "REQUIRED",
        "independent_interaction_evidence": False,
        "successful_attack_counts": baseline_counts,
        "limitation": "The five rows are named configurations of the same six-Boolean evaluator, not independent mechanism executions.",
    })

    threshold = threshold_audit()
    deletion_rows = threshold.pop("deletion_rows")
    mutation_rows = threshold.pop("single_mutation_rows")
    shared_key_rows = threshold.pop("shared_key_rows")
    coalition_rows = threshold.pop("coalition_rows")
    gamma = threshold.pop("gamma")
    write_csv(RAW / "threshold-deletion-authorization.csv", deletion_rows)
    write_csv(RAW / "threshold-single-mutations.csv", mutation_rows)
    write_csv(RAW / "threshold-shared-key-candidate-cells.csv", shared_key_rows)
    write_csv(RAW / "threshold-coalition-cells.csv", coalition_rows)
    write_json(RAW / "threshold-compiled-gamma.json", {
        "schema": "contextmark-compiled-coalition-gamma-v1",
        "entries": gamma,
        "trace_rule": threshold["trace_contract"],
    })
    write_json(RAW / "threshold-audit-summary.json", threshold)

    terminal = terminal_failure_audit()
    resume = resume_continuity_audit()
    negative = negative_control()
    write_json(RAW / "terminal-failure-registry-audit.json", terminal)
    write_json(RAW / "resume-registry-continuity-audit.json", resume)
    write_json(RAW / "negative-control-envelope-deletion.json", negative)

    if not (mutation_summary["valid"] and omission_summary["valid"] and lattice_summary["valid"] and threshold["passed"] and terminal["passed"] and resume["passed"] and negative["attack_succeeds"]):
        raise RuntimeError("structural campaign failed")
    return {
        "mutation_campaign": mutation_summary,
        "finite_attack_harness": omission_summary,
        "safeguard_lattice": lattice_summary,
        "architecture_baseline_success_counts": baseline_counts,
        "threshold_audit": threshold,
        "terminal_failure_registry": terminal,
        "resume_registry_continuity": resume,
        "negative_control": negative,
    }


def run_exact_probability_checks() -> list[dict[str, Any]]:
    rows = []
    for event_count in (4, 8, 12, 16, 20):
        probabilities = [1e-6 * (index + 1) for index in range(event_count)]
        enumerated, states, elapsed_ms = enumerate_union_probability(probabilities)
        closed = closed_form_union(probabilities)
        rows.append({
            "event_count": event_count,
            "states_enumerated": states,
            "enumerated_probability": f"{enumerated:.18g}",
            "closed_form_probability": f"{closed:.18g}",
            "absolute_error": f"{abs(enumerated - closed):.18g}",
            "elapsed_ms": f"{elapsed_ms:.6f}",
        })
    write_csv(RAW / "exact-probability-checks.csv", rows)
    if int(rows[-1]["states_enumerated"]) != 1_048_576 or max(float(row["absolute_error"]) for row in rows) > 1e-12:
        raise RuntimeError("exact probability check failed")
    return rows


def run_calibration_checks() -> dict[str, Any]:
    rows = coverage_grid((index / 100 for index in range(1, 100)), horizon=64, alpha=0.05)
    write_csv(DERIVED / "optional-stopping-coverage.csv", rows)
    fixed_max = max(rows, key=lambda row: row["fixed_level_noncoverage"])
    anytime_max = max(rows, key=lambda row: row["anytime_noncoverage"])
    counterexample = equal_marginal_history_counterexample()
    write_json(RAW / "equal-marginal-history-counterexample.json", counterexample)
    summary = {
        "horizon": 64,
        "family_alpha": 0.05,
        "grid_points": len(rows),
        "fixed_level_max_noncoverage": fixed_max["fixed_level_noncoverage"],
        "fixed_level_argmax_probability": fixed_max["true_probability"],
        "anytime_max_noncoverage": anytime_max["anytime_noncoverage"],
        "anytime_argmax_probability": anytime_max["true_probability"],
        "analytic_anytime_upper_bound": 0.05,
        "equal_marginal_counterexample": counterexample,
        "valid": fixed_max["fixed_level_noncoverage"] > 0.1 and anytime_max["anytime_noncoverage"] <= 0.05 + 1e-12,
    }
    write_json(RAW / "optional-stopping-summary.json", summary)
    if not summary["valid"]:
        raise RuntimeError("calibration audit failed")
    return summary


def run_bound_curves() -> dict[str, Any]:
    rates = PrimitiveRates()
    q_values = (1, 2, 4, 8, 16, 32, 64, 128, 256)
    rows = []
    for game in GAMES:
        game_rows = []
        for q in q_values:
            n = 4 * q
            theorem = theorem_bound(game, q, n, rates)
            independent = independent_model(game, q, n, rates)
            if theorem + 1e-15 < independent:
                raise RuntimeError("bound curve is not conservative")
            row = {
                "game": game,
                "queries": q,
                "records": n,
                "theorem_bound": theorem,
                "independent_model": independent,
            }
            game_rows.append(row)
            rows.append(row)
        write_csv(DERIVED / f"security-{game}.csv", game_rows)
    caps = query_caps(4.0, 0.01, rates)
    inputs = {
        "rates": rates.as_dict(),
        "records_per_context": 4.0,
        "target_probability": 0.01,
        "integer_query_caps": caps,
    }
    write_json(RAW / "bound-inputs-and-caps.json", inputs)
    write_csv(DERIVED / "query-caps.csv", [{"game": game, "integer_query_cap": value} for game, value in caps.items()])
    return inputs


def build_session_chain(chain_length: int, sample: int):
    actors = ["builder", "reviewer", "packager", "release"]
    compiler = ContextMarkCompiler.deterministic(actors, seed=SEED, chain_id=f"session-{chain_length}-{sample}")
    session = compiler.begin_session(make_demo_program(16))
    total_started = time.perf_counter_ns()
    append_started = total_started
    for index in range(chain_length):
        session.append_private(
            actor=actors[index % len(actors)],
            operation=f"stage-{index}",
            metadata={"issue_id": f"s-{chain_length}-{sample}-{index}", "policy": "v1"},
        )
    append_us = (time.perf_counter_ns() - append_started) / 1000
    export_started = time.perf_counter_ns()
    chain, artifact = session.snapshot()
    export_us = (time.perf_counter_ns() - export_started) / 1000
    end_to_end_us = (time.perf_counter_ns() - total_started) / 1000
    return compiler, chain, artifact, {
        "append_only_us": append_us,
        "snapshot_export_us": export_us,
        "end_to_end_us": end_to_end_us,
    }


def build_replay_chain(chain_length: int, sample: int):
    actors = ["builder", "reviewer", "packager", "release"]
    compiler = ContextMarkCompiler.deterministic(actors, seed=SEED, chain_id=f"replay-{chain_length}-{sample}")
    chain: list[dict[str, Any]] = []
    artifact = make_demo_program(16)
    started = time.perf_counter_ns()
    for index in range(chain_length):
        chain, artifact = compiler.issue(
            chain,
            artifact,
            actor=actors[index % len(actors)],
            operation=f"stage-{index}",
            metadata={"issue_id": f"r-{chain_length}-{sample}-{index}", "policy": "v1"},
        )
    elapsed_us = (time.perf_counter_ns() - started) / 1000
    return compiler, chain, artifact, elapsed_us


BENCHMARK_DEPTHS = (1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2048)


def run_compiler_benchmark_depth(length: int) -> dict[str, Any]:
    """Measure one frozen chain depth in an isolated process invocation.

    Every session sample is timed through one exported full chain and tip
    artifact.  Append-only and final-export components are retained separately.
    Each one of the 31 session exports and, where applicable, all seven replay
    exports is verified once outside its construction interval.
    """
    if length not in BENCHMARK_DEPTHS:
        raise ValueError(f"unregistered benchmark depth: {length}")
    session_total: list[float] = []
    session_append: list[float] = []
    session_export: list[float] = []
    session_per_stage: list[float] = []
    verify: list[float] = []
    serialize: list[float] = []
    manifest_sizes: list[int] = []
    artifact_sizes: list[int] = []
    samples: list[dict[str, Any]] = []
    session_verified = 0
    for sample in range(31):
        compiler, chain, artifact, timing = build_session_chain(length, sample)
        elapsed_us = float(timing["end_to_end_us"])
        session_total.append(elapsed_us)
        session_append.append(float(timing["append_only_us"]))
        session_export.append(float(timing["snapshot_export_us"]))
        session_per_stage.append(elapsed_us / length)
        samples.extend([
            {"chain_length": length, "sample_kind": "validated_tip_end_to_end", "sample_index": sample, "elapsed_us": elapsed_us},
            {"chain_length": length, "sample_kind": "validated_tip_append_only", "sample_index": sample, "elapsed_us": timing["append_only_us"]},
            {"chain_length": length, "sample_kind": "validated_tip_snapshot_export", "sample_index": sample, "elapsed_us": timing["snapshot_export_us"]},
        ])
        started = time.perf_counter_ns()
        accepted = compiler.verify(chain, artifact)
        verify_elapsed = (time.perf_counter_ns() - started) / 1000
        if not accepted:
            raise RuntimeError(f"session export failed verification at depth={length}, sample={sample}")
        session_verified += 1
        verify.append(verify_elapsed)
        samples.append({"chain_length": length, "sample_kind": "verify_distinct_session_export", "sample_index": sample, "elapsed_us": verify_elapsed})
        started = time.perf_counter_ns()
        manifest = compiler.serialize_manifest(chain)
        serialize_elapsed = (time.perf_counter_ns() - started) / 1000
        serialize.append(serialize_elapsed)
        manifest_sizes.append(len(manifest))
        artifact_sizes.append(len(compiler.serialize_artifact(artifact)))
        samples.append({"chain_length": length, "sample_kind": "serialize_distinct_session_export", "sample_index": sample, "elapsed_us": serialize_elapsed})

    replay_total: list[float] = []
    replay_verified = 0
    if length <= 256:
        for sample in range(7):
            compiler, chain, artifact, elapsed_us = build_replay_chain(length, sample)
            replay_total.append(elapsed_us)
            samples.append({"chain_length": length, "sample_kind": "full_prefix_replay_end_to_end", "sample_index": sample, "elapsed_us": elapsed_us})
            if not compiler.verify(chain, artifact):
                raise RuntimeError(f"replay export failed verification at depth={length}, sample={sample}")
            replay_verified += 1

    if session_verified != 31 or (length <= 256 and replay_verified != 7):
        raise RuntimeError("not every exported construction was verified")
    row = {
        "chain_length": length,
        "construction_boundary": "end-to-end construction through one exported full chain and tip artifact",
        "session_samples": len(session_total),
        "session_exports_verified": session_verified,
        "median_validated_tip_total_us": statistics.median(session_total),
        "p95_validated_tip_total_us": percentile(session_total, 0.95),
        "median_validated_tip_append_only_us": statistics.median(session_append),
        "p95_validated_tip_append_only_us": percentile(session_append, 0.95),
        "median_validated_tip_snapshot_export_us": statistics.median(session_export),
        "p95_validated_tip_snapshot_export_us": percentile(session_export, 0.95),
        "median_validated_tip_us_per_stage": statistics.median(session_per_stage),
        "replay_samples": len(replay_total),
        "replay_exports_verified": replay_verified,
        "median_replay_total_us": statistics.median(replay_total) if replay_total else "",
        "p95_replay_total_us": percentile(replay_total, 0.95) if replay_total else "",
        "replay_to_tip_speedup": (statistics.median(replay_total) / statistics.median(session_total)) if replay_total else "",
        "verify_samples": len(verify),
        "verify_sample_definition": "one verification for each distinct session export",
        "median_verify_us": statistics.median(verify),
        "p95_verify_us": percentile(verify, 0.95),
        "serialize_samples": len(serialize),
        "serialize_sample_definition": "one serialization for each distinct session export",
        "median_serialize_us": statistics.median(serialize),
        "p95_serialize_us": percentile(serialize, 0.95),
        "manifest_bytes": int(statistics.median(manifest_sizes)),
        "manifest_bytes_min": min(manifest_sizes),
        "manifest_bytes_max": max(manifest_sizes),
        "artifact_bytes": int(statistics.median(artifact_sizes)),
        "artifact_bytes_min": min(artifact_sizes),
        "artifact_bytes_max": max(artifact_sizes),
        "all_verifications_passed": True,
    }
    shard = {
        "schema": "contextmark-compiler-benchmark-shard-v2",
        "depth": length,
        "frozen_plan": {
            "session_samples": 31,
            "replay_samples": 7 if length <= 256 else 0,
            "verify_samples": 31,
            "serialize_samples": 31,
            "construction_boundary": row["construction_boundary"],
            "verification_outside_construction_timing": True,
        },
        "row": row,
        "samples": samples,
    }
    write_json(RAW / "benchmark-shards" / f"depth-{length}.json", shard)
    return shard


def aggregate_compiler_benchmark() -> list[dict[str, Any]]:
    aggregate: list[dict[str, Any]] = []
    samples: list[dict[str, Any]] = []
    for length in BENCHMARK_DEPTHS:
        path = RAW / "benchmark-shards" / f"depth-{length}.json"
        if not path.exists():
            raise RuntimeError(f"missing frozen benchmark shard: {path.relative_to(ROOT)}")
        shard = json.loads(path.read_text(encoding="utf-8"))
        if shard.get("schema") != "contextmark-compiler-benchmark-shard-v2" or int(shard.get("depth", -1)) != length:
            raise RuntimeError(f"invalid benchmark shard: {path.relative_to(ROOT)}")
        row = shard["row"]
        if row.get("session_exports_verified") != 31 or row.get("verify_samples") != 31:
            raise RuntimeError(f"incomplete session verification evidence at depth {length}")
        if length <= 256 and row.get("replay_exports_verified") != 7:
            raise RuntimeError(f"incomplete replay verification evidence at depth {length}")
        aggregate.append(row)
        samples.extend(shard["samples"])
    write_csv(RAW / "compiler-scaling-samples.csv", samples)
    write_csv(DERIVED / "compiler-scaling.csv", aggregate)
    write_csv(DERIVED / "compiler-replay-scaling.csv", [row for row in aggregate if row["replay_samples"]])
    return aggregate


def run_threshold_timing() -> list[dict[str, Any]]:
    rows = []
    samples = []
    base = make_demo_program(16)
    for groups in (1, 2, 3):
        mark_times: list[float] = []
        read_times: list[float] = []
        for sample in range(31):
            key = hashlib.sha256(f"timing-key-{groups}-{sample}".encode()).digest()
            payloads = [
                hashlib.sha256(f"timing-payload-{groups}-{sample}-{group}".encode()).digest()
                for group in range(groups)
            ]
            artifact = base
            started = time.perf_counter_ns()
            for payload in payloads:
                artifact = threshold_backend.mark(key, artifact, payload, n=5, t=3)
            mark_us = (time.perf_counter_ns() - started) / 1000
            started = time.perf_counter_ns()
            selected = threshold_read(key, artifact)
            read_us = (time.perf_counter_ns() - started) / 1000
            candidates = read_candidates(key, artifact)
            expected_selected = min(
                ((threshold_backend.payload_commitment(payload), payload) for payload in payloads),
                key=lambda item: item[0],
            )[1]
            if {payload for _commitment, payload in candidates} != set(payloads):
                raise RuntimeError("threshold timing candidate set mismatch")
            if selected != expected_selected:
                raise RuntimeError("threshold timing canonical read mismatch")
            mark_times.append(mark_us)
            read_times.append(read_us)
            samples.append({
                "payload_groups": groups,
                "sample_index": sample,
                "mark_total_us": mark_us,
                "read_us": read_us,
                "candidate_count": len(candidates),
                "selected_payload": selected.hex(),
                "expected_selected_payload": expected_selected.hex(),
                "passed": True,
            })
        rows.append({
            "payload_groups": groups,
            "samples": 31,
            "median_mark_total_us": statistics.median(mark_times),
            "p95_mark_total_us": percentile(mark_times, 0.95),
            "median_read_us": statistics.median(read_times),
            "p95_read_us": percentile(read_times, 0.95),
            "all_candidate_sets_and_canonical_reads_passed": True,
        })
    write_csv(RAW / "threshold-carrier-timing-samples.csv", samples)
    write_csv(DERIVED / "threshold-carrier-timing.csv", rows)
    return rows


def _subset_reader(key: bytes, artifact: dict[str, Any]) -> bytes | None:
    """Exhaustive all-subset baseline for one authenticated payload group."""
    carriers = threshold_backend._valid_carriers(key, artifact)
    groups: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
    for carrier in carriers:
        groups.setdefault((carrier["commitment"], carrier["n"], carrier["t"]), []).append(carrier)
    candidates: list[tuple[str, bytes]] = []
    for (commitment, _n, threshold), members in groups.items():
        members.sort(key=lambda carrier: carrier["index"])
        if len(members) < threshold:
            continue
        expected_secret = None
        consistent = True
        points = [(carrier["index"], int(carrier["value"], 16)) for carrier in members]
        for subset in combinations(points, threshold):
            secret = threshold_backend._interpolate(list(subset))
            if expected_secret is None:
                expected_secret = secret
            elif secret != expected_secret:
                consistent = False
                break
        if not consistent or expected_secret is None or expected_secret >= 1 << 256:
            continue
        payload = expected_secret.to_bytes(32, "big")
        if threshold_backend.payload_commitment(payload) == commitment:
            candidates.append((commitment, payload))
    candidates.sort(key=lambda item: item[0])
    return candidates[0][1] if candidates else None


def run_residual_subset_timing() -> list[dict[str, Any]]:
    rows = []
    samples = []
    base = make_demo_program(8)
    for n, threshold in ((5, 3), (10, 5), (32, 16)):
        residual_times: list[float] = []
        subset_times: list[float] = []
        for sample in range(31):
            key = hashlib.sha256(f"residual-key-{n}-{threshold}-{sample}".encode()).digest()
            payload = hashlib.sha256(f"residual-payload-{n}-{threshold}-{sample}".encode()).digest()
            artifact = threshold_backend.mark(key, base, payload, n=n, t=threshold)
            started = time.perf_counter_ns()
            residual = threshold_read(key, artifact)
            residual_us = (time.perf_counter_ns() - started) / 1000
            if residual != payload:
                raise RuntimeError("residual reader timing produced a wrong payload")
            subset_us: float | str = ""
            subset_status = "not_run_declared_combinatorial_boundary"
            if (n, threshold) != (32, 16):
                started = time.perf_counter_ns()
                subset = _subset_reader(key, artifact)
                subset_us = (time.perf_counter_ns() - started) / 1000
                if subset != payload:
                    raise RuntimeError("subset baseline timing produced a wrong payload")
                subset_times.append(float(subset_us))
                subset_status = "measured"
            residual_times.append(residual_us)
            samples.append({
                "n": n,
                "t": threshold,
                "sample_index": sample,
                "legacy_subsets": __import__("math").comb(n, threshold),
                "residual_read_us": residual_us,
                "subset_read_us": subset_us,
                "subset_status": subset_status,
                "residual_payload_correct": True,
                "subset_payload_correct": True if subset_status == "measured" else "",
            })
        rows.append({
            "n": n,
            "t": threshold,
            "samples": 31,
            "legacy_subsets": __import__("math").comb(n, threshold),
            "residual_points": n - threshold,
            "residual_read_median_us": statistics.median(residual_times),
            "residual_read_p95_us": percentile(residual_times, 0.95),
            "subset_read_median_us": statistics.median(subset_times) if subset_times else "",
            "subset_read_p95_us": percentile(subset_times, 0.95) if subset_times else "",
            "subset_timing_status": "measured" if subset_times else "not_run_declared_combinatorial_boundary",
        })
    write_csv(RAW / "residual-subset-timing-samples.csv", samples)
    write_csv(DERIVED / "residual-subset-timing.csv", rows)
    return rows


def build_run_manifest() -> dict[str, Any]:
    manifest_path = RAW / "run-manifest.json"
    paths = [ROOT / "requirements.txt", ROOT / "run_experiments.py", ROOT / "run_experiments_sharded.sh"]
    paths.extend((ROOT / "contextmark").glob("*.py"))
    paths.extend((ROOT / "tests").glob("*.py"))
    paths.extend(path for path in OUTPUT.rglob("*") if path.is_file() and path != manifest_path)
    entries = []
    for path in sorted(set(paths), key=lambda p: p.as_posix()):
        base = OUTPUT if path.is_relative_to(OUTPUT) else ROOT
        entries.append({
            "base": "output" if base == OUTPUT else "artifact",
            "path": path.relative_to(base).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256_file(path),
        })
    manifest = {
        "schema": "contextmark-run-manifest-v2",
        "seed": SEED,
        "command": "PYTHONDONTWRITEBYTECODE=1 PYTHONUTF8=1 sh run_experiments_sharded.sh OUTPUT",
        "entry_count": len(entries),
        "entries": entries,
    }
    write_json(manifest_path, manifest)
    return manifest


def prepare_experiments() -> dict[str, Any]:
    if OUTPUT.exists() and any(OUTPUT.iterdir()):
        raise RuntimeError("output must be absent or empty; retained evidence is never deleted")
    for directory in (RAW, DERIVED):
        directory.mkdir(parents=True, exist_ok=True)
    environment = environment_record()
    write_json(RAW / "environment.json", environment)
    tests = run_tests()
    structural = run_structural_campaigns()
    exact = run_exact_probability_checks()
    calibration = run_calibration_checks()
    assurance = assurance_checks()
    if not assurance["passed"]:
        raise RuntimeError("assurance regression campaign failed")
    write_json(RAW / "proof-implementation-checks.json", assurance)
    bounds = run_bound_curves()
    prepared = {
        "schema": "contextmark-prepared-evidence-v2",
        "environment": environment,
        "tests": tests,
        "structural_campaigns": structural,
        "exact_probability_max_error": max(float(row["absolute_error"]) for row in exact),
        "exact_probability_m20_elapsed_ms": float(exact[-1]["elapsed_ms"]),
        "calibration": calibration,
        "query_caps": bounds["integer_query_caps"],
        "assurance_checks": {k: v for k, v in assurance.items() if k not in {"closure_rows", "threshold_parameter_pairs"}},
        "benchmark_depths": list(BENCHMARK_DEPTHS),
    }
    write_json(RAW / "prepared-summary.json", prepared)
    return prepared


def finalize_experiments() -> dict[str, Any]:
    prepared_path = RAW / "prepared-summary.json"
    if not prepared_path.exists():
        raise RuntimeError("prepare step has not been executed")
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    scaling = aggregate_compiler_benchmark()
    threshold_timing = run_threshold_timing()
    residual_subset_timing = run_residual_subset_timing()
    summary = {
        "schema": "contextmark-experiment-summary-v2",
        "environment": prepared["environment"],
        "tests": prepared["tests"],
        "structural_campaigns": prepared["structural_campaigns"],
        "exact_probability_max_error": prepared["exact_probability_max_error"],
        "exact_probability_m20_elapsed_ms": prepared["exact_probability_m20_elapsed_ms"],
        "calibration": prepared["calibration"],
        "query_caps": prepared["query_caps"],
        "compiler_scaling": scaling,
        "threshold_timing": threshold_timing,
        "residual_subset_timing": residual_subset_timing,
        "assurance_checks": prepared["assurance_checks"],
    }
    write_json(RAW / "run-summary.json", summary)
    manifest = build_run_manifest()
    print(json.dumps(summary, indent=2, sort_keys=True))
    print(f"run_manifest_entries={manifest['entry_count']}")
    return summary


def main() -> int:
    prepare_experiments()
    for depth in BENCHMARK_DEPTHS:
        print(f"benchmark depth={depth}", flush=True)
        run_compiler_benchmark_depth(depth)
    finalize_experiments()
    return 0


def dispatch() -> int:
    global OUTPUT, RAW, DERIVED
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=OUTPUT, help="fresh output directory (default: reproduced)")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--prepare", action="store_true")
    mode.add_argument("--benchmark-depth", type=int)
    mode.add_argument("--finalize", action="store_true")
    args = parser.parse_args()
    OUTPUT = args.out.expanduser().resolve()
    if OUTPUT == ROOT or OUTPUT in ROOT.parents or OUTPUT == ROOT / "results" or (ROOT / "results") in OUTPUT.parents:
        raise RuntimeError("output cannot be the source tree, its ancestor, or retained historical results")
    RAW, DERIVED = OUTPUT / "raw", OUTPUT / "derived"
    if not args.prepare and args.benchmark_depth is None and not args.finalize:
        return main()
    if args.prepare:
        prepare_experiments()
        return 0
    if args.benchmark_depth is not None:
        depth = args.benchmark_depth
        shard = run_compiler_benchmark_depth(depth)
        print(json.dumps({"depth": depth, "row": shard["row"]}, indent=2, sort_keys=True))
        return 0
    if args.finalize:
        finalize_experiments()
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(dispatch())
