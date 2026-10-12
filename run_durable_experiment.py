"""Bounded local durability validation and same-information persistence cost.

No archived campaigns, remote services, production watermark, or power-cut test.
The ordinary durable-state path stores identical prevalidated attempt/terminal
bytes using the same authentication and synchronization settings. Its timed
boundary excludes preparing/signing/marking those bytes, so it is a persistence
reference, not an end-to-end competing provenance mechanism.
"""
from __future__ import annotations

import argparse
from copy import deepcopy
import csv
from datetime import datetime, timezone
import importlib.metadata
import io
import json
import math
import os
from pathlib import Path
import platform
import sqlite3
import statistics
import sys
import tempfile
import time
import unittest

from contextmark.canonical import canonical_bytes
from contextmark.compiler import ContextMarkCompiler, make_demo_program
from contextmark.durable_registry import DurableRegistry

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "tests"))
from owned_durable_fixture import OwnedStubBackend, WORK_ROOT

DEPTHS = (1, 8, 32)
SAMPLES = 11
WARMUPS = 2


def fresh_compiler(path=None):
    return ContextMarkCompiler.deterministic(["builder"], seed=29, chain_id="durable-cost",
        backend=OwnedStubBackend(), registry_path=str(path) if path is not None else None)


def append_work(session, depth, sample):
    for i in range(depth):
        session.append_private(actor="builder", operation="owned-stage",
                               metadata={"stage": i, "sample": sample})


def corpus(depth, sample):
    with fresh_compiler() as c:
        session = c.begin_session(make_demo_program(2))
        append_work(session, depth, sample)
        snapshot = c.export_registry_snapshot()
        entries = sorted(snapshot["entries"], key=lambda e: e["unsigned"]["index"])
        return deepcopy(entries), session.snapshot(), snapshot, c.master_key


def pending(entry):
    return {key: deepcopy(entry[key]) for key in
            ("request_id", "request_program_hex", "unsigned", "context")} | {"status": "pending"}


def full_path(path, depth, sample, expected_pair, expected_snapshot):
    with fresh_compiler(path) as c:
        session = c.begin_session(make_demo_program(2))
        start = time.perf_counter_ns()
        append_work(session, depth, sample)
        exported = session.snapshot()
        elapsed = (time.perf_counter_ns() - start) / 1e6
        if exported != expected_pair or c.export_registry_snapshot() != expected_snapshot or not c.verify(*exported):
            raise AssertionError("full path differs from matched corpus")
        settings = (c._durable.connection.execute("PRAGMA journal_mode").fetchone()[0],
                    c._durable.connection.execute("PRAGMA synchronous").fetchone()[0])
    start = time.perf_counter_ns()
    with fresh_compiler(path) as reopened:
        recovery = (time.perf_counter_ns() - start) / 1e6
        if reopened.export_registry_snapshot() != expected_snapshot:
            raise AssertionError("full reopen lost state")
        # Replay all successful requests with no new backend calls.
        for entry in expected_snapshot["entries"]:
            prefix = reopened._reconstruct_chain(entry["context"])[:-1]
            reopened.issue(prefix, json.loads(bytes.fromhex(entry["request_program_hex"])),
                           actor=entry["unsigned"]["actor"], operation=entry["unsigned"]["operation"],
                           metadata=entry["unsigned"]["metadata"])
        if reopened.backend.calls != 0:
            raise AssertionError("reopen resampled backend")
    return elapsed, recovery, settings


def ordinary_state_path(path, entries, key, expected_pair):
    # Same request, context, signed record, artifact, HMAC, unique indices, two
    # commits and SQLite settings. Preparing and validating the corpus is untimed.
    state = {}
    store = DurableRegistry(path, master_key=key, chain_id="durable-cost")
    try:
        start = time.perf_counter_ns()
        for entry in entries:
            reserved = pending(entry)
            store.write_entries([reserved], reserve=True)
            store.write_entries([entry])
            state[entry["context"]] = deepcopy(entry)
        ordered = sorted(state.values(), key=lambda e: e["unsigned"]["index"])
        exported = ([deepcopy(e["record"]) for e in ordered], deepcopy(ordered[-1]["artifact"]))
        elapsed = (time.perf_counter_ns() - start) / 1e6
        if exported != expected_pair:
            raise AssertionError("ordinary export differs")
        loaded = store.load_entries()
        if canonical_bytes(loaded) != canonical_bytes(sorted(entries, key=lambda e: e["request_id"])):
            raise AssertionError("ordinary state differs from full path")
    finally:
        store.close()
    start = time.perf_counter_ns()
    reopened = DurableRegistry(path, master_key=key, chain_id="durable-cost")
    try:
        load_ms = (time.perf_counter_ns() - start) / 1e6
        loaded = reopened.load_entries()
        if canonical_bytes(loaded) != canonical_bytes(sorted(entries, key=lambda e: e["request_id"])):
            raise AssertionError("ordinary reopen lost state")
    finally:
        reopened.close()
    return elapsed, load_ms


def validation():
    # Reviewed local durability tests plus existing owned restore/risk tests.
    # Do not discover the archived attack/mutation/campaign modules.
    suite = unittest.TestSuite()
    for name in ("test_durable_registry", "test_restore_membership",
                 "test_review_regressions.RegistryTranscriptRegression",
                 "test_review_regressions.RiskInputRegression"):
        suite.addTests(unittest.defaultTestLoader.loadTestsFromName(name))
    output = io.StringIO()
    started = time.perf_counter_ns()
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    return dict(tests=result.testsRun, failures=len(result.failures), errors=len(result.errors),
                skipped=len(result.skipped), passed=result.wasSuccessful(),
                elapsed_ms=(time.perf_counter_ns() - started) / 1e6), output.getvalue()


def p95(values):
    return sorted(values)[math.ceil(.95 * len(values)) - 1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--cpu-name", required=True, help="observed CPU name, not inferred")
    parser.add_argument("--filesystem", required=True, help="observed local filesystem description")
    args = parser.parse_args()
    out = args.out.resolve()
    if not out.is_relative_to((ROOT / "results").resolve()) or out == ROOT / "results":
        raise ValueError("output must be a new subdirectory under this candidate's results")
    out.mkdir(parents=True, exist_ok=False)
    protocol = dict(depths=DEPTHS, measured_samples=SAMPLES, warmups=WARMUPS,
                    program="make_demo_program(2)", seed=29,
                    order="alternating full/ordinary with sample parity; all samples retained",
                    issue_boundary="new private appends plus one final chain/artifact export; excludes database creation/open",
                    full_reopen_boundary="open, authenticate all rows, request/signature/binder/reader/ancestry validation",
                    ordinary_reopen_boundary="open and authenticate all rows, without compiler semantic validation",
                    ordinary_baseline="identical prevalidated pending/terminal bytes, same store; excludes preparation, signing and backend work",
                    failure_scope="abrupt child-process exits at call/commit boundaries; no power loss or live distributed service",
                    production_robustness_or_novelty_measured=False)
    (out / "protocol.json").write_text(json.dumps(protocol, indent=2) + "\n", encoding="utf-8")
    checks, log = validation()
    (out / "validation.txt").write_text(log, encoding="utf-8")
    (out / "validation.json").write_text(json.dumps(checks, indent=2) + "\n", encoding="utf-8")
    if not checks["passed"]:
        raise RuntimeError("owned validation failed; output retained")
    WORK_ROOT.mkdir(parents=True, exist_ok=True)
    rows = []
    with tempfile.TemporaryDirectory(prefix="cost-", dir=WORK_ROOT) as folder:
        root = Path(folder)
        for depth in DEPTHS:
            for sample in range(-WARMUPS, SAMPLES):
                entries, pair, snapshot, key = corpus(depth, sample)
                path = root / ("full-%d-%d.sqlite" % (depth, sample))
                baseline = root / ("ordinary-%d-%d.sqlite" % (depth, sample))
                if sample % 2:
                    ordinary_ms, ordinary_load = ordinary_state_path(baseline, entries, key, pair)
                    full_ms, recovery_ms, settings = full_path(path, depth, sample, pair, snapshot)
                else:
                    full_ms, recovery_ms, settings = full_path(path, depth, sample, pair, snapshot)
                    ordinary_ms, ordinary_load = ordinary_state_path(baseline, entries, key, pair)
                rows.append(dict(depth=depth, sample=sample, warmup=sample < 0,
                    full_issue_export_ms=full_ms, ordinary_state_export_ms=ordinary_ms,
                    full_reopen_ms=recovery_ms, ordinary_authenticated_open_ms=ordinary_load,
                    full_db_bytes=path.stat().st_size, ordinary_db_bytes=baseline.stat().st_size,
                    terminal_entry_bytes=sum(len(canonical_bytes(e)) for e in entries),
                    equal_terminal_bytes=True, all_retries_without_mark=True,
                    journal_mode=settings[0], synchronous=settings[1]))
                print("depth=%d sample=%d full=%.3f ordinary=%.3f" % (depth, sample, full_ms, ordinary_ms), flush=True)
    with (out / "samples.csv").open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)
    summary = []
    for depth in DEPTHS:
        selected = [r for r in rows if r["depth"] == depth and not r["warmup"]]
        result = dict(depth=depth, samples=len(selected))
        for metric in ("full_issue_export_ms", "ordinary_state_export_ms", "full_reopen_ms", "ordinary_authenticated_open_ms"):
            values = [r[metric] for r in selected]
            result[metric + "_median"] = statistics.median(values)
            result[metric + "_p95"] = p95(values)
        summary.append(result)
    environment = dict(timestamp_utc=datetime.now(timezone.utc).isoformat(),
        python=platform.python_version(), executable=sys.executable, platform=platform.platform(),
        machine=platform.machine(), cpu_name=args.cpu_name, logical_cpus=os.cpu_count(),
        cryptography=importlib.metadata.version("cryptography"), sqlite=sqlite3.sqlite_version,
        filesystem=args.filesystem,
        journal_mode="delete", synchronous=3, timer="perf_counter_ns", subprocesses="owned crash fixtures only")
    result = dict(schema="contextmark-durable-local-v1", environment=environment,
                  protocol=protocol, validation=checks, measured_pairs=33, warmup_pairs=6,
                  summaries=summary, all_terminal_entries_equal=True, all_reopens_and_retries_pass=True)
    (out / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
