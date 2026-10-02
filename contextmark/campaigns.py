"""Deterministic structural campaigns and finite witnesses."""
from __future__ import annotations

import hashlib
from copy import deepcopy
from itertools import product
from typing import Any

from .canonical import canonical_bytes, expression_binder
from .compiler import (
    AuthenticatedEnvelopeBackend,
    ContextMarkCompiler,
    ContextMarkError,
    MarkingError,
    make_demo_program,
)
from .threshold_backend import (
    CARRIER_FIELD,
    ThresholdCarrierAdapter,
    binder as threshold_binder,
    mark as threshold_mark,
    payload_commitment,
    public_authorized_derivative,
    read as threshold_read,
    read_candidates,
    trace_context_payloads,
)


def three_stage_fixture(*, backend=None, binder=expression_binder, chain_id: str = "campaign"):
    compiler = ContextMarkCompiler.deterministic(
        ["builder", "reviewer", "packager"],
        seed=20260718,
        chain_id=chain_id,
        backend=backend,
        binder=binder,
    )
    session = compiler.begin_session(make_demo_program(32))
    artifacts = []
    for index, actor in enumerate(("builder", "reviewer", "packager")):
        chain, artifact = session.append(
            actor=actor,
            operation=("compile", "review", "package")[index],
            metadata={"issue_id": f"c{index}", "policy": "v1"},
        )
        artifacts.append(deepcopy(artifact))
    return compiler, chain, artifact, artifacts


def _flip_hex(value: str) -> str:
    return ("0" if value[0] != "0" else "1") + value[1:]


def mutation_campaign() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    fields = ("version", "chain_id", "index", "parent", "binder", "actor", "operation", "metadata", "context", "signature")
    for position in range(3):
        for field in fields:
            compiler, chain, artifact, _ = three_stage_fixture(chain_id=f"mutation-record-{position}-{field}")
            candidate = deepcopy(chain)
            record = candidate[position]
            if field in {"version", "chain_id", "operation"}:
                record[field] = str(record[field]) + "-other"
            elif field == "index":
                record[field] = int(record[field]) + 4
            elif field == "parent":
                record[field] = "11" * 32
            elif field in {"binder", "context", "signature"}:
                record[field] = _flip_hex(str(record[field]))
            elif field == "actor":
                record[field] = "mallory"
            elif field == "metadata":
                record[field] = {**record[field], "changed": True}
            accepted = compiler.verify(candidate, artifact)
            rows.append({"case": f"record-{position}-{field}", "group": "record_field", "accepted": accepted, "rejected": not accepted})

    chain_cases = []
    compiler, chain, artifact, _ = three_stage_fixture(chain_id="mutation-chain")
    chain_cases.append(("empty", []))
    chain_cases.append(("truncated", deepcopy(chain[:-1])))
    chain_cases.append(("duplicate-tip", deepcopy(chain) + [deepcopy(chain[-1])]))
    chain_cases.append(("reordered", [deepcopy(chain[1]), deepcopy(chain[0]), deepcopy(chain[2])]))
    extra = deepcopy(chain); extra[1]["extra"] = True; chain_cases.append(("extra-field", extra))
    missing = deepcopy(chain); del missing[1]["operation"]; chain_cases.append(("missing-field", missing))
    nonrecord = [deepcopy(chain[0]), "not-a-record", deepcopy(chain[2])]; chain_cases.append(("nonrecord", nonrecord))
    for name, candidate in chain_cases:
        accepted = compiler.verify(candidate, artifact)
        rows.append({"case": name, "group": "chain_language", "accepted": accepted, "rejected": not accepted})

    artifact_cases: list[tuple[str, Any]] = []
    artifact_cases.append(("not-object", []))
    missing_env = deepcopy(artifact); missing_env.pop("_contextmark"); artifact_cases.append(("missing-envelope", missing_env))
    wrong_type = deepcopy(artifact); wrong_type["_contextmark"] = []; artifact_cases.append(("envelope-type", wrong_type))
    extra_env = deepcopy(artifact); extra_env["_contextmark"]["extra"] = True; artifact_cases.append(("envelope-extra", extra_env))
    missing_tag = deepcopy(artifact); del missing_tag["_contextmark"]["tag"]; artifact_cases.append(("envelope-missing-tag", missing_tag))
    wrong_backend = deepcopy(artifact); wrong_backend["_contextmark"]["backend"] = "other"; artifact_cases.append(("backend-version", wrong_backend))
    bad_payload = deepcopy(artifact); bad_payload["_contextmark"]["payload"] = "00"; artifact_cases.append(("payload-short", bad_payload))
    bad_tag = deepcopy(artifact); bad_tag["_contextmark"]["tag"] = _flip_hex(bad_tag["_contextmark"]["tag"]); artifact_cases.append(("tag-change", bad_tag))
    changed_host = deepcopy(artifact); changed_host["module"] = "other"; artifact_cases.append(("host-change", changed_host))
    transplant = make_demo_program(33); transplant["_contextmark"] = deepcopy(artifact["_contextmark"]); artifact_cases.append(("transplant", transplant))
    for name, candidate in artifact_cases:
        accepted = compiler.verify(chain, candidate)
        rows.append({"case": name, "group": "artifact", "accepted": accepted, "rejected": not accepted})

    if len(rows) != 47:
        raise AssertionError(f"mutation campaign size changed: {len(rows)}")
    return rows


def negative_control() -> dict[str, Any]:
    compiler, chain, artifact, _ = three_stage_fixture(chain_id="negative-control")
    deleted = deepcopy(artifact)
    before_binder = expression_binder(artifact)
    deleted.pop("_contextmark")
    return {
        "accepted_before": compiler.verify(chain, artifact),
        "accepted_after_deletion": compiler.verify(chain, deleted),
        "binder_equal": expression_binder(deleted) == before_binder,
        "attack_succeeds": not compiler.verify(chain, deleted),
    }


def coarse_binder_alias_witness() -> dict[str, Any]:
    def coarse(_program: dict[str, Any]) -> str:
        return "00" * 32

    compiler = ContextMarkCompiler.deterministic(
        ["builder"], seed=20260718, chain_id="coarse", binder=coarse, backend=AuthenticatedEnvelopeBackend(coarse)
    )
    compiler.issue([], {"program": "A"}, actor="builder", operation="compile", metadata={"issue_id": "same"})
    rejected = False
    try:
        compiler.issue([], {"program": "B"}, actor="builder", operation="compile", metadata={"issue_id": "same"})
    except ContextMarkError:
        rejected = True
    return {"same_binder_different_program_rejected": rejected, "status_counts": compiler.registry_status_counts()}


def terminal_failure_audit() -> dict[str, Any]:
    class FailingBackend:
        def __init__(self, fail: bool) -> None:
            self.fail = fail
            self.calls = 0
            self.delegate = AuthenticatedEnvelopeBackend(expression_binder)

        def mark(self, key: bytes, program: dict[str, Any], payload: str) -> dict[str, Any]:
            self.calls += 1
            if self.fail:
                raise RuntimeError("injected failure")
            return self.delegate.mark(key, program, payload)

        def read(self, key: bytes, artifact: dict[str, Any]) -> str | None:
            return self.delegate.read(key, artifact)

    failing = FailingBackend(True)
    compiler = ContextMarkCompiler.deterministic(
        ["builder"], seed=20260718, chain_id="terminal", backend=failing, max_contexts=1
    )
    request = dict(parent_chain=[], program=make_demo_program(8), actor="builder", operation="compile", metadata={"issue_id": "f0"})
    initial = retry = restored_retry = budget = False
    try:
        compiler.issue(**request)
    except MarkingError:
        initial = True
    calls_initial = failing.calls
    try:
        compiler.issue(**request)
    except MarkingError:
        retry = True
    calls_retry = failing.calls
    try:
        compiler.issue([], make_demo_program(9), actor="builder", operation="compile", metadata={"issue_id": "f1"})
    except ContextMarkError:
        budget = True
    snapshot = compiler.export_registry_snapshot()
    restored_backend = FailingBackend(False)
    restored = ContextMarkCompiler.deterministic(
        ["builder"], seed=20260718, chain_id="terminal", backend=restored_backend, max_contexts=1
    )
    restored.restore_registry_snapshot(snapshot)
    try:
        restored.issue(**request)
    except MarkingError:
        restored_retry = True
    return {
        "initial_failed": initial,
        "calls_after_initial": calls_initial,
        "retry_failed": retry,
        "calls_after_retry": calls_retry,
        "budget_rejected": budget,
        "restored_retry_failed": restored_retry,
        "restored_backend_calls": restored_backend.calls,
        "status_counts": restored.registry_status_counts(),
        "passed": initial and retry and budget and restored_retry and calls_initial == calls_retry == 1 and restored_backend.calls == 0,
    }


def resume_continuity_audit() -> dict[str, Any]:
    compiler = ContextMarkCompiler.deterministic(["builder", "packager"], seed=20260718, chain_id="resume")
    chain, artifact = compiler.issue([], make_demo_program(12), actor="builder", operation="compile", metadata={"issue_id": "r0"})
    snapshot = compiler.export_registry_snapshot()
    fresh = ContextMarkCompiler.deterministic(["builder", "packager"], seed=20260718, chain_id="resume")
    issue_rejected = resume_rejected = False
    try:
        fresh.issue(chain, artifact, actor="packager", operation="package", metadata={"issue_id": "r1"})
    except ContextMarkError:
        issue_rejected = True
    try:
        fresh.begin_session(chain=chain, artifact=artifact)
    except ContextMarkError:
        resume_rejected = True
    fresh.restore_registry_snapshot(snapshot)
    session = fresh.begin_session(chain=chain, artifact=artifact)
    chain2, artifact2 = session.append(actor="packager", operation="package", metadata={"issue_id": "r1"})
    return {
        "issue_without_registry_rejected": issue_rejected,
        "resume_without_registry_rejected": resume_rejected,
        "restored_continuation_accepted": fresh.verify(chain2, artifact2),
        "passed": issue_rejected and resume_rejected and fresh.verify(chain2, artifact2),
    }


def _candidate_selection_check(
    expected_payloads: list[bytes],
    actual_candidates: list[tuple[str, bytes]],
    selected_payload: bytes | None,
) -> dict[str, Any]:
    """Check candidate-set equality and the scalar reader's canonical choice."""
    expected = {payload_commitment(payload): payload for payload in expected_payloads}
    actual = {commitment: payload for commitment, payload in actual_candidates}
    expected_selected = expected[min(expected)] if expected else None
    return {
        "expected_payloads": [expected[key].hex() for key in sorted(expected)],
        "actual_payloads": [actual[key].hex() for key in sorted(actual)],
        "expected_selected": expected_selected.hex() if expected_selected is not None else "",
        "actual_selected": selected_payload.hex() if selected_payload is not None else "",
        "candidate_set_matches": actual == expected,
        "canonical_selection_matches": selected_payload == expected_selected,
        "passed": actual == expected and selected_payload == expected_selected,
    }


def _context_trace_check(
    expected_contexts: list[str],
    actual_contexts: list[str],
    selected_context: str | None,
) -> dict[str, Any]:
    expected = sorted(set(expected_contexts))
    actual = sorted(set(actual_contexts))
    expected_selected = expected[0] if expected else None
    return {
        "expected_contexts": ";".join(expected),
        "actual_contexts": ";".join(actual),
        "expected_selected": expected_selected or "",
        "actual_selected": selected_context or "",
        "trace_set_matches": actual == expected,
        "canonical_selection_matches": selected_context == expected_selected,
        "passed": actual == expected and selected_context == expected_selected,
    }


def _trace_signed_tip_contexts(
    compiler: ContextMarkCompiler,
    gamma: list[dict[str, Any]],
    candidate: dict[str, Any],
) -> list[str]:
    """Executable compiled trace predicate for a multi-context pattern Gamma."""
    pairs: list[tuple[str, bytes]] = []
    for entry in gamma:
        record = entry["record"]
        context = str(entry["context"])
        compiler.validate_chain([record])
        if record["context"] != context:
            raise ContextMarkError("Gamma record does not authenticate its declared tip")
        pairs.append((context, compiler.derive_watermark_key(context)))
    return trace_context_payloads(pairs, candidate)


def threshold_audit() -> dict[str, Any]:
    key = hashlib.sha256(b"threshold-audit-key").digest()
    base = make_demo_program(8)
    payloads = [hashlib.sha256(f"payload-{i}".encode()).digest() for i in range(3)]
    issued = threshold_mark(key, base, payloads[0], n=5, t=3)
    deletion_rows = []
    carriers = issued[CARRIER_FIELD]
    for bits in product((0, 1), repeat=5):
        candidate = deepcopy(issued)
        candidate[CARRIER_FIELD] = [deepcopy(carrier) for bit, carrier in zip(bits, carriers) if bit]
        recovered = threshold_read(key, candidate)
        expected = sum(bits) >= 3
        deletion_rows.append({
            "mask": "".join(map(str, bits)),
            "kept": sum(bits),
            "actual_payload": recovered.hex() if recovered is not None else "",
            "expected_payload": payloads[0].hex() if expected else "",
            "read_success": recovered == payloads[0],
            "expected_success": expected,
            "public_authorized": public_authorized_derivative(issued, candidate, threshold=3),
            "passed": (recovered == payloads[0]) == expected
            and public_authorized_derivative(issued, candidate, threshold=3) == expected,
        })

    # One changed field for each carrier and field family: 5 carriers x 5 mutations.
    mutation_rows = []
    for position in range(5):
        for field in ("tag", "value", "index", "commitment", "version"):
            candidate = deepcopy(issued)
            carrier = candidate[CARRIER_FIELD][position]
            if field in {"tag", "commitment"}:
                carrier[field] = _flip_hex(carrier[field])
            elif field == "value":
                carrier[field] = format(int(carrier[field], 16) + 1, "x")
            elif field == "index":
                carrier[field] = 99
            else:
                carrier[field] = "other"
            actual = threshold_read(key, candidate)
            mutation_rows.append({
                "position": position,
                "field": field,
                "actual_payload": actual.hex() if actual is not None else "",
                "expected_payload": payloads[0].hex(),
                "still_reads": actual == payloads[0],
                "passed": actual == payloads[0],
            })

    # Same-key/multi-payload semantics are a backend stress test, not the
    # compiler's default key schedule.  Candidate-set recovery and scalar
    # canonical selection are checked separately.
    shared_contributors = [threshold_mark(key, base, payload, n=4, t=3) for payload in payloads[:2]]
    shared_key_rows = []
    for masks in product(range(16), repeat=2):
        candidate = deepcopy(base)
        candidate[CARRIER_FIELD] = []
        expected_payloads: list[bytes] = []
        for group, mask in enumerate(masks):
            chosen = [
                carrier for index, carrier in enumerate(shared_contributors[group][CARRIER_FIELD])
                if mask & (1 << index)
            ]
            candidate[CARRIER_FIELD].extend(deepcopy(chosen))
            if len(chosen) >= 3:
                expected_payloads.append(payloads[group])
        check = _candidate_selection_check(
            expected_payloads,
            read_candidates(key, candidate),
            threshold_read(key, candidate),
        )
        shared_key_rows.append({
            "masks": ";".join(f"{mask:04b}" for mask in masks),
            **check,
        })

    # Actual compiler instantiation: each signed context d_j has its own
    # derived key k_j and exact tip payload d_j.  Gamma contains the signed
    # singleton records; Trace_Gamma returns precisely those contexts whose own
    # key recovers that signed payload from the mixed candidate.
    adapter = ThresholdCarrierAdapter(n=4, t=3)
    compiler = ContextMarkCompiler.deterministic(
        ["builder"],
        seed=20260718,
        chain_id="compiled-coalition-audit",
        binder=threshold_binder,
        backend=adapter,
    )
    gamma: list[dict[str, Any]] = []
    compiler_artifacts: list[dict[str, Any]] = []
    for group in range(3):
        chain, artifact = compiler.issue(
            [],
            base,
            actor="builder",
            operation="issue-copy",
            metadata={"issue_id": f"gamma-{group}", "group": group},
        )
        gamma.append({"context": chain[-1]["context"], "record": deepcopy(chain[-1])})
        compiler_artifacts.append(deepcopy(artifact))

    coalition_rows = []
    for contributor_count in (2, 3):
        for masks in product(range(16), repeat=contributor_count):
            candidate = deepcopy(base)
            candidate[CARRIER_FIELD] = []
            expected_contexts: list[str] = []
            for group, mask in enumerate(masks):
                chosen = [
                    carrier for index, carrier in enumerate(compiler_artifacts[group][CARRIER_FIELD])
                    if mask & (1 << index)
                ]
                candidate[CARRIER_FIELD].extend(deepcopy(chosen))
                if len(chosen) >= 3:
                    expected_contexts.append(gamma[group]["context"])
            actual_contexts = _trace_signed_tip_contexts(compiler, gamma[:contributor_count], candidate)
            actual_selected = actual_contexts[0] if actual_contexts else None
            check = _context_trace_check(expected_contexts, actual_contexts, actual_selected)
            coalition_rows.append({
                "contributor_count": contributor_count,
                "masks": ";".join(f"{mask:04b}" for mask in masks),
                **check,
            })

    gamma_summary = [
        {
            "context": entry["context"],
            "record_signature": entry["record"]["signature"],
            "record_valid": True,
            "payload_rule": "exact signed-tip context bytes",
            "key_rule": "compiler-derived key for this context",
        }
        for entry in gamma
    ]
    passed = (
        all(row["passed"] for row in deletion_rows)
        and all(row["still_reads"] and row["passed"] for row in mutation_rows)
        and all(row["passed"] for row in shared_key_rows)
        and all(row["passed"] for row in coalition_rows)
    )
    return {
        "deletion_rows": deletion_rows,
        "single_mutation_rows": mutation_rows,
        "shared_key_rows": shared_key_rows,
        "coalition_rows": coalition_rows,
        "gamma": gamma_summary,
        "deletion_cases": len(deletion_rows),
        "single_mutation_cases": len(mutation_rows),
        "single_mutations_all_still_read": all(row["still_reads"] for row in mutation_rows),
        "shared_key_two_group_cells": len(shared_key_rows),
        "shared_key_candidate_set_mismatches": sum(not row["candidate_set_matches"] for row in shared_key_rows),
        "shared_key_canonical_selection_mismatches": sum(not row["canonical_selection_matches"] for row in shared_key_rows),
        "two_contributor_cells": sum(row["contributor_count"] == 2 for row in coalition_rows),
        "three_contributor_cells": sum(row["contributor_count"] == 3 for row in coalition_rows),
        "coalition_cells": len(coalition_rows),
        "coalition_trace_mismatches": sum(not row["trace_set_matches"] for row in coalition_rows),
        "coalition_canonical_selection_mismatches": sum(not row["canonical_selection_matches"] for row in coalition_rows),
        "trace_contract": "Gamma binds each valid signed tip d_j to its compiler-derived key k_j; Trace_Gamma(Y) is the set of j for which Read_{k_j}(Y)=d_j; a scalar contributor is the lexicographically smallest traced context",
        "passed": passed,
    }

