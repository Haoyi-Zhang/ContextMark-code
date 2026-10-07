"""Portable owned restore regressions with an independent list-scan projection."""
from __future__ import annotations

from copy import deepcopy
import unittest

from contextmark import compiler as api
from contextmark.canonical import canonical_bytes
from contextmark.threshold_backend import ThresholdCarrierAdapter


class OwnedBackend:
    """Deterministic finite test double, not a resource or crash workflow."""
    def __init__(self, delegate):
        self.delegate = delegate
        self.calls = 0
        self.fail_next = False

    def mark(self, key, program, payload):
        self.calls += 1
        if self.fail_next:
            self.fail_next = False
            raise RuntimeError("owned terminal failure")
        return self.delegate.mark(key, program, payload)

    def read(self, key, artifact):
        return self.delegate.read(key, artifact)


def owned_compiler(kind="envelope", seed=7, *, module=api, threshold=ThresholdCarrierAdapter, budget=128):
    delegate = module.AuthenticatedEnvelopeBackend() if kind == "envelope" else threshold(n=5, t=3)
    backend = OwnedBackend(delegate)
    compiler = module.ContextMarkCompiler.deterministic(
        ["builder", "packager"], seed=seed, chain_id="owned-restore-membership",
        backend=backend, max_records=128, max_contexts=budget)
    return compiler, backend


def finite_fixture(kind, attempts, seed=7, *, module=api, threshold=ThresholdCarrierAdapter):
    compiler, backend = owned_compiler(kind, seed, module=module, threshold=threshold)
    chain, artifact = [], module.make_demo_program(2)
    requests = []
    for index in range(attempts):
        args = dict(parent_chain=deepcopy(chain), program=deepcopy(artifact),
                    actor="builder" if index % 2 == 0 else "packager",
                    operation="owned-step", metadata={"issue_id": index})
        backend.fail_next = index % 3 == 2
        try:
            pair = compiler.issue(**args)
        except module.MarkingError:
            requests.append((args, None))
        else:
            chain, artifact = pair
            requests.append((args, deepcopy(pair)))
    return compiler, backend, chain, artifact, requests


def list_scan_projection(snapshot):
    """Independent finite transcript oracle, not a copy of the restore function.

    Check ordered index/terminal coverage by list scans and derive expected
    stored states. Cryptographic authenticity and full request validation stay
    with the compiler; this reference supplies no new security guarantee.
    """
    attempted, entries = snapshot["attempted_contexts"], snapshot["entries"]
    if (type(snapshot["entry_count"]) is not int or type(snapshot["attempted_context_count"]) is not int
            or snapshot["entry_count"] != len(entries) or snapshot["attempted_context_count"] != len(attempted)):
        raise ValueError("counts")
    if attempted != sorted(attempted) or any(a == b for a, b in zip(attempted, attempted[1:])):
        raise ValueError("ordered unique contexts")
    identifiers = [entry["request_id"] for entry in entries]
    if identifiers != sorted(identifiers) or any(a == b for a, b in zip(identifiers, identifiers[1:])):
        raise ValueError("ordered unique requests")
    contexts = [entry["context"] for entry in entries]
    if any(not isinstance(context, str) or not any(context == item for item in attempted) for context in contexts):
        raise ValueError("entry coverage")
    if any(sum(context == item for item in contexts) != 1 for context in attempted):
        raise ValueError("context bijection")
    successes = [entry for entry in entries if entry["status"] == "success"]
    for entry in entries:
        if entry["status"] not in ("success", "failed"):
            raise ValueError("terminal status")
        index, parent = entry["unsigned"]["index"], entry["unsigned"]["parent"]
        if index and not any(e["context"] == parent and e["unsigned"]["index"] == index - 1 for e in successes):
            raise ValueError("successful ancestry")
    requests = {entry["request_id"]: {k: deepcopy(v) for k, v in entry.items() if k != "request_id"}
                for entry in entries}
    owners = {entry["context"]: entry["request_id"] for entry in entries}
    issued = {entry["context"]: (bytes.fromhex(entry["request_program_hex"]), entry["unsigned"]["index"],
                                entry["unsigned"]["parent"], deepcopy(entry["record"]), deepcopy(entry["artifact"]))
              for entry in successes}
    return requests, owners, issued, sorted(attempted)


def authenticated(compiler, snapshot):
    """Fixture-key authentication of inconsistent owned inputs, never forgery."""
    snapshot["tag"] = compiler._registry_tag({k: v for k, v in snapshot.items() if k != "tag"})
    return snapshot


def index_variants(snapshot):
    variants = []
    def variant(name, edit, recount=False):
        packet = deepcopy(snapshot)
        edit(packet)
        if recount:
            packet["entry_count"] = len(packet["entries"])
            packet["attempted_context_count"] = len(packet["attempted_contexts"])
        variants.append((name, packet))
    variant("missing-context", lambda p: p["attempted_contexts"].pop(), True)
    variant("extra-context", lambda p: p["attempted_contexts"].append("ff" * 32), True)
    variant("duplicate-context", lambda p: p["attempted_contexts"].insert(0, p["attempted_contexts"][0]), True)
    variant("unsorted-context", lambda p: p["attempted_contexts"].reverse())
    variant("attempt-count-int", lambda p: p.update(attempted_context_count=99))
    variant("attempt-count-bool", lambda p: p.update(attempted_context_count=True))
    variant("entry-count-int", lambda p: p.update(entry_count=99))
    variant("entry-count-bool", lambda p: p.update(entry_count=True))
    variant("duplicate-entry", lambda p: p["entries"].append(deepcopy(p["entries"][-1])), True)
    variant("unsorted-entries", lambda p: p["entries"].reverse())
    variant("missing-entry", lambda p: p["entries"].pop(), True)
    variant("unindexed-entry", lambda p: p["entries"][0].update(context="ee" * 32))
    return variants


def semantic_variants(snapshot):
    variants = []
    for name, field, value in (
        ("wrong-request-id", "request_id", "00" * 32),
        ("wrong-program", "request_program_hex", canonical_bytes(api.make_demo_program(3)).hex()),
        ("noncanonical-program", "request_program_hex", (b" " + canonical_bytes(api.make_demo_program(2))).hex()),
    ):
        packet = deepcopy(snapshot)
        packet["entries"][0][field] = value
        variants.append((name, packet))
    packet = deepcopy(snapshot)
    success = next(e for e in packet["entries"] if e["status"] == "success")
    success["record"]["operation"] = "different-owned-operation"
    variants.append(("request-record-mismatch", packet))
    for status in ("success", "failed"):
        packet = deepcopy(snapshot)
        child = next(e for e in packet["entries"] if e["status"] == status and e["unsigned"]["index"] > 0)
        packet["entries"] = [child]
        packet["attempted_contexts"] = [child["context"]]
        packet["entry_count"] = packet["attempted_context_count"] = 1
        variants.append(("orphan-" + status, packet))
    return variants


class RestoreMembershipTests(unittest.TestCase):
    def assert_projection(self, compiler, packet):
        expected = list_scan_projection(packet)
        self.assertEqual((compiler._requests, compiler._context_owner, compiler._issued,
                          sorted(compiler._attempted_contexts)), expected)
        self.assertEqual(canonical_bytes(compiler.export_registry_snapshot()), canonical_bytes(packet))

    def test_finite_restore_and_complete_terminal_retries(self):
        for kind in ("envelope", "threshold"):
            for attempts in (0, 1, 8, 32):
                for seed in (0, 7, 20260718):
                    with self.subTest(kind=kind, attempts=attempts, seed=seed):
                        source, _, chain, artifact, requests = finite_fixture(kind, attempts, seed)
                        packet = source.export_registry_snapshot()
                        target, backend = owned_compiler(kind, seed)
                        untouched = deepcopy(packet)
                        target.restore_registry_snapshot(packet)
                        self.assertEqual(packet, untouched)
                        self.assert_projection(target, packet)
                        self.assertEqual(target.registry_status_counts(), source.registry_status_counts())
                        for args, expected in requests:
                            if expected is None:
                                with self.assertRaisesRegex(api.MarkingError, "terminal backend failure: RuntimeError"):
                                    target.issue(**args)
                            else:
                                self.assertEqual(target.issue(**args), expected)
                                self.assertTrue(target.verify(*expected))
                        self.assertEqual(backend.calls, 0)
                        self.assert_projection(target, packet)
                        args = dict(parent_chain=chain, program=artifact, actor="builder",
                                    operation="owned-continuation", metadata={"next": attempts})
                        self.assertEqual(target.issue(**args), source.issue(**args))
                        self.assertEqual(target.export_registry_snapshot(), source.export_registry_snapshot())
                        self.assertEqual(target.registry_status_counts(), source.registry_status_counts())
                        self.assertEqual(backend.calls, 1)

    def test_independent_scan_rejects_index_variants_atomically(self):
        source, _, _, _, _ = finite_fixture("envelope", 8)
        for name, packet in index_variants(source.export_registry_snapshot()):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    list_scan_projection(packet)
                target, backend = owned_compiler()
                empty = canonical_bytes(target.export_registry_snapshot())
                with self.assertRaises(api.ContextMarkError):
                    target.restore_registry_snapshot(authenticated(source, packet))
                self.assertEqual(canonical_bytes(target.export_registry_snapshot()), empty)
                self.assertEqual(backend.calls, 0)

    def test_semantic_validation_and_successful_ancestry_remain(self):
        source, _, _, _, _ = finite_fixture("envelope", 8)
        for name, packet in semantic_variants(source.export_registry_snapshot()):
            with self.subTest(name=name):
                target, backend = owned_compiler()
                empty = canonical_bytes(target.export_registry_snapshot())
                with self.assertRaises(api.ContextMarkError):
                    target.restore_registry_snapshot(authenticated(source, packet))
                self.assertEqual(canonical_bytes(target.export_registry_snapshot()), empty)
                self.assertEqual(backend.calls, 0)

    def test_authentication_nonempty_target_and_snapshot_isolation(self):
        source, _, _, _, _ = finite_fixture("envelope", 8)
        packet = source.export_registry_snapshot()
        target, backend = owned_compiler()
        bad = deepcopy(packet)
        bad["tag"] = "00" * 32
        with self.assertRaisesRegex(api.ContextMarkError, "authentication failed"):
            target.restore_registry_snapshot(bad)
        target.restore_registry_snapshot(packet)
        saved = canonical_bytes(target.export_registry_snapshot())
        with self.assertRaisesRegex(api.ContextMarkError, "requires an empty compiler"):
            target.restore_registry_snapshot(packet)
        self.assertEqual(canonical_bytes(target.export_registry_snapshot()), saved)
        packet["entries"][0]["unsigned"]["metadata"]["mutated"] = True
        packet["attempted_contexts"].clear()
        self.assertEqual(canonical_bytes(target.export_registry_snapshot()), saved)
        self.assertEqual(backend.calls, 0)

    def test_exact_attempt_budget_before_backend_call(self):
        source, _, chain, artifact, _ = finite_fixture("envelope", 8)
        packet = source.export_registry_snapshot()
        target, backend = owned_compiler(budget=8)
        target.restore_registry_snapshot(packet)
        with self.assertRaisesRegex(api.ContextMarkError, "terminal attempt budget exceeded"):
            target.issue(chain, artifact, actor="builder", operation="over-budget")
        self.assertEqual(target.export_registry_snapshot(), packet)
        self.assertEqual(backend.calls, 0)
        too_small, _ = owned_compiler(budget=7)
        with self.assertRaisesRegex(api.ContextMarkError, "exceeds the terminal attempt budget"):
            too_small.restore_registry_snapshot(packet)
        self.assertEqual(too_small.registry_status_counts(), (0, 0, 0))

    def test_matched_session_stateless_full_transcripts(self):
        for kind in ("envelope", "threshold"):
            for depth in (0, 1, 3, 8):
                for mode in ("unchanged", "changed-host", "resume-with-failure"):
                    with self.subTest(kind=kind, depth=depth, mode=mode):
                        stateless, sb = owned_compiler(kind)
                        session_compiler, cb = owned_compiler(kind)
                        chain, artifact = [], api.make_demo_program(2)
                        session = session_compiler.begin_session(deepcopy(artifact))
                        for index in range(depth):
                            program = deepcopy(artifact)
                            if mode == "changed-host":
                                program["module"] = "owned-host-" + str(index)
                            args = dict(actor="builder", operation="owned-stage", metadata={"issue_id": index})
                            chain, artifact = stateless.issue(chain, program, **args)
                            context = session.append_private(program=program, **args)
                            self.assertEqual(session.snapshot(), (chain, artifact))
                            self.assertEqual(context, chain[-1]["context"])
                            self.assertEqual(session_compiler.serialize_manifest(session.snapshot()[0]),
                                             stateless.serialize_manifest(chain))
                            self.assertEqual(session_compiler.serialize_artifact(session.snapshot()[1]),
                                             stateless.serialize_artifact(artifact))
                            self.assertEqual(session_compiler.export_registry_snapshot(), stateless.export_registry_snapshot())
                            self.assertEqual(session_compiler.registry_status_counts(), stateless.registry_status_counts())
                            self.assertTrue(session_compiler.verify(chain, artifact))
                            if index == 0 and mode == "resume-with-failure":
                                failure = dict(actor="packager", operation="owned-failure")
                                sb.fail_next = cb.fail_next = True
                                with self.assertRaises(api.MarkingError):
                                    stateless.issue(chain, artifact, **failure)
                                with self.assertRaises(api.MarkingError):
                                    session.append_private(**failure)
                                self.assertEqual(session_compiler.export_registry_snapshot(), stateless.export_registry_snapshot())
                                left, sb = owned_compiler(kind)
                                right, cb = owned_compiler(kind)
                                left.restore_registry_snapshot(stateless.export_registry_snapshot())
                                right.restore_registry_snapshot(session_compiler.export_registry_snapshot())
                                stateless, session_compiler = left, right
                                session = right.begin_session(chain=chain, artifact=artifact)
                                for compiler in (left, right):
                                    with self.assertRaisesRegex(api.MarkingError, "terminal backend failure"):
                                        compiler.issue(chain, artifact, **failure)
                                self.assertEqual((sb.calls, cb.calls), (0, 0))
                        saved = session_compiler.export_registry_snapshot()
                        with self.assertRaisesRegex(api.ContextMarkError, "stale session parent"):
                            session.append_private(actor="builder", operation="stale", expected_parent_context="00" * 32)
                        self.assertEqual(session_compiler.export_registry_snapshot(), saved)
                        exported_chain, exported_artifact = session.snapshot()
                        exported_artifact["module"] = "mutated-export"
                        if exported_chain:
                            exported_chain[0]["operation"] = "mutated-export"
                        self.assertEqual(session.snapshot(), (chain, artifact))


if __name__ == "__main__":
    unittest.main()

