"""Functional durable issuance tests, exclusively on owned local stub services."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from contextmark.canonical import canonical_bytes
from contextmark.compiler import ContextMarkCompiler, ContextMarkError, MarkingError, make_demo_program
from contextmark.durable_registry import DurableRegistry, DurableRegistryError
from owned_durable_fixture import ARTIFACT_ROOT, WORK_ROOT, OwnedStubBackend, compiler, request


class DurableRegistryTests(unittest.TestCase):
    def setUp(self):
        WORK_ROOT.mkdir(parents=True, exist_ok=True)
        self.folder = tempfile.TemporaryDirectory(prefix="functional-", dir=WORK_ROOT)
        self.path = Path(self.folder.name) / "state.sqlite"
        self.instances = []

    def tearDown(self):
        for c in reversed(self.instances):
            if not c._closed:
                c.close()
        self.folder.cleanup()

    def open(self, backend=None, **kwargs):
        c = compiler(self.path, backend or OwnedStubBackend(), **kwargs)
        self.instances.append(c)
        return c

    def child(self, mode):
        return subprocess.run([sys.executable, "-B", str(ARTIFACT_ROOT / "tests" / "owned_durable_fixture.py"),
                               self.folder.name, mode], cwd=ARTIFACT_ROOT,
                              env={**os.environ, "PYTHONPATH": str(ARTIFACT_ROOT), "PYTHONDONTWRITEBYTECODE": "1"},
                              capture_output=True, text=True, timeout=20)

    def call_events(self):
        path = Path(self.folder.name) / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_pending_is_committed_before_backend_entry(self):
        b = OwnedStubBackend()
        c = self.open(b)
        def inspect(payload):
            with closing(sqlite3.connect(self.path)) as db:
                row = db.execute("SELECT body FROM attempts WHERE context=?", (payload,)).fetchone()
                self.assertEqual(json.loads(row[0])["status"], "pending")
        b.before_mark = inspect
        c.issue(**request())
        self.assertEqual(b.calls, 1)

    def test_success_restart_and_fresh_session_continuation(self):
        b = OwnedStubBackend()
        c = self.open(b)
        pair = c.issue(**request())
        snapshot = c.export_registry_snapshot()
        self.assertTrue(c.verify(*pair))
        c.close()
        other = OwnedStubBackend()
        restored = self.open(other)
        self.assertEqual(restored.issue(**request()), pair)
        self.assertEqual(restored.export_registry_snapshot(), snapshot)
        self.assertEqual(other.calls, 0)
        session = restored.begin_session(chain=pair[0], artifact=pair[1])
        session.append_private(actor="builder", operation="owned-package")
        self.assertTrue(restored.verify(*session.snapshot()))
        self.assertEqual(other.calls, 1)

    def test_backend_and_postcheck_failures_are_terminal_after_restart(self):
        for mode in ("raise", "reader-fault", "binder-fault", "noncanonical"):
            with self.subTest(mode=mode):
                self.path = Path(self.folder.name) / (mode + ".sqlite")
                b = OwnedStubBackend(mode=mode)
                c = self.open(b)
                with self.assertRaises(MarkingError):
                    c.issue(**request())
                self.assertEqual(c.registry_status_counts(), (0, 1, 1))
                c.close()
                other = OwnedStubBackend()
                restored = self.open(other)
                with self.assertRaisesRegex(MarkingError, "terminal backend failure"):
                    restored.issue(**request())
                self.assertEqual(other.calls, 0)
                restored.close()

    def test_abrupt_process_exit_crash_matrix_and_two_restarts(self):
        for mode, calls in (("after-reservation", 0), ("inside-mark", 1), ("before-terminal", 1), ("during-terminal", 1)):
            with self.subTest(mode=mode):
                # One separate work folder per child, all owned and candidate-local.
                child_folder = Path(self.folder.name) / mode
                child_folder.mkdir()
                completed = subprocess.run([sys.executable, "-B", str(ARTIFACT_ROOT / "tests" / "owned_durable_fixture.py"),
                                           str(child_folder), mode], cwd=ARTIFACT_ROOT,
                                          env={**os.environ, "PYTHONPATH": str(ARTIFACT_ROOT), "PYTHONDONTWRITEBYTECODE": "1"},
                                          capture_output=True, text=True, timeout=20)
                self.assertIn(completed.returncode, (71, 72, 73, 76), completed.stderr)
                call_path = child_folder / "calls.jsonl"
                events = call_path.read_text().splitlines() if call_path.exists() else []
                self.assertEqual(len(events), calls)
                for _ in range(2):
                    b = OwnedStubBackend(call_log=call_path)
                    with compiler(child_folder / "state.sqlite", b) as recovered:
                        with self.assertRaisesRegex(MarkingError, "InterruptedAttempt"):
                            recovered.issue(**request())
                        self.assertEqual(recovered.registry_status_counts(), (0, 1, 1))
                        self.assertEqual(b.calls, 0)
                events = call_path.read_text().splitlines() if call_path.exists() else []
                self.assertEqual(len(events), calls)

    def test_exit_before_reservation_does_not_consume_attempt(self):
        for mode, code in (("before-reservation", 70), ("during-reservation", 75)):
            with self.subTest(mode=mode):
                folder = Path(self.folder.name) / mode
                folder.mkdir()
                result = subprocess.run([sys.executable, "-B", str(ARTIFACT_ROOT / "tests" / "owned_durable_fixture.py"),
                                        str(folder), mode], cwd=ARTIFACT_ROOT,
                                       env={**os.environ, "PYTHONPATH": str(ARTIFACT_ROOT), "PYTHONDONTWRITEBYTECODE": "1"},
                                       capture_output=True, text=True, timeout=20)
                self.assertEqual(result.returncode, code, result.stderr)
                b = OwnedStubBackend(call_log=folder / "calls.jsonl")
                with compiler(folder / "state.sqlite", b) as c:
                    self.assertEqual(c.registry_status_counts(), (0, 0, 0))
                    c.issue(**request())
                self.assertEqual(len((folder / "calls.jsonl").read_text().splitlines()), 1)

    def test_exit_after_terminal_commit_replays_committed_output(self):
        result = self.child("after-terminal")
        self.assertEqual(result.returncode, 74, result.stderr)
        b = OwnedStubBackend(call_log=Path(self.folder.name) / "calls.jsonl")
        c = self.open(b)
        pair = c.issue(**request())
        self.assertTrue(c.verify(*pair))
        self.assertEqual(c.registry_status_counts(), (1, 0, 1))
        self.assertEqual(b.calls, 0)
        self.assertEqual(len(self.call_events()), 1)

    def test_active_owner_excludes_other_compiler_and_process(self):
        c = self.open()
        with self.assertRaises(ContextMarkError):
            self.open()
        result = self.child("ok")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.call_events(), [])
        self.assertEqual(c.registry_status_counts(), (0, 0, 0))
        c.close()
        self.assertEqual(self.child("ok").returncode, 0)

    def test_pending_concurrent_retry_does_not_sample(self):
        entered, release = threading.Event(), threading.Event()
        b = OwnedStubBackend()
        c = self.open(b)
        def hold(_payload):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("owned test timeout")
        b.before_mark = hold
        with ThreadPoolExecutor(max_workers=2) as pool:
            future = pool.submit(c.issue, **request())
            try:
                self.assertTrue(entered.wait(5))
                with self.assertRaisesRegex(ContextMarkError, "in progress"):
                    c.issue(**request())
                with self.assertRaisesRegex(ContextMarkError, "pending"):
                    c.close()
            finally:
                release.set()
            pair = future.result(timeout=5)
        self.assertEqual(c.issue(**request()), pair)
        self.assertEqual(b.calls, 1)

    def test_durable_context_alias_is_rejected_after_restart(self):
        coarse = lambda _program: "00" * 32
        b = OwnedStubBackend(binder=coarse)
        c = self.open(b, binder=coarse)
        args = request()
        c.issue(**args)
        c.close()
        other = OwnedStubBackend(binder=coarse)
        restored = self.open(other, binder=coarse)
        args["program"] = make_demo_program(3)
        with self.assertRaisesRegex(ContextMarkError, "another logical request"):
            restored.issue(**args)
        self.assertEqual(other.calls, 0)

    def test_interrupted_attempt_still_consumes_budget(self):
        self.assertEqual(self.child("inside-mark").returncode, 71)
        b = OwnedStubBackend()
        c = self.open(b, max_contexts=1)
        with self.assertRaisesRegex(ContextMarkError, "attempt budget"):
            c.issue([], make_demo_program(3), actor="builder", operation="owned-new")
        self.assertEqual(b.calls, 0)

    def test_reservation_write_error_stops_issuer_before_mark(self):
        b = OwnedStubBackend()
        c = self.open(b)
        with patch.object(c._durable, "write_entries", side_effect=DurableRegistryError("owned I/O failure")):
            with self.assertRaisesRegex(ContextMarkError, "issuer stopped"):
                c.issue(**request())
        with self.assertRaisesRegex(ContextMarkError, "storage uncertain"):
            c.issue(**request())
        with self.assertRaisesRegex(ContextMarkError, "storage uncertain"):
            c.export_registry_snapshot()
        self.assertEqual(b.calls, 0)

    def test_driver_transaction_errors_stop_issuer_and_preserve_state(self):
        class OwnedDriver:
            def __init__(self, rollback_fails):
                self.rollback_fails = rollback_fails
                self.in_transaction = False
                self.rollback_calls = 0

            def execute(self, sql, *parameters):
                if sql == "BEGIN IMMEDIATE":
                    self.in_transaction = True
                elif sql == "COMMIT":
                    raise sqlite3.OperationalError("owned commit I/O fault")
                elif sql == "ROLLBACK":
                    self.rollback_calls += 1
                    if self.rollback_fails:
                        raise sqlite3.OperationalError("owned rollback I/O fault")
                    self.in_transaction = False
                return self

            def close(self):
                self.in_transaction = False

        for rollback_fails in (False, True):
            with self.subTest(rollback_fails=rollback_fails):
                c = ContextMarkCompiler.deterministic(["builder"], backend=OwnedStubBackend())
                pair = c.issue([], make_demo_program(2), actor="builder", operation="owned-build")
                saved_requests = deepcopy(c._requests)
                saved_snapshot = c.export_registry_snapshot()
                program, unsigned, context, request_id = c._prepare_request(
                    pair[0], pair[1], actor="builder", operation="owned-package", metadata=None)
                entry = dict(request_id=request_id, status="pending", request_program_hex=program.hex(),
                             unsigned=unsigned, context=context)
                store = DurableRegistry.__new__(DurableRegistry)
                store.connection = OwnedDriver(rollback_fails)
                store.key, store.chain_id = c.master_key, c.chain_id
                store.owner, store.locked = None, False
                store._header = lambda: {"entry_count": 1, "revision": 2}
                c._durable = store
                try:
                    with self.assertRaises(ContextMarkError) as raised:
                        c._persist([entry], reserve=True)
                    wrapped = raised.exception.__cause__
                    self.assertIsInstance(wrapped, DurableRegistryError)
                    self.assertIsInstance(wrapped.__cause__, sqlite3.OperationalError)
                    expected_fault = "owned rollback I/O fault" if rollback_fails else "owned commit I/O fault"
                    self.assertEqual(str(wrapped.__cause__), expected_fault)
                    if rollback_fails:
                        self.assertEqual(str(wrapped.__cause__.__context__), "owned commit I/O fault")
                    self.assertEqual(store.connection.rollback_calls, 1)
                    self.assertTrue(c._storage_failed)
                    self.assertEqual(c._requests, saved_requests)
                    self.assertEqual(c.registry_status_counts(), (1, 0, 1))
                    self.assertTrue(c.verify(*pair))
                    self.assertEqual(saved_snapshot["entries"][0]["record"], pair[0][0])
                    with self.assertRaisesRegex(ContextMarkError, "storage uncertain"):
                        c._ensure_issuance_open()
                    with self.assertRaisesRegex(ContextMarkError, "storage uncertain"):
                        c.export_registry_snapshot()
                finally:
                    c.close()

    def test_terminal_write_error_never_releases_and_restart_does_not_retry(self):
        b = OwnedStubBackend()
        c = self.open(b)
        original = c._durable.write_entries
        def fault(entries, *, reserve=False):
            if not reserve:
                raise DurableRegistryError("owned terminal I/O failure")
            original(entries, reserve=reserve)
        with patch.object(c._durable, "write_entries", side_effect=fault):
            with self.assertRaises(ContextMarkError):
                c.issue(**request())
        self.assertEqual(b.calls, 1)
        c.close()
        other = OwnedStubBackend()
        restored = self.open(other)
        with self.assertRaisesRegex(MarkingError, "InterruptedAttempt"):
            restored.issue(**request())
        self.assertEqual(other.calls, 0)

    def test_recovery_write_failure_cannot_open_issuer_or_erase_pending(self):
        self.assertEqual(self.child("inside-mark").returncode, 71)
        b = OwnedStubBackend()
        with patch("contextmark.durable_registry.DurableRegistry.write_entries", side_effect=DurableRegistryError("owned recovery fault")):
            with self.assertRaises(ContextMarkError):
                self.open(b)
        self.assertEqual(b.calls, 0)
        restored = self.open(b)
        with self.assertRaisesRegex(MarkingError, "InterruptedAttempt"):
            restored.issue(**request())
        self.assertEqual(b.calls, 0)

    def test_uncertain_error_after_committed_terminal_state(self):
        for mode in ("ok", "raise"):
            with self.subTest(mode=mode):
                self.path = Path(self.folder.name) / ("uncertain-" + mode + ".sqlite")
                b = OwnedStubBackend(mode=mode)
                c = self.open(b)
                original = c._durable.write_entries
                def uncertain(entries, *, reserve=False):
                    original(entries, reserve=reserve)
                    if not reserve:
                        raise DurableRegistryError("owned error after commit")
                with patch.object(c._durable, "write_entries", side_effect=uncertain):
                    with self.assertRaises(ContextMarkError):
                        c.issue(**request())
                with self.assertRaisesRegex(ContextMarkError, "storage uncertain"):
                    c.issue(**request())
                self.assertEqual(b.calls, 1)
                c.close()
                other = OwnedStubBackend()
                restored = self.open(other)
                if mode == "ok":
                    self.assertTrue(restored.verify(*restored.issue(**request())))
                else:
                    with self.assertRaisesRegex(MarkingError, "RuntimeError"):
                        restored.issue(**request())
                self.assertEqual(other.calls, 0)
                restored.close()

    def test_interrupted_child_preserves_prefix_and_allows_different_context(self):
        b = OwnedStubBackend(call_log=Path(self.folder.name) / "calls.jsonl")
        c = self.open(b)
        chain, artifact = c.issue(**request())
        c.close()
        result = self.child("append-inside-mark")
        self.assertEqual(result.returncode, 71, result.stderr)
        other = OwnedStubBackend(call_log=Path(self.folder.name) / "calls.jsonl")
        restored = self.open(other)
        self.assertEqual(restored.issue(**request()), (chain, artifact))
        session = restored.begin_session(chain=chain, artifact=artifact)
        with self.assertRaisesRegex(MarkingError, "InterruptedAttempt"):
            session.append_private(actor="builder", operation="owned-package")
        self.assertEqual(other.calls, 0)
        session.append_private(actor="builder", operation="owned-other-context")
        self.assertTrue(restored.verify(*session.snapshot()))
        events = self.call_events()
        self.assertEqual(len(events), 3)
        self.assertEqual(len({event["payload"] for event in events}), 3)
        self.assertEqual(len({event["key_digest"] for event in events}), 3)
        self.assertEqual(restored.registry_status_counts(), (2, 1, 3))

    def test_failure_commit_error_preserves_pending_and_stops_issuer(self):
        b = OwnedStubBackend(mode="raise")
        c = self.open(b)
        original = c._durable.write_entries
        def fault(entries, *, reserve=False):
            if not reserve:
                raise DurableRegistryError("owned failure-tombstone I/O error")
            original(entries, reserve=reserve)
        with patch.object(c._durable, "write_entries", side_effect=fault):
            with self.assertRaises(ContextMarkError):
                c.issue(**request())
        self.assertEqual(b.calls, 1)
        c.close()
        other = OwnedStubBackend()
        restored = self.open(other)
        with self.assertRaisesRegex(MarkingError, "InterruptedAttempt"):
            restored.issue(**request())
        self.assertEqual(other.calls, 0)

    def test_snapshot_import_into_empty_durable_store_survives_restart(self):
        b = OwnedStubBackend()
        memory = ContextMarkCompiler.deterministic(
            ["builder"], seed=29, chain_id="owned-durable-repair", backend=b)
        pair = memory.issue(**request())
        packet = memory.export_registry_snapshot()
        c = self.open()
        c.restore_registry_snapshot(packet)
        self.assertEqual(c.export_registry_snapshot(), packet)
        c.close()
        other = OwnedStubBackend()
        restored = self.open(other)
        self.assertEqual(restored.issue(**request()), pair)
        self.assertEqual(other.calls, 0)

    def test_wrong_test_key_and_chain_do_not_reset_existing_store(self):
        c = self.open()
        c.issue(**request())
        c.close()
        for kwargs in ({"seed": 30}, {"chain_id": "owned-other-chain"}):
            args = dict(seed=29, chain_id="owned-durable-repair", registry_path=str(self.path), backend=OwnedStubBackend())
            args.update(kwargs)
            with self.assertRaises(ContextMarkError):
                ContextMarkCompiler.deterministic(["builder"], **args)
        restored = self.open()
        self.assertEqual(restored.registry_status_counts(), (1, 0, 1))

    def test_closed_issuer_cannot_issue_or_import(self):
        c = self.open()
        packet = c.export_registry_snapshot()
        c.close()
        with self.assertRaises(ContextMarkError):
            c.issue(**request())
        with self.assertRaises(ContextMarkError):
            c.restore_registry_snapshot(packet)

    def test_durable_private_and_stateless_transcripts_match(self):
        left = self.open()
        self.path = Path(self.folder.name) / "session.sqlite"
        right = self.open()
        chain, artifact = [], make_demo_program(2)
        session = right.begin_session(deepcopy(artifact))
        for i in range(8):
            args = dict(actor="builder", operation="owned-stage", metadata={"issue_id": i})
            chain, artifact = left.issue(chain, artifact, **args)
            session.append_private(program=deepcopy(session.snapshot()[1]), **args)
            self.assertEqual(session.snapshot(), (chain, artifact))
        self.assertEqual(canonical_bytes(left.export_registry_snapshot()), canonical_bytes(right.export_registry_snapshot()))


if __name__ == "__main__":
    unittest.main()
