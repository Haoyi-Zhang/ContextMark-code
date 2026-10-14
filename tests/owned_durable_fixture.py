"""Owned local backend and bounded child-process crash fixture; no network."""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sys

from contextmark.canonical import canonical_bytes
from contextmark.compiler import AuthenticatedEnvelopeBackend, ContextMarkCompiler, make_demo_program
from contextmark.durable_registry import DurableRegistry

ARTIFACT_ROOT = Path(__file__).resolve().parents[1]
WORK_ROOT = Path(os.environ.get("CONTEXTMARK_OWNED_WORK_ROOT",
                               str(ARTIFACT_ROOT / "results" / "durable-repair-work"))).resolve()


class OwnedStubBackend:
    """A local authenticated test double, with optional ordinary service faults."""
    def __init__(self, *, mode="ok", call_log=None, binder=None):
        self.mode, self.call_log = mode, call_log
        self.calls = 0
        self.delegate = AuthenticatedEnvelopeBackend() if binder is None else AuthenticatedEnvelopeBackend(binder)
        self.before_mark = None

    def mark(self, key, program, payload):
        if self.before_mark:
            self.before_mark(payload)
        self.calls += 1
        if self.call_log:
            event = canonical_bytes({"payload": payload, "key_digest": hashlib.sha256(key).hexdigest()}) + b"\n"
            with open(self.call_log, "ab") as handle:
                handle.write(event)
                handle.flush()
                os.fsync(handle.fileno())
        if self.mode == "crash":
            os._exit(71)
        if self.mode == "raise":
            raise RuntimeError("owned local backend fault")
        artifact = self.delegate.mark(key, deepcopy(program), payload)
        if self.mode == "binder-fault":
            artifact["module"] = "owned-changed-host"
        elif self.mode == "noncanonical":
            artifact["owned_float"] = 1.5
        return artifact

    def read(self, key, artifact):
        if self.mode == "reader-fault":
            return None
        return self.delegate.read(key, artifact)


def request():
    return dict(parent_chain=[], program=make_demo_program(2), actor="builder",
                operation="owned-build", metadata={"issue_id": 0})


def compiler(path, backend, **kwargs):
    return ContextMarkCompiler.deterministic(["builder"], seed=29,
        chain_id="owned-durable-repair", registry_path=str(path), backend=backend, **kwargs)


def retire_with_process_exit(folder, mode):
    """Interrupt native pending retirement, with no issuance or backend mark."""
    original = DurableRegistry.write_entries

    def retire(store, entries, *, reserve=False):
        if (reserve or len(entries) != 2
                or any(entry.get("status") != "failed"
                       or entry.get("failure_code") != "InterruptedAttempt" for entry in entries)):
            raise ValueError("expected two owned pending-to-failed recovery entries")
        if mode == "during-recovery":
            def before_commit(sql):
                if sql.strip().upper() == "COMMIT":
                    os._exit(77)
            store.connection.set_trace_callback(before_commit)
        original(store, entries, reserve=False)
        if mode == "after-recovery":
            os._exit(78)
        raise RuntimeError("native retirement did not reach the injected exit")

    DurableRegistry.write_entries = retire
    with compiler(folder / "state.sqlite", OwnedStubBackend(call_log=folder / "calls.jsonl")):
        raise RuntimeError("recovery unexpectedly returned without the injected exit")


def child_main():
    # Paths are restricted to this candidate's generated local work directory.
    folder = Path(sys.argv[1]).resolve()
    if not folder.is_relative_to(WORK_ROOT.resolve()):
        raise ValueError("child fixture must stay inside the P029 candidate")
    mode = sys.argv[2]
    if mode in {"during-recovery", "after-recovery"}:
        return retire_with_process_exit(folder, mode)
    append = mode.startswith("append-")
    if append:
        mode = mode.removeprefix("append-")
    backend = OwnedStubBackend(mode="crash" if mode == "inside-mark" else "ok",
                               call_log=folder / "calls.jsonl")
    c = compiler(folder / "state.sqlite", backend)
    args = request()
    if append:
        chain, artifact = c.issue(**args)
        args = dict(parent_chain=chain, program=artifact, actor="builder", operation="owned-package")
    original = c._durable.write_entries

    def injected(entries, *, reserve=False):
        if mode == "before-reservation" and reserve:
            os._exit(70)
        if mode == "before-terminal" and not reserve:
            os._exit(72)
        original(entries, reserve=reserve)
        if mode == "after-reservation" and reserve:
            os._exit(73)
        if mode == "after-terminal" and not reserve:
            os._exit(74)

    c._durable.write_entries = injected
    if mode in {"during-reservation", "during-terminal"}:
        commits = 0
        def interrupt_transaction(sql):
            nonlocal commits
            if sql.strip().upper() == "COMMIT":
                commits += 1
                if mode == "during-reservation" or commits == 2:
                    os._exit(75 if mode == "during-reservation" else 76)
        c._durable.connection.set_trace_callback(interrupt_transaction)
    try:
        pair = c.issue(**args)
        print(json.dumps(pair, sort_keys=True))
    except Exception as exc:
        print(type(exc).__name__ + ": " + str(exc))
        return 5
    finally:
        c.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(child_main())
