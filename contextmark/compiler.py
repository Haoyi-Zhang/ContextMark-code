"""Context-bound software provenance compiler and durable issue registry."""
from __future__ import annotations

import hashlib
import hmac
import json
import threading
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .canonical import CanonicalizationError, canonical_bytes, expression_binder

RECORD_VERSION = "contextmark-record-v1"
GENESIS = "GENESIS"
RECORD_FIELDS = {
    "version",
    "chain_id",
    "index",
    "parent",
    "binder",
    "actor",
    "operation",
    "metadata",
    "context",
    "signature",
}


class ContextMarkError(ValueError):
    """Base error for the reference compiler."""


class MarkingError(ContextMarkError):
    """Raised when the backend fails or violates its interface contract."""


class WatermarkBackend(Protocol):
    def mark(self, key: bytes, program: dict[str, Any], payload: str) -> dict[str, Any]: ...

    def read(self, key: bytes, artifact: dict[str, Any]) -> str | None: ...


@dataclass(frozen=True)
class VerificationResult:
    accepted: bool
    reason: str


class AuthenticatedEnvelopeBackend:
    """Removable authenticated envelope used as a negative control."""

    VERSION = "authenticated-envelope-v1"
    FIELDS = {"backend", "payload", "tag"}

    def __init__(self, binder=expression_binder) -> None:
        self.binder = binder

    def _tag(self, key: bytes, program: dict[str, Any], payload: str) -> str:
        message = b"contextmark/envelope/v1\0" + bytes.fromhex(self.binder(program)) + bytes.fromhex(payload)
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def mark(self, key: bytes, program: dict[str, Any], payload: str) -> dict[str, Any]:
        try:
            canonical_bytes(program)
        except (CanonicalizationError, TypeError, ValueError, RecursionError) as exc:
            raise MarkingError("program is outside the canonical artifact language") from exc
        if not isinstance(payload, str) or len(payload) != 64 or payload != payload.lower():
            raise MarkingError("payload must be canonical lowercase SHA-256 hexadecimal")
        try:
            bytes.fromhex(payload)
        except ValueError as exc:
            raise MarkingError("payload is not hexadecimal") from exc
        artifact = deepcopy(program)
        artifact["_contextmark"] = {
            "backend": self.VERSION,
            "payload": payload,
            "tag": self._tag(key, artifact, payload),
        }
        return artifact

    def read(self, key: bytes, artifact: dict[str, Any]) -> str | None:
        try:
            if not isinstance(artifact, dict):
                return None
            # Canonicalize the complete artifact before the binder erases any
            # carrier field.  Otherwise malformed data in a binder-ignored
            # field could bypass the public artifact language.
            canonical_bytes(artifact)
            envelope = artifact.get("_contextmark")
            if not isinstance(envelope, dict) or set(envelope) != self.FIELDS:
                return None
            if envelope.get("backend") != self.VERSION:
                return None
            payload, tag = envelope.get("payload"), envelope.get("tag")
            if not isinstance(payload, str) or len(payload) != 64 or payload != payload.lower():
                return None
            if not isinstance(tag, str) or len(tag) != 64 or tag != tag.lower():
                return None
            bytes.fromhex(payload)
            bytes.fromhex(tag)
            expected = self._tag(key, artifact, payload)
            if not hmac.compare_digest(tag, expected):
                return None
            return payload
        except (CanonicalizationError, ValueError, TypeError, RecursionError, RuntimeError):
            return None


class ContextMarkCompiler:
    """Reference compiler with terminal success/failure issue semantics."""

    _CONTEXT_DOMAIN = b"contextmark/context/v1\0"
    _SIGNATURE_DOMAIN = b"contextmark/signature/v1\0"
    _KEY_DOMAIN = b"contextmark/watermark-key/v1\0"
    _REQUEST_DOMAIN = b"contextmark/request/v1\0"
    _REGISTRY_TAG_DOMAIN = b"contextmark/registry/v1\0"
    _REGISTRY_VERSION = "contextmark-registry-v1"

    def __init__(
        self,
        *,
        master_key: bytes,
        actor_private_keys: Mapping[str, Ed25519PrivateKey],
        actor_public_keys: Mapping[str, Ed25519PublicKey],
        chain_id: str = "contextmark-chain",
        binder=expression_binder,
        backend: WatermarkBackend | None = None,
        max_records: int = 4096,
        max_contexts: int = 16384,
    ) -> None:
        if len(master_key) < 32:
            raise ContextMarkError("master key must contain at least 32 bytes")
        if not actor_public_keys:
            raise ContextMarkError("at least one authorized actor is required")
        self.master_key = bytes(master_key)
        self.actor_private_keys = dict(actor_private_keys)
        self.actor_public_keys = dict(actor_public_keys)
        self.chain_id = chain_id
        self.binder = binder
        self.backend = backend or AuthenticatedEnvelopeBackend(binder)
        self.max_records = max_records
        self.max_contexts = max_contexts
        self._registry_lock = threading.RLock()
        self._requests: dict[str, dict[str, Any]] = {}
        self._context_owner: dict[str, str] = {}
        self._issued: dict[str, tuple[bytes, int, str, dict[str, Any], dict[str, Any]]] = {}
        self._attempted_contexts: set[str] = set()

    @classmethod
    def deterministic(
        cls,
        actors: list[str] | tuple[str, ...],
        *,
        seed: int = 20260718,
        chain_id: str = "contextmark-chain",
        binder=expression_binder,
        backend: WatermarkBackend | None = None,
        max_records: int = 4096,
        max_contexts: int = 16384,
    ) -> "ContextMarkCompiler":
        private: dict[str, Ed25519PrivateKey] = {}
        public: dict[str, Ed25519PublicKey] = {}
        for actor in actors:
            material = hashlib.sha256(f"contextmark/actor/{seed}/{actor}".encode()).digest()
            key = Ed25519PrivateKey.from_private_bytes(material)
            private[actor] = key
            public[actor] = key.public_key()
        master = hashlib.sha256(f"contextmark/master/{seed}".encode()).digest()
        return cls(
            master_key=master,
            actor_private_keys=private,
            actor_public_keys=public,
            chain_id=chain_id,
            binder=binder,
            backend=backend,
            max_records=max_records,
            max_contexts=max_contexts,
        )

    @staticmethod
    def _unsigned(record: Mapping[str, Any]) -> dict[str, Any]:
        return {key: deepcopy(record[key]) for key in (
            "version", "chain_id", "index", "parent", "binder", "actor", "operation", "metadata"
        )}

    def _context_digest(self, unsigned: Mapping[str, Any]) -> str:
        return hashlib.sha256(self._CONTEXT_DOMAIN + canonical_bytes(dict(unsigned))).hexdigest()

    def _signature_message(self, unsigned: Mapping[str, Any], context: str) -> bytes:
        return self._SIGNATURE_DOMAIN + canonical_bytes({"record": dict(unsigned), "context": context})

    def derive_watermark_key(self, context: str) -> bytes:
        try:
            raw = bytes.fromhex(context)
        except ValueError as exc:
            raise ContextMarkError("context is not hexadecimal") from exc
        if len(raw) != 32:
            raise ContextMarkError("context digest has the wrong length")
        return hmac.new(self.master_key, self._KEY_DOMAIN + raw, hashlib.sha256).digest()

    def _prepare_request(
        self,
        parent_chain: list[dict[str, Any]],
        program: dict[str, Any],
        *,
        actor: str,
        operation: str,
        metadata: Mapping[str, Any] | None,
    ) -> tuple[bytes, dict[str, Any], str, str]:
        if actor not in self.actor_private_keys:
            raise ContextMarkError(f"no private key for actor {actor!r}")
        if len(parent_chain) >= self.max_records:
            raise ContextMarkError("record limit exceeded")
        if not isinstance(operation, str) or not operation:
            raise ContextMarkError("operation must be a nonempty string")
        parent = str(parent_chain[-1]["context"]) if parent_chain else GENESIS
        request_program = canonical_bytes(program)
        unsigned = {
            "version": RECORD_VERSION,
            "chain_id": self.chain_id,
            "index": len(parent_chain),
            "parent": parent,
            "binder": self.binder(program),
            "actor": actor,
            "operation": operation,
            "metadata": deepcopy(dict(metadata or {})),
        }
        context = self._context_digest(unsigned)
        request_id = self._request_identifier(unsigned, request_program)
        return request_program, unsigned, context, request_id

    def _request_identifier(self, unsigned: Mapping[str, Any], request_program: bytes) -> str:
        request_material = {
            "parent": unsigned["parent"],
            "actor": unsigned["actor"],
            "operation": unsigned["operation"],
            "metadata": unsigned["metadata"],
            "binder": unsigned["binder"],
            "program_sha256": hashlib.sha256(request_program).hexdigest(),
        }
        return hashlib.sha256(self._REQUEST_DOMAIN + canonical_bytes(request_material)).hexdigest()

    def _terminal_response(self, request_id: str, request_program: bytes, unsigned: dict[str, Any], context: str):
        state = self._requests.get(request_id)
        if state is None:
            return None
        if state["request_program_hex"] != request_program.hex() or state["unsigned"] != unsigned or state["context"] != context:
            raise ContextMarkError("request identifier is already bound to another request")
        if state["status"] == "success":
            artifact = deepcopy(state["artifact"])
            return self._reconstruct_chain(context), artifact
        if state["status"] == "failed":
            raise MarkingError(f"terminal backend failure: {state['failure_code']}")
        raise ContextMarkError("request is already in progress")

    def _issue_from_validated_parent(
        self,
        parent_chain: list[dict[str, Any]],
        program: dict[str, Any],
        *,
        actor: str,
        operation: str,
        metadata: Mapping[str, Any] | None = None,
        _return_chain: bool = True,
    ) -> tuple[Any, dict[str, Any]]:
        try:
            request_program, unsigned, context, request_id = self._prepare_request(
                parent_chain, program, actor=actor, operation=operation, metadata=metadata
            )
        except (CanonicalizationError, TypeError, ValueError) as exc:
            raise ContextMarkError(f"request construction failed: {exc}") from exc

        with self._registry_lock:
            existing = self._terminal_response(request_id, request_program, unsigned, context)
            if existing is not None:
                chain, artifact = existing
                return (chain, artifact) if _return_chain else (deepcopy(chain[-1]), artifact)
            owner = self._context_owner.get(context)
            if owner is not None and owner != request_id:
                raise ContextMarkError("context digest is already bound to another logical request")
            if context not in self._attempted_contexts and len(self._attempted_contexts) >= self.max_contexts:
                raise ContextMarkError("terminal attempt budget exceeded")
            self._attempted_contexts.add(context)
            self._context_owner[context] = request_id
            self._requests[request_id] = {
                "status": "pending",
                "request_program_hex": request_program.hex(),
                "unsigned": deepcopy(unsigned),
                "context": context,
            }

        key = self.derive_watermark_key(context)
        try:
            artifact = self.backend.mark(key, deepcopy(program), context)
            if self.binder(artifact) != unsigned["binder"]:
                raise MarkingError("backend is not binder transparent")
            if self.backend.read(key, artifact) != context:
                raise MarkingError("backend correctness check failed")
            signature = self.actor_private_keys[actor].sign(self._signature_message(unsigned, context)).hex()
            record = {**unsigned, "context": context, "signature": signature}
        except Exception as exc:
            failure_code = exc.__class__.__name__
            with self._registry_lock:
                self._requests[request_id].update({"status": "failed", "failure_code": failure_code})
            if isinstance(exc, MarkingError):
                raise
            raise MarkingError(f"backend failed: {failure_code}") from exc

        with self._registry_lock:
            self._requests[request_id].update({
                "status": "success", "record": deepcopy(record), "artifact": deepcopy(artifact)
            })
            self._issued[context] = (
                request_program,
                int(unsigned["index"]),
                str(unsigned["parent"]),
                deepcopy(record),
                deepcopy(artifact),
            )
        if _return_chain:
            return deepcopy(parent_chain) + [record], artifact
        return deepcopy(record), artifact

    def _reconstruct_chain(self, context: str) -> list[dict[str, Any]]:
        """Reconstruct one successful lineage by following authenticated parents."""
        records: list[dict[str, Any]] = []
        current = context
        seen: set[str] = set()
        while current != GENESIS:
            if current in seen:
                raise ContextMarkError("terminal registry contains a parent cycle")
            seen.add(current)
            issued = self._issued.get(current)
            if issued is None:
                raise ContextMarkError("terminal registry is missing an ancestor")
            _, index, parent, record, _artifact = issued
            records.append(deepcopy(record))
            current = parent
            if len(records) > self.max_records:
                raise ContextMarkError("terminal registry lineage exceeds the record limit")
        records.reverse()
        if any(int(record["index"]) != index for index, record in enumerate(records)):
            raise ContextMarkError("terminal registry indices are inconsistent")
        return records

    def _require_registry_covers_chain(self, chain: list[dict[str, Any]], artifact: dict[str, Any] | None = None) -> None:
        if not chain:
            return
        with self._registry_lock:
            parent = GENESIS
            tip_artifact: dict[str, Any] | None = None
            for index, record in enumerate(chain):
                context = str(record.get("context"))
                issued = self._issued.get(context)
                if issued is None:
                    raise ContextMarkError(
                        "nonempty issuance requires live or restored terminal registry state covering the prefix"
                    )
                _, stored_index, stored_parent, stored_record, stored_artifact = issued
                if stored_index != index or stored_parent != parent or canonical_bytes(stored_record) != canonical_bytes(record):
                    raise ContextMarkError("accepted prefix does not match terminal issuance state")
                parent = context
                tip_artifact = stored_artifact
            if artifact is not None and (tip_artifact is None or canonical_bytes(tip_artifact) != canonical_bytes(artifact)):
                raise ContextMarkError("accepted tip artifact does not match terminal issuance state")

    def issue(
        self,
        parent_chain: list[dict[str, Any]],
        program: dict[str, Any],
        *,
        actor: str,
        operation: str,
        metadata: Mapping[str, Any] | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        if parent_chain:
            self.validate_chain(parent_chain)
            self._require_registry_covers_chain(parent_chain)
        return self._issue_from_validated_parent(
            parent_chain, program, actor=actor, operation=operation, metadata=metadata
        )

    def _verify_record(self, record: Mapping[str, Any], *, index: int, parent: str) -> str:
        if not isinstance(record, Mapping) or set(record) != RECORD_FIELDS:
            raise ContextMarkError("record has an invalid field set")
        if record.get("version") != RECORD_VERSION or record.get("chain_id") != self.chain_id:
            raise ContextMarkError("record version or chain identifier mismatch")
        if record.get("index") != index or record.get("parent") != parent:
            raise ContextMarkError("record index or parent mismatch")
        actor = record.get("actor")
        if not isinstance(actor, str) or actor not in self.actor_public_keys:
            raise ContextMarkError("actor is not authorized")
        context = record.get("context")
        signature = record.get("signature")
        if not isinstance(context, str) or len(context) != 64 or context != context.lower():
            raise ContextMarkError("context encoding is invalid")
        if not isinstance(signature, str) or len(signature) != 128 or signature != signature.lower():
            raise ContextMarkError("signature encoding is invalid")
        try:
            bytes.fromhex(context)
            signature_bytes = bytes.fromhex(signature)
        except ValueError as exc:
            raise ContextMarkError("record hexadecimal encoding is invalid") from exc
        unsigned = self._unsigned(record)
        if self._context_digest(unsigned) != context:
            raise ContextMarkError("context digest mismatch")
        try:
            self.actor_public_keys[actor].verify(signature_bytes, self._signature_message(unsigned, context))
        except InvalidSignature as exc:
            raise ContextMarkError("signature verification failed") from exc
        return context

    def validate_chain(self, chain: list[dict[str, Any]]) -> None:
        if not isinstance(chain, list) or not chain:
            raise ContextMarkError("chain must be a nonempty list")
        if len(chain) > self.max_records:
            raise ContextMarkError("record limit exceeded")
        parent = GENESIS
        for index, record in enumerate(chain):
            parent = self._verify_record(record, index=index, parent=parent)

    def verify_detailed(self, chain: Any, artifact: Any) -> VerificationResult:
        try:
            if not isinstance(chain, list) or not chain:
                raise ContextMarkError("chain must be a nonempty list")
            if not isinstance(artifact, dict):
                raise ContextMarkError("artifact must be an object")
            self.validate_chain(chain)
            tip = chain[-1]
            if self.binder(artifact) != tip["binder"]:
                raise ContextMarkError("tip binder mismatch")
            key = self.derive_watermark_key(str(tip["context"]))
            if self.backend.read(key, artifact) != tip["context"]:
                raise ContextMarkError("tip payload mismatch")
            return VerificationResult(True, "accepted")
        except (ContextMarkError, CanonicalizationError, TypeError, ValueError, RecursionError, RuntimeError) as exc:
            return VerificationResult(False, str(exc))

    def verify(self, chain: Any, artifact: Any) -> bool:
        return self.verify_detailed(chain, artifact).accepted

    def registry_status_counts(self) -> tuple[int, int, int]:
        with self._registry_lock:
            success = sum(state["status"] == "success" for state in self._requests.values())
            failed = sum(state["status"] == "failed" for state in self._requests.values())
            return success, failed, len(self._attempted_contexts)

    def _registry_tag(self, unsigned_snapshot: Mapping[str, Any]) -> str:
        return hmac.new(
            self.master_key,
            self._REGISTRY_TAG_DOMAIN + canonical_bytes(dict(unsigned_snapshot)),
            hashlib.sha256,
        ).hexdigest()

    def export_registry_snapshot(self) -> dict[str, Any]:
        with self._registry_lock:
            entries = []
            for request_id in sorted(self._requests):
                state = deepcopy(self._requests[request_id])
                if state["status"] == "pending":
                    raise ContextMarkError("cannot snapshot an in-progress request")
                entries.append({"request_id": request_id, **state})
            unsigned = {
                "version": self._REGISTRY_VERSION,
                "chain_id": self.chain_id,
                "entry_count": len(entries),
                "attempted_context_count": len(self._attempted_contexts),
                "attempted_contexts": sorted(self._attempted_contexts),
                "entries": entries,
            }
            return {**unsigned, "tag": self._registry_tag(unsigned)}

    def restore_registry_snapshot(self, snapshot: Mapping[str, Any]) -> None:
        try:
            self._restore_registry_snapshot(snapshot)
        except ContextMarkError:
            raise
        except (CanonicalizationError, KeyError, TypeError, ValueError, RecursionError, RuntimeError) as exc:
            raise ContextMarkError(f"registry snapshot validation failed: {exc}") from exc

    def _restore_registry_snapshot(self, snapshot: Mapping[str, Any]) -> None:
        required = {
            "version", "chain_id", "entry_count", "attempted_context_count",
            "attempted_contexts", "entries", "tag",
        }
        if not isinstance(snapshot, Mapping) or set(snapshot) != required:
            raise ContextMarkError("registry snapshot has an invalid field set")
        unsigned = {key: deepcopy(snapshot[key]) for key in required if key != "tag"}
        tag = snapshot.get("tag")
        if not isinstance(tag, str) or tag != self._registry_tag(unsigned):
            raise ContextMarkError("registry snapshot authentication failed")
        if unsigned["version"] != self._REGISTRY_VERSION or unsigned["chain_id"] != self.chain_id:
            raise ContextMarkError("registry snapshot version or chain identifier mismatch")
        entries, attempted = unsigned["entries"], unsigned["attempted_contexts"]
        if not isinstance(entries, list) or not isinstance(attempted, list):
            raise ContextMarkError("registry snapshot arrays are malformed")
        if (type(unsigned["entry_count"]) is not int or type(unsigned["attempted_context_count"]) is not int
                or unsigned["entry_count"] != len(entries) or unsigned["attempted_context_count"] != len(attempted)):
            raise ContextMarkError("registry snapshot count mismatch")
        if attempted != sorted(set(attempted)):
            raise ContextMarkError("attempted-context index is not canonical")
        if len(attempted) > self.max_contexts:
            raise ContextMarkError("registry snapshot exceeds the terminal attempt budget")

        requests: dict[str, dict[str, Any]] = {}
        context_owner: dict[str, str] = {}
        issued: dict[str, tuple[bytes, int, str, dict[str, Any], dict[str, Any]]] = {}
        previous = None
        for entry in entries:
            if not isinstance(entry, dict) or "request_id" not in entry:
                raise ContextMarkError("registry entry is malformed")
            request_id = entry.pop("request_id")
            if not isinstance(request_id, str) or len(request_id) != 64:
                raise ContextMarkError("registry request identifier is malformed")
            try:
                bytes.fromhex(request_id)
            except ValueError as exc:
                raise ContextMarkError("registry request identifier is not hexadecimal") from exc
            if previous is not None and request_id <= previous:
                raise ContextMarkError("registry entries are not in canonical order")
            previous = request_id
            status = entry.get("status")
            if status not in {"success", "failed"}:
                raise ContextMarkError("registry entry has a nonterminal status")
            context = entry.get("context")
            if not isinstance(context, str) or context not in attempted:
                raise ContextMarkError("registry entry is absent from the attempted-context index")
            if context in context_owner:
                raise ContextMarkError("registry context is owned by multiple requests")
            context_owner[context] = request_id
            program_hex = entry.get("request_program_hex")
            unsigned_record = entry.get("unsigned")
            if not isinstance(program_hex, str) or not isinstance(unsigned_record, dict):
                raise ContextMarkError("registry request state is malformed")
            try:
                program_bytes = bytes.fromhex(program_hex)
                program = json.loads(program_bytes)
            except ValueError as exc:
                raise ContextMarkError("registry program encoding is malformed") from exc
            if program_bytes.hex() != program_hex or canonical_bytes(program) != program_bytes or not isinstance(program, dict):
                raise ContextMarkError("registry request program is not canonical")
            if set(unsigned_record) != RECORD_FIELDS - {"context", "signature"}:
                raise ContextMarkError("registry unsigned record has an invalid field set")
            index, parent = unsigned_record["index"], unsigned_record["parent"]
            if type(index) is not int or not 0 <= index < self.max_records:
                raise ContextMarkError("registry record index is invalid")
            if not isinstance(parent, str) or ((index == 0) != (parent == GENESIS)):
                raise ContextMarkError("registry genesis/parent relation is invalid")
            if (unsigned_record["version"] != RECORD_VERSION or unsigned_record["chain_id"] != self.chain_id
                    or unsigned_record["actor"] not in self.actor_public_keys
                    or not isinstance(unsigned_record["operation"], str) or not unsigned_record["operation"]
                    or not isinstance(unsigned_record["metadata"], dict)):
                raise ContextMarkError("registry request language is invalid")
            if self.binder(program) != unsigned_record["binder"]:
                raise ContextMarkError("registry request binder does not match its program")
            if self._request_identifier(unsigned_record, program_bytes) != request_id:
                raise ContextMarkError("registry request identifier does not match its request")
            if self._context_digest(unsigned_record) != context:
                raise ContextMarkError("registry context does not match its unsigned record")
            if status == "success":
                if set(entry) != {
                    "status", "request_program_hex", "unsigned", "context", "record", "artifact"
                }:
                    raise ContextMarkError("successful registry entry has an invalid field set")
                record, artifact = entry["record"], entry["artifact"]
                if self._unsigned(record) != unsigned_record or record["context"] != context:
                    raise ContextMarkError("registry record does not match its request")
                self._verify_record(record, index=index, parent=parent)
                key = self.derive_watermark_key(context)
                if self.binder(artifact) != unsigned_record["binder"] or self.backend.read(key, artifact) != context:
                    raise ContextMarkError("successful registry artifact is not accepted")
                issued[context] = (
                    program_bytes, index, parent,
                    deepcopy(record), deepcopy(artifact),
                )
            else:
                if set(entry) != {
                    "status", "request_program_hex", "unsigned", "context", "failure_code"
                }:
                    raise ContextMarkError("failed registry entry has an invalid field set")
                if not isinstance(entry["failure_code"], str) or not entry["failure_code"]:
                    raise ContextMarkError("registry failure code is invalid")
            requests[request_id] = deepcopy(entry)
        if set(context_owner) != set(attempted):
            raise ContextMarkError("attempted-context index contains a missing or extra context")
        # A closed terminal transcript includes the successful predecessor of
        # every non-genesis attempt, including failed attempts after a tip.
        for entry in requests.values():
            index, parent = entry["unsigned"]["index"], entry["unsigned"]["parent"]
            if index and (parent not in issued or issued[parent][1] != index - 1):
                raise ContextMarkError("registry request is missing a successful predecessor")
        with self._registry_lock:
            if self._requests or self._attempted_contexts:
                raise ContextMarkError("registry restore requires an empty compiler")
            self._requests = requests
            self._context_owner = context_owner
            self._issued = issued
            self._attempted_contexts = set(attempted)

    def begin_session(
        self,
        program: dict[str, Any] | None = None,
        *,
        chain: list[dict[str, Any]] | None = None,
        artifact: dict[str, Any] | None = None,
    ) -> "ValidatedTipSession":
        return ValidatedTipSession(self, program=program, chain=chain, artifact=artifact)

    def serialize_manifest(self, chain: list[dict[str, Any]]) -> bytes:
        return canonical_bytes(chain)

    def serialize_artifact(self, artifact: dict[str, Any]) -> bytes:
        return canonical_bytes(artifact)


class ValidatedTipSession:
    """Serialized append session with incremental private state and durable continuity."""

    def __init__(
        self,
        compiler: ContextMarkCompiler,
        *,
        program: dict[str, Any] | None = None,
        chain: list[dict[str, Any]] | None = None,
        artifact: dict[str, Any] | None = None,
    ) -> None:
        self.compiler = compiler
        self._lock = threading.RLock()
        if chain is None and artifact is None:
            if program is None:
                raise ContextMarkError("a genesis session requires a program")
            self._chain: list[dict[str, Any]] = []
            self._artifact = deepcopy(program)
            return
        if chain is None or artifact is None:
            raise ContextMarkError("resume requires both chain and artifact")
        result = compiler.verify_detailed(chain, artifact)
        if not result.accepted:
            raise ContextMarkError(f"resume state is not accepted: {result.reason}")
        compiler._require_registry_covers_chain(chain, artifact)
        self._chain = deepcopy(chain)
        self._artifact = deepcopy(artifact)

    @property
    def current_parent_context(self) -> str:
        with self._lock:
            return str(self._chain[-1]["context"]) if self._chain else GENESIS

    def snapshot(self) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        with self._lock:
            return deepcopy(self._chain), deepcopy(self._artifact)

    def _append_incremental(
        self,
        *,
        actor: str,
        operation: str,
        metadata: Mapping[str, Any] | None,
        program: dict[str, Any] | None,
        expected_parent_context: str | None,
    ) -> tuple[dict[str, Any], dict[str, Any]]:
        current = self.current_parent_context
        expected = current if expected_parent_context is None else expected_parent_context
        if expected != current:
            raise ContextMarkError("stale session parent context")
        source = deepcopy(self._artifact if program is None else program)
        record, artifact = self.compiler._issue_from_validated_parent(
            self._chain,
            source,
            actor=actor,
            operation=operation,
            metadata=metadata,
            _return_chain=False,
        )
        self._chain.append(deepcopy(record))
        self._artifact = deepcopy(artifact)
        return deepcopy(record), deepcopy(artifact)

    def append_private(
        self,
        *,
        actor: str,
        operation: str,
        metadata: Mapping[str, Any] | None = None,
        program: dict[str, Any] | None = None,
        expected_parent_context: str | None = None,
    ) -> str:
        """Append without exporting the growing prefix; return only the new context."""
        with self._lock:
            record, _artifact = self._append_incremental(
                actor=actor,
                operation=operation,
                metadata=metadata,
                program=program,
                expected_parent_context=expected_parent_context,
            )
            return str(record["context"])

    def append(
        self,
        *,
        actor: str,
        operation: str,
        metadata: Mapping[str, Any] | None = None,
        program: dict[str, Any] | None = None,
        expected_parent_context: str | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Append and explicitly export a defensive copy of the complete state."""
        with self._lock:
            self._append_incremental(
                actor=actor,
                operation=operation,
                metadata=metadata,
                program=program,
                expected_parent_context=expected_parent_context,
            )
            return self.snapshot()


def make_demo_program(size: int = 96) -> dict[str, Any]:
    """Create a deterministic finite expression-program object."""
    body = []
    for index in range(size):
        body.append({
            "target": f"v{index:04d}",
            "op": "add" if index % 2 == 0 else "xor",
            "left": index,
            "right": (index * 17 + 3) % 257,
        })
    return {"language": "finite-expr-v1", "module": "demo", "body": body, "return": f"v{size-1:04d}"}
