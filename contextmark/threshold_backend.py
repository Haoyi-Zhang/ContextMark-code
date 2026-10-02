"""Finite authenticated threshold carrier used as a positive contract witness."""
from __future__ import annotations

import hashlib
import hmac
from copy import deepcopy
from typing import Any

from .canonical import CanonicalizationError, canonical_bytes, without_watermark

P = (1 << 521) - 1
PAYLOAD_BYTES = 32
CARRIER_FIELD = "_threshold_carriers"


class ThresholdCarrierError(ValueError):
    pass


def _inv(value: int) -> int:
    return pow(value % P, P - 2, P)


def _eval(coefficients: list[int], x: int) -> int:
    total = 0
    for coefficient in reversed(coefficients):
        total = (total * x + coefficient) % P
    return total


def _interpolation_weights(points: list[tuple[int, int]]) -> list[int]:
    """Lagrange denominators, computed once for a distinct-position basis."""
    xs = [x for x, _ in points]
    if len(set(xs)) != len(xs):
        raise ThresholdCarrierError("duplicate interpolation position")
    weights = []
    for i, xi in enumerate(xs):
        denominator = 1
        for j, xj in enumerate(xs):
            if i != j:
                denominator = denominator * (xi - xj) % P
        weights.append(_inv(denominator))
    return weights


def _evaluate_interpolant(points: list[tuple[int, int]], weights: list[int], x: int) -> int:
    """Evaluate a fixed basis in linear field operations, with no new inversions."""
    for xi, yi in points:
        if x == xi:
            return yi % P
    differences = [(x - xi) % P for xi, _ in points]
    prefix = [1]
    for value in differences:
        prefix.append(prefix[-1] * value % P)
    suffix = 1
    total = 0
    for i in range(len(points) - 1, -1, -1):
        total = (total + points[i][1] * weights[i] * prefix[i] * suffix) % P
        suffix = suffix * differences[i] % P
    return total


def _interpolate(points: list[tuple[int, int]], x: int = 0) -> int:
    return _evaluate_interpolant(points, _interpolation_weights(points), x)


def _commit(payload: bytes) -> str:
    return hashlib.sha256(b"contextmark/threshold/commit/v1\0" + payload).hexdigest()


def payload_commitment(payload: bytes) -> str:
    """Return the public commitment used to canonically order payload groups."""
    if not isinstance(payload, bytes) or len(payload) != PAYLOAD_BYTES:
        raise ThresholdCarrierError("payload must contain exactly 32 bytes")
    return _commit(payload)


def binder(program: dict[str, Any]) -> str:
    clean = without_watermark(program)
    clean.pop(CARRIER_FIELD, None)
    return hashlib.sha256(canonical_bytes(clean)).hexdigest()


def _tag(key: bytes, host_binder: str, commitment: str, index: int, value: int, n: int, t: int) -> str:
    message = b"contextmark/threshold/tag/v1\0" + canonical_bytes({
        "binder": host_binder,
        "commitment": commitment,
        "index": index,
        "value": format(value, "x"),
        "n": n,
        "t": t,
    })
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def _coefficients(key: bytes, payload: bytes, t: int) -> list[int]:
    coefficients = [int.from_bytes(payload, "big")]
    for index in range(1, t):
        material = hmac.new(
            key,
            b"contextmark/threshold/coefficient/v1\0" + payload + index.to_bytes(4, "big"),
            hashlib.sha512,
        ).digest()
        coefficients.append(int.from_bytes(material, "big") % P)
    return coefficients


def mark(key: bytes, program: dict[str, Any], payload: bytes, *, n: int = 5, t: int = 3) -> dict[str, Any]:
    if not isinstance(payload, bytes) or len(payload) != PAYLOAD_BYTES:
        raise ThresholdCarrierError("payload must contain exactly 32 bytes")
    if type(n) is not int or type(t) is not int or not (2 <= t <= n <= 32):
        raise ThresholdCarrierError("threshold parameters are outside the finite instance")
    canonical_bytes(program)
    host = binder(program)
    commitment = _commit(payload)
    coefficients = _coefficients(key, payload, t)
    carriers = []
    for index in range(1, n + 1):
        value = _eval(coefficients, index)
        carriers.append({
            "version": "threshold-carrier-v1",
            "commitment": commitment,
            "index": index,
            "value": format(value, "x"),
            "n": n,
            "t": t,
            "tag": _tag(key, host, commitment, index, value, n, t),
        })
    artifact = deepcopy(program)
    existing = artifact.get(CARRIER_FIELD, [])
    if existing is None:
        existing = []
    if not isinstance(existing, list):
        raise ThresholdCarrierError("existing carrier field is not a list")
    artifact[CARRIER_FIELD] = deepcopy(existing) + carriers
    return artifact


def _valid_carriers(key: bytes, program: dict[str, Any]) -> list[dict[str, Any]]:
    if not isinstance(program, dict):
        return []
    carriers = program.get(CARRIER_FIELD)
    if not isinstance(carriers, list):
        return []
    host = binder(program)
    valid = []
    seen_slots: set[tuple[str, int, int, int]] = set()
    for carrier in carriers:
        try:
            if not isinstance(carrier, dict) or set(carrier) != {
                "version", "commitment", "index", "value", "n", "t", "tag"
            }:
                continue
            if carrier["version"] != "threshold-carrier-v1":
                continue
            commitment, tag = carrier["commitment"], carrier["tag"]
            index, n, t = carrier["index"], carrier["n"], carrier["t"]
            if not isinstance(commitment, str) or len(commitment) != 64 or commitment != commitment.lower():
                continue
            if not isinstance(tag, str) or len(tag) != 64 or tag != tag.lower():
                continue
            if type(index) is not int or type(n) is not int or type(t) is not int or not (1 <= index <= n <= 32 and 2 <= t <= n):
                continue
            encoded_value = carrier["value"]
            if not isinstance(encoded_value, str) or not 1 <= len(encoded_value) <= 131:
                continue
            value = int(encoded_value, 16)
            if not 0 <= value < P or format(value, "x") != encoded_value:
                continue
            if bytes.fromhex(commitment).hex() != commitment or bytes.fromhex(tag).hex() != tag:
                continue
            slot = (commitment, n, t, index)
            if slot in seen_slots:
                continue
            expected = _tag(key, host, commitment, index, value, n, t)
            if not hmac.compare_digest(tag, expected):
                continue
            seen_slots.add(slot)
            valid.append(deepcopy(carrier))
        except (ValueError, TypeError):
            continue
    return valid


def read_candidates(key: bytes, program: dict[str, Any]) -> list[tuple[str, bytes]]:
    groups: dict[tuple[str, int, int], list[dict[str, Any]]] = {}
    try:
        canonical_bytes(program)
        carriers = _valid_carriers(key, program)
    except (CanonicalizationError, TypeError, ValueError, RecursionError):
        return []
    for carrier in carriers:
        groups.setdefault((carrier["commitment"], carrier["n"], carrier["t"]), []).append(carrier)
    candidates: list[tuple[str, bytes]] = []
    for (commitment, _n, t), carriers in groups.items():
        carriers.sort(key=lambda c: c["index"])
        if len(carriers) < t:
            continue
        points = [(c["index"], int(c["value"], 16)) for c in carriers[:t]]
        weights = _interpolation_weights(points)
        secret = _evaluate_interpolant(points, weights, 0)
        if secret >= (1 << (PAYLOAD_BYTES * 8)):
            continue
        payload = secret.to_bytes(PAYLOAD_BYTES, "big")
        if _commit(payload) != commitment:
            continue
        # One fixed basis plus residual checks is equivalent to checking all
        # t-subsets, but avoids binomially many reconstructions.  The proof and
        # exhaustive small-field differential tests are supplied with the paper.
        if all(
            _evaluate_interpolant(points, weights, c["index"]) == int(c["value"], 16)
            for c in carriers[t:]
        ):
            candidates.append((commitment, payload))
    candidates.sort(key=lambda item: item[0])
    return candidates


def read(key: bytes, program: dict[str, Any]) -> bytes | None:
    """Return one canonical contributor payload, or ``None``.

    For a single issued group this is its exact payload.  With several
    threshold-reaching groups under the same key, :func:`read_candidates`
    exposes the complete candidate set and this function returns only the
    payload whose commitment is lexicographically smallest.  It must not be
    interpreted as recovering every contributor through one scalar return.
    """
    candidates = read_candidates(key, program)
    return candidates[0][1] if candidates else None


def trace_context_payloads(
    context_keys: list[tuple[str, bytes]],
    program: dict[str, Any],
) -> list[str]:
    """Return compiler contexts whose own key recovers their exact tip payload.

    ``context_keys`` is the executable part of a compiled coalition pattern:
    each context is a signed-tip digest and each key is the compiler key derived
    for that context.  Signature validity is checked by the caller because this
    backend intentionally has no dependency on the compiler module.
    """
    traced: list[str] = []
    for context, key in context_keys:
        if not isinstance(context, str) or len(context) != 64 or context != context.lower():
            raise ThresholdCarrierError("context is not canonical lowercase hexadecimal")
        try:
            payload = bytes.fromhex(context)
        except ValueError as exc:
            raise ThresholdCarrierError("context is not hexadecimal") from exc
        if len(payload) != PAYLOAD_BYTES:
            raise ThresholdCarrierError("context payload has the wrong length")
        if read(key, program) == payload:
            traced.append(context)
    return sorted(set(traced))


def public_authorized_derivative(issued: dict[str, Any], candidate: dict[str, Any], *, threshold: int) -> bool:
    """Public retention closure: retain one issued group at its frozen threshold.

    Repetition and arbitrary canonical carrier noise are permitted but never
    count toward the threshold.  This matches a reader that ignores invalid
    carriers.  Exact byte membership is checked without a key or reader call.
    The theorem's origin clause uses a single issued payload group.  With several
    groups this predicate is their public union, not a new multi-origin theorem.
    """
    if not isinstance(issued, dict) or not isinstance(candidate, dict):
        return False
    if type(threshold) is not int or not 2 <= threshold <= 32:
        return False
    try:
        canonical_bytes(issued)
        canonical_bytes(candidate)
        if binder(issued) != binder(candidate):
            return False
        issued_carriers = issued.get(CARRIER_FIELD)
        candidate_carriers = candidate.get(CARRIER_FIELD)
        if not isinstance(issued_carriers, list) or not isinstance(candidate_carriers, list):
            return False
        issued_positions = {}
        for c in issued_carriers:
            if isinstance(c, dict) and type(c.get("index")) is int and type(c.get("n")) is int and type(c.get("t")) is int:
                if c["t"] == threshold and 1 <= c["index"] <= c["n"] <= 32 and threshold <= c["n"] and isinstance(c.get("commitment"), str):
                    issued_positions[canonical_bytes(c)] = ((c["commitment"], c["n"], c["t"]), c["index"])
        retained: dict[tuple[str, int, int], set[int]] = {}
        for c in candidate_carriers:
            position = issued_positions.get(canonical_bytes(c))
            if position is not None:
                group, index = position
                retained.setdefault(group, set()).add(index)
        return any(len(indices) >= threshold for indices in retained.values())
    except (CanonicalizationError, TypeError, ValueError, RecursionError):
        return False


class ThresholdCarrierAdapter:
    def __init__(self, *, n: int = 5, t: int = 3) -> None:
        if type(n) is not int or type(t) is not int or not (2 <= t <= n <= 32):
            raise ThresholdCarrierError("invalid threshold")
        self.n, self.t = n, t

    def mark(self, key: bytes, program: dict[str, Any], payload: str) -> dict[str, Any]:
        if not isinstance(payload, str) or len(payload) != 64 or payload != payload.lower():
            raise ThresholdCarrierError("payload is not canonical hexadecimal")
        try:
            raw = bytes.fromhex(payload)
        except ValueError as exc:
            raise ThresholdCarrierError("payload is not hexadecimal") from exc
        return mark(key, program, raw, n=self.n, t=self.t)

    def read(self, key: bytes, artifact: dict[str, Any]) -> str | None:
        payload = read(key, artifact)
        return payload.hex() if payload is not None else None
