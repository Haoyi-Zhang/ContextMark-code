"""Canonical JSON and application binder utilities."""
from __future__ import annotations

import hashlib
import json
import math
from copy import deepcopy
from typing import Any


class CanonicalizationError(ValueError):
    """Raised when an object is outside the canonical JSON language."""


def _validate(value: Any, *, depth: int = 0) -> None:
    if depth > 64:
        raise CanonicalizationError("maximum nesting depth exceeded")
    if value is None or isinstance(value, (bool, str, int)):
        if isinstance(value, int) and not (-(1 << 63) <= value < (1 << 63)):
            raise CanonicalizationError("integer is outside the signed 64-bit range")
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalizationError("non-finite numbers are not canonical")
        raise CanonicalizationError("floating-point numbers are excluded")
    if isinstance(value, list):
        for item in value:
            _validate(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalizationError("mapping keys must be strings")
            _validate(item, depth=depth + 1)
        return
    raise CanonicalizationError(f"unsupported canonical type: {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    """Return the unique UTF-8 JSON encoding of ``value``."""
    _validate(value)
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError) as exc:
        raise CanonicalizationError(str(exc)) from exc


def without_watermark(program: dict[str, Any]) -> dict[str, Any]:
    """Remove the two reference watermark carriers from one program object."""
    if not isinstance(program, dict):
        raise CanonicalizationError("program must be an object")
    clean = deepcopy(program)
    clean.pop("_contextmark", None)
    clean.pop("_threshold_carriers", None)
    return clean


def expression_binder(program: dict[str, Any]) -> str:
    """Bind the canonical program while ignoring reference carriers."""
    return hashlib.sha256(canonical_bytes(without_watermark(program))).hexdigest()
