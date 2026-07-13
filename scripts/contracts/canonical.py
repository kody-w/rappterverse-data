# SPDX-License-Identifier: Apache-2.0

"""Project canonical JSON v2.

This is a deliberately small project format, not an RFC 8785 implementation.
It accepts only JSON values without floating-point numbers, normalizes every
string and object key to NFC, sorts object keys, and emits compact UTF-8.
Stored JSON values and JSONL lines use ``stored=True`` to append one LF.
The root may contain at most 64 nested array/object containers.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Mapping
from typing import Any, Dict, List, Tuple, Union

CANONICALIZATION_V2 = "rappterverse-canonical-json/v2"
MAX_JSON_NESTING_DEPTH = 64


class CanonicalJSONV2Error(ValueError):
    """Raised when a value is outside the canonical JSON v2 domain."""


class CanonicalJSONV2DepthError(CanonicalJSONV2Error):
    """Raised when a value exceeds the deterministic nesting limit."""


def ensure_json_depth(
    value: Any, *, max_depth: int = MAX_JSON_NESTING_DEPTH
) -> None:
    """Reject values with more than ``max_depth`` nested containers."""

    stack = [(value, 0)]
    while stack:
        item, parent_depth = stack.pop()
        if isinstance(item, (list, tuple, Mapping)):
            depth = parent_depth + 1
            if depth > max_depth:
                raise CanonicalJSONV2DepthError(
                    "maximum JSON nesting depth {} exceeded".format(max_depth)
                )
            children = item.values() if isinstance(item, Mapping) else item
            stack.extend((child, depth) for child in children)


def _normalize(value: Any, path: str = "$") -> Any:
    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        raise CanonicalJSONV2Error(
            "{}: floating-point numbers are not allowed".format(path)
        )
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (list, tuple)):
        return [
            _normalize(item, "{}[{}]".format(path, index))
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        normalized: Dict[str, Any] = {}
        original_keys: Dict[str, str] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONV2Error(
                    "{}: object keys must be strings".format(path)
                )
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                raise CanonicalJSONV2Error(
                    "{}: object keys {!r} and {!r} collide after NFC normalization".format(
                        path, original_keys[normalized_key], key
                    )
                )
            original_keys[normalized_key] = key
            normalized[normalized_key] = _normalize(
                item, "{}.{}".format(path, normalized_key)
            )
        return normalized
    raise CanonicalJSONV2Error(
        "{}: unsupported JSON value type {}".format(path, type(value).__name__)
    )


def canonical_json_v2(value: Any, *, stored: bool = False) -> bytes:
    """Return canonical JSON v2 bytes, with one terminal LF when stored."""

    try:
        ensure_json_depth(value)
        normalized = _normalize(value)
    except RecursionError as exc:
        raise CanonicalJSONV2DepthError(
            "maximum JSON nesting depth {} exceeded".format(
                MAX_JSON_NESTING_DEPTH
            )
        ) from exc
    try:
        encoded = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8", errors="strict")
    except RecursionError as exc:
        raise CanonicalJSONV2DepthError(
            "maximum JSON nesting depth {} exceeded".format(
                MAX_JSON_NESTING_DEPTH
            )
        ) from exc
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise CanonicalJSONV2Error(
            "value is not strict UTF-8 JSON: {}".format(exc)
        ) from exc
    return encoded + (b"\n" if stored else b"")


def _reject_float(token: str) -> None:
    raise CanonicalJSONV2Error(
        "floating-point number token {!r} is not allowed".format(token)
    )


def _reject_constant(token: str) -> None:
    raise CanonicalJSONV2Error(
        "non-finite number token {!r} is not JSON".format(token)
    )


def _object_pairs(pairs: List[Tuple[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise CanonicalJSONV2Error("duplicate object key {!r}".format(key))
        value[key] = item
    return value


def parse_json_v2(data: Union[bytes, str]) -> Any:
    """Parse strict UTF-8 JSON in the canonical v2 value domain.

    Parsing does not require the source bytes themselves to be canonical.
    Callers validating stored artifacts compare against
    ``canonical_json_v2(value, stored=True)``.
    """

    try:
        text = (
            data.decode("utf-8", errors="strict")
            if isinstance(data, bytes)
            else data
        )
    except UnicodeDecodeError as exc:
        raise CanonicalJSONV2Error("input is not valid UTF-8") from exc
    if not isinstance(text, str):
        raise CanonicalJSONV2Error("input must be bytes or text")
    if text.startswith("\ufeff"):
        raise CanonicalJSONV2Error("UTF-8 BOM is not allowed")
    try:
        value = json.loads(
            text,
            object_pairs_hook=_object_pairs,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except CanonicalJSONV2Error:
        raise
    except RecursionError as exc:
        raise CanonicalJSONV2DepthError(
            "maximum JSON nesting depth {} exceeded".format(
                MAX_JSON_NESTING_DEPTH
            )
        ) from exc
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CanonicalJSONV2Error("input is not strict JSON") from exc
    try:
        ensure_json_depth(value)
        normalized = _normalize(value)
    except RecursionError as exc:
        raise CanonicalJSONV2DepthError(
            "maximum JSON nesting depth {} exceeded".format(
                MAX_JSON_NESTING_DEPTH
            )
        ) from exc
    canonical_json_v2(normalized)
    return normalized
