"""Canonical JSON and JSONL primitives used by the public data lake."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import math
import re
import unicodedata
from collections.abc import Iterable, Mapping
from typing import Any

CANONICALIZATION = "rappterverse-canonical-json/v1"


class CanonicalJSONError(ValueError):
    """Raised when a value cannot be represented as canonical JSON."""


_CONTENT_KIND_RE = re.compile(r"^[a-z][a-z0-9-]{1,40}$")


def normalize_json(value: Any, *, _path: str = "$") -> Any:
    """Return a JSON value with all strings normalized to Unicode NFC.

    Mapping keys must be strings. If two distinct source keys normalize to the
    same key, the input is rejected rather than silently losing data.
    """

    if value is None or isinstance(value, (bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise CanonicalJSONError(f"{_path}: non-finite numbers are not JSON")
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value)
    if isinstance(value, (list, tuple)):
        return [
            normalize_json(item, _path=f"{_path}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        normalized: dict[str, Any] = {}
        source_keys: dict[str, str] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise CanonicalJSONError(
                    f"{_path}: object key {key!r} is not a string"
                )
            normalized_key = unicodedata.normalize("NFC", key)
            if normalized_key in normalized:
                first = source_keys[normalized_key]
                raise CanonicalJSONError(
                    f"{_path}: keys {first!r} and {key!r} normalize to "
                    f"{normalized_key!r}"
                )
            source_keys[normalized_key] = key
            normalized[normalized_key] = normalize_json(
                item, _path=f"{_path}.{normalized_key}"
            )
        return normalized
    raise CanonicalJSONError(
        f"{_path}: unsupported JSON value of type {type(value).__name__}"
    )


def canonical_json_bytes(value: Any) -> bytes:
    """Encode one value as compact, key-sorted, NFC-normalized UTF-8 JSON."""

    normalized = normalize_json(value)
    try:
        text = json.dumps(
            normalized,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        return text.encode("utf-8", errors="strict")
    except (TypeError, UnicodeEncodeError, ValueError) as exc:
        raise CanonicalJSONError(f"value is not canonical UTF-8 JSON: {exc}") from exc


def canonical_jsonl_line(value: Any) -> bytes:
    """Encode one canonical JSONL line, including its terminating LF."""

    return canonical_json_bytes(value) + b"\n"


def canonical_jsonl_bytes(values: Iterable[Any]) -> bytes:
    """Encode an iterable as canonical raw JSONL."""

    return b"".join(canonical_jsonl_line(value) for value in values)


def _reject_constant(token: str) -> None:
    raise CanonicalJSONError(f"non-finite number token {token!r} is not JSON")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CanonicalJSONError(f"duplicate object key {key!r}")
        result[key] = value
    return result


def canonical_loads(data: bytes | str) -> Any:
    """Parse UTF-8 JSON and return its NFC-normalized JSON value."""

    try:
        text = data.decode("utf-8", errors="strict") if isinstance(data, bytes) else data
    except UnicodeDecodeError as exc:
        raise CanonicalJSONError(f"input is not valid UTF-8: {exc}") from exc
    try:
        value = json.loads(
            text,
            parse_constant=_reject_constant,
            object_pairs_hook=_reject_duplicate_keys,
        )
    except CanonicalJSONError:
        raise
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        raise CanonicalJSONError(f"input is not valid JSON: {exc}") from exc
    normalized = normalize_json(value)
    canonical_json_bytes(normalized)
    return normalized


def sha256_hex(data: bytes) -> str:
    """Return the lowercase SHA-256 digest of *data*."""

    return hashlib.sha256(data).hexdigest()


def sha256_digest(data: bytes) -> str:
    """Return a schema-compatible, algorithm-qualified SHA-256 digest."""

    return f"sha256:{sha256_hex(data)}"


def content_id(value: Any, *, kind: str = "record") -> str:
    """Return a deterministic content-addressed identifier for one JSON value."""

    if not _CONTENT_KIND_RE.fullmatch(kind):
        raise CanonicalJSONError(f"invalid content kind {kind!r}")
    return f"urn:rappterverse:{kind}:{sha256_digest(canonical_json_bytes(value))}"


def content_hash(values: Iterable[Any]) -> str:
    """Hash a canonical logical JSONL stream independent of shard layout."""

    digest = hashlib.sha256()
    for value in values:
        digest.update(canonical_jsonl_line(value))
    return f"sha256:{digest.hexdigest()}"


def deterministic_gzip(data: bytes, *, compresslevel: int = 9) -> bytes:
    """Return deterministic gzip bytes with no filename and an mtime of zero."""

    if not 0 <= compresslevel <= 9:
        raise ValueError("compresslevel must be between 0 and 9")
    buffer = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=compresslevel,
        fileobj=buffer,
        mtime=0,
    ) as stream:
        stream.write(data)
    return buffer.getvalue()
