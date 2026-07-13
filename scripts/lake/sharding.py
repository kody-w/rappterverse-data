"""Deterministic size-bounded sharding for canonical JSONL datasets."""

from __future__ import annotations

import hashlib
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import (
    CANONICALIZATION,
    canonical_json_bytes,
    canonical_jsonl_line,
    content_id,
    normalize_json,
    sha256_digest,
)

DEFAULT_TARGET_BYTES = 768_000
DEFAULT_HARD_CAP_BYTES = 1_000_000
DEFAULT_LINE_CAP_BYTES = 262_144
DEFAULT_FRAGMENT_TARGET_BYTES = 128_000

SHARD_TARGET_BYTES = DEFAULT_TARGET_BYTES
SHARD_HARD_CAP_BYTES = DEFAULT_HARD_CAP_BYTES
LINE_MAX_BYTES = DEFAULT_LINE_CAP_BYTES
FRAGMENT_TARGET_BYTES = DEFAULT_FRAGMENT_TARGET_BYTES

MANIFEST_SCHEMA = "rappterverse.canonical-shards/v1"
FRAGMENT_SCHEMA = "rappterverse.artifact-fragment/v1"
SHARD_PREFIX = "part-"
_ARTIFACT_KINDS = {
    "records",
    "transcripts",
    "deliberations",
    "provider-reasoning",
    "world-pack-sources",
}
_DIGEST_RE = re.compile(r"^sha256:[a-f0-9]{64}$")
_STABLE_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9._:/-]{0,255}$")
_OBJECT_PATH_RE = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9._/-]+$")


class ShardingError(ValueError):
    """Raised when records cannot satisfy the configured shard invariants."""


@dataclass(frozen=True)
class _LogicalRecord:
    key: Any
    key_bytes: bytes
    body: bytes
    line: bytes
    content_id: str


@dataclass(frozen=True)
class _PhysicalLine:
    data: bytes
    key: Any
    logical_start: bool


@dataclass(frozen=True)
class Shard:
    """One planned raw canonical JSONL shard."""

    index: int
    path: str
    data: bytes
    records: int
    logical_records: int
    min_key: Any
    max_key: Any
    sha256: str

    @property
    def bytes(self) -> int:
        return len(self.data)

    def manifest_entry(self) -> dict[str, Any]:
        return {
            "bytes": self.bytes,
            "index": self.index,
            "logicalRecords": self.logical_records,
            "maxKey": self.max_key,
            "minKey": self.min_key,
            "path": self.path,
            "records": self.records,
            "sha256": self.sha256,
        }

    @property
    def max_line_bytes(self) -> int:
        return max(len(body) + 1 for body in self.data[:-1].split(b"\n"))

    def descriptor(
        self,
        *,
        artifact_kind: str,
        review_receipt_ref: str,
        path: str | None = None,
    ) -> dict[str, Any]:
        """Return a public shard descriptor compatible with the v1 contracts."""

        if artifact_kind not in _ARTIFACT_KINDS:
            raise ShardingError(f"unsupported artifact kind {artifact_kind!r}")
        if not _DIGEST_RE.fullmatch(self.sha256):
            raise ShardingError("shard sha256 must be a SHA-256 digest")
        if not _DIGEST_RE.fullmatch(review_receipt_ref):
            raise ShardingError("review_receipt_ref must be a SHA-256 digest")
        if (
            not isinstance(self.min_key, str)
            or not _STABLE_KEY_RE.fullmatch(self.min_key)
            or not isinstance(self.max_key, str)
            or not _STABLE_KEY_RE.fullmatch(self.max_key)
        ):
            raise ShardingError("public shard descriptor keys must be strings")
        digest_hex = self.sha256.removeprefix("sha256:")
        object_path = path or (
            f"objects/{artifact_kind}/sha256/{digest_hex[:2]}/{digest_hex}.jsonl"
        )
        if len(object_path) > 512 or not _OBJECT_PATH_RE.fullmatch(object_path):
            raise ShardingError("path is not a valid public object path")
        return {
            "artifactKind": artifact_kind,
            "byteSize": self.bytes,
            "contentAddressed": True,
            "firstItemId": self.min_key,
            "itemCount": self.records,
            "lastItemId": self.max_key,
            "maxFragmentBytes": self.max_line_bytes,
            "mediaType": "application/x-ndjson",
            "path": object_path,
            "reviewReceiptRef": review_receipt_ref,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class ShardPlan:
    """A complete deterministic shard layout and its manifest."""

    shards: tuple[Shard, ...]
    manifest: dict[str, Any]

    @property
    def files(self) -> dict[str, bytes]:
        files = {shard.path: shard.data for shard in self.shards}
        files["manifest.json"] = canonical_jsonl_line(self.manifest)
        return files


def _positive_int(name: str, value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ShardingError(f"{name} must be a positive integer")
    return value


def _validate_limits(
    target_bytes: int,
    hard_cap_bytes: int,
    line_cap_bytes: int,
    fragment_target_bytes: int,
) -> None:
    _positive_int("target_bytes", target_bytes)
    _positive_int("hard_cap_bytes", hard_cap_bytes)
    _positive_int("line_cap_bytes", line_cap_bytes)
    _positive_int("fragment_target_bytes", fragment_target_bytes)
    if target_bytes > hard_cap_bytes:
        raise ShardingError("target_bytes cannot exceed hard_cap_bytes")
    if hard_cap_bytes > DEFAULT_HARD_CAP_BYTES:
        raise ShardingError(
            f"hard_cap_bytes cannot exceed {DEFAULT_HARD_CAP_BYTES}"
        )
    if line_cap_bytes > hard_cap_bytes:
        raise ShardingError("line_cap_bytes cannot exceed hard_cap_bytes")
    if line_cap_bytes > DEFAULT_LINE_CAP_BYTES:
        raise ShardingError(
            f"line_cap_bytes cannot exceed {DEFAULT_LINE_CAP_BYTES}"
        )
    if fragment_target_bytes > line_cap_bytes:
        raise ShardingError("fragment_target_bytes cannot exceed line_cap_bytes")


def _path_parts(key_path: str) -> tuple[str, ...]:
    if key_path.startswith("/"):
        return tuple(
            part.replace("~1", "/").replace("~0", "~")
            for part in key_path[1:].split("/")
            if part
        )
    if key_path.startswith("$."):
        key_path = key_path[2:]
    return tuple(part for part in key_path.split(".") if part)


def extract_key(record: Any, key_path: str) -> Any:
    """Extract a normalized sort key using dotted syntax or a JSON pointer."""

    if not isinstance(key_path, str) or not key_path:
        raise ShardingError("key_path must be a non-empty string")
    current = record
    for part in _path_parts(key_path):
        if isinstance(current, Mapping):
            if part not in current:
                raise ShardingError(f"record is missing key path {key_path!r}")
            current = current[part]
        elif isinstance(current, Sequence) and not isinstance(
            current, (str, bytes, bytearray)
        ):
            try:
                index = int(part)
                current = current[index]
            except (ValueError, IndexError) as exc:
                raise ShardingError(
                    f"record is missing key path {key_path!r}"
                ) from exc
        else:
            raise ShardingError(f"record is missing key path {key_path!r}")
    return normalize_json(current)


def _prepare_records(
    records: Iterable[Any], key_path: str | None
) -> list[_LogicalRecord]:
    prepared: list[_LogicalRecord] = []
    for record in records:
        normalized = normalize_json(record)
        if (
            isinstance(normalized, Mapping)
            and normalized.get("schemaVersion") == FRAGMENT_SCHEMA
        ):
            raise ShardingError(f"{FRAGMENT_SCHEMA!r} is reserved for shard fragments")
        body = canonical_json_bytes(normalized)
        record_id = content_id(normalized)
        key = record_id if key_path is None else extract_key(normalized, key_path)
        prepared.append(
            _LogicalRecord(
                key=key,
                key_bytes=canonical_json_bytes(key),
                body=body,
                line=body + b"\n",
                content_id=record_id,
            )
        )
    prepared.sort(key=lambda item: (item.key_bytes, item.body))
    return prepared


def _fragment_body(
    *,
    chunk: str,
    content_id: str,
    count: int,
    index: int,
    previous: str | None,
) -> bytes:
    chunk_bytes = chunk.encode("utf-8")
    envelope = {
        "artifactId": content_id,
        "artifactKind": "record",
        "count": count,
        "data": chunk,
        "encoding": "utf-8",
        "index": index,
        "mediaType": "application/json",
        "previousFragmentSha256": previous,
        "schemaVersion": FRAGMENT_SCHEMA,
        "sha256": sha256_digest(chunk_bytes),
        "utf8Bytes": len(chunk_bytes),
    }
    return canonical_json_bytes(envelope)


def _split_payload_for_count(
    record: _LogicalRecord,
    count: int,
    line_cap_bytes: int,
    fragment_target_bytes: int,
) -> list[_PhysicalLine]:
    lines: list[_PhysicalLine] = []
    payload = record.body.decode("utf-8")
    offset = 0
    previous: str | None = None

    while offset < len(payload):
        index = len(lines)
        remaining = len(payload) - offset
        low = 1
        high = remaining
        best_size = 0
        best_body: bytes | None = None
        best_digest: str | None = None

        while low <= high:
            size = (low + high) // 2
            chunk = payload[offset : offset + size]
            chunk_bytes = chunk.encode("utf-8")
            body = _fragment_body(
                chunk=chunk,
                content_id=record.content_id,
                count=count,
                index=index,
                previous=previous,
            )
            if (
                len(chunk_bytes) <= fragment_target_bytes
                and len(body) + 1 <= line_cap_bytes
            ):
                best_size = size
                best_body = body
                best_digest = sha256_digest(chunk_bytes)
                low = size + 1
            else:
                high = size - 1

        if best_body is None or best_digest is None:
            raise ShardingError(
                "line_cap_bytes is too small for the fragment envelope"
            )

        lines.append(
            _PhysicalLine(
                data=best_body + b"\n",
                key=record.key,
                logical_start=index == 0,
            )
        )
        offset += best_size
        previous = best_digest

    return lines


def _fragment_record(
    record: _LogicalRecord, line_cap_bytes: int, fragment_target_bytes: int
) -> list[_PhysicalLine]:
    count = 1
    for _ in range(64):
        lines = _split_payload_for_count(
            record, count, line_cap_bytes, fragment_target_bytes
        )
        actual_count = len(lines)
        if actual_count == count:
            return lines
        count = actual_count
    raise ShardingError("fragment count did not converge")


def _physical_lines(
    records: list[_LogicalRecord],
    line_cap_bytes: int,
    fragment_target_bytes: int,
) -> list[_PhysicalLine]:
    lines: list[_PhysicalLine] = []
    for record in records:
        if len(record.line) <= line_cap_bytes:
            lines.append(
                _PhysicalLine(
                    data=record.line,
                    key=record.key,
                    logical_start=True,
                )
            )
        else:
            lines.extend(
                _fragment_record(record, line_cap_bytes, fragment_target_bytes)
            )
    return lines


def _split_index(lines: list[_PhysicalLine]) -> int:
    total = sum(len(line.data) for line in lines)
    running = 0
    best_index = 1
    best_distance: int | None = None
    for index in range(1, len(lines)):
        running += len(lines[index - 1].data)
        distance = abs(total - 2 * running)
        if best_distance is None or distance < best_distance:
            best_index = index
            best_distance = distance
    return best_index


def _recursive_groups(
    lines: list[_PhysicalLine], target_bytes: int, hard_cap_bytes: int
) -> list[list[_PhysicalLine]]:
    total = sum(len(line.data) for line in lines)
    if total <= target_bytes:
        return [lines]
    if len(lines) == 1:
        if total > hard_cap_bytes:
            raise ShardingError(
                f"single physical line is {total} bytes, above hard cap "
                f"{hard_cap_bytes}"
            )
        return [lines]
    pivot = _split_index(lines)
    return _recursive_groups(
        lines[:pivot], target_bytes, hard_cap_bytes
    ) + _recursive_groups(lines[pivot:], target_bytes, hard_cap_bytes)


def _build_shards(
    lines: list[_PhysicalLine], target_bytes: int, hard_cap_bytes: int
) -> tuple[Shard, ...]:
    if not lines:
        return ()
    groups = _recursive_groups(lines, target_bytes, hard_cap_bytes)
    shards: list[Shard] = []
    for index, group in enumerate(groups):
        data = b"".join(line.data for line in group)
        if len(data) > hard_cap_bytes:
            raise ShardingError(
                f"planned shard {index} is {len(data)} bytes, above hard cap "
                f"{hard_cap_bytes}"
            )
        shards.append(
            Shard(
                index=index,
                path=f"{SHARD_PREFIX}{index:05d}.jsonl",
                data=data,
                records=len(group),
                logical_records=sum(line.logical_start for line in group),
                min_key=group[0].key,
                max_key=group[-1].key,
                sha256=sha256_digest(data),
            )
        )
    return tuple(shards)


def plan_shards(
    records: Iterable[Any],
    *,
    key_path: str | None = "id",
    target_bytes: int = DEFAULT_TARGET_BYTES,
    hard_cap_bytes: int = DEFAULT_HARD_CAP_BYTES,
    line_cap_bytes: int = DEFAULT_LINE_CAP_BYTES,
    fragment_target_bytes: int | None = None,
) -> ShardPlan:
    """Canonicalize, sort, fragment, and recursively split logical records."""

    if fragment_target_bytes is None:
        fragment_target_bytes = min(DEFAULT_FRAGMENT_TARGET_BYTES, line_cap_bytes)
    _validate_limits(
        target_bytes, hard_cap_bytes, line_cap_bytes, fragment_target_bytes
    )
    prepared = _prepare_records(records, key_path)
    digest = hashlib.sha256()
    canonical_bytes = 0
    for record in prepared:
        digest.update(record.line)
        canonical_bytes += len(record.line)

    lines = _physical_lines(prepared, line_cap_bytes, fragment_target_bytes)
    shards = _build_shards(lines, target_bytes, hard_cap_bytes)
    layout_bytes = sum(shard.bytes for shard in shards)
    manifest = {
        "canonicalBytes": canonical_bytes,
        "canonicalization": CANONICALIZATION,
        "compression": "none",
        "contentHash": f"sha256:{digest.hexdigest()}",
        "encoding": "utf-8",
        "fragmentTargetBytes": fragment_target_bytes,
        "keyPath": key_path,
        "layoutBytes": layout_bytes,
        "lineMaxBytes": line_cap_bytes,
        "lines": len(lines),
        "records": len(prepared),
        "schemaVersion": MANIFEST_SCHEMA,
        "shardMaxBytes": hard_cap_bytes,
        "shardTargetBytes": target_bytes,
        "shards": [shard.manifest_entry() for shard in shards],
        "unicodeNormalization": "NFC",
    }
    return ShardPlan(shards=shards, manifest=manifest)


def _atomic_write(path: Path, data: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    with temporary.open("wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _write_if_needed(path: Path, data: bytes, *, resume: bool) -> None:
    if resume and path.is_file() and path.read_bytes() == data:
        return
    _atomic_write(path, data)


def write_plan(
    plan: ShardPlan,
    output_dir: str | os.PathLike[str],
    *,
    resume: bool = False,
    manifest_name: str = "manifest.json",
) -> ShardPlan:
    """Persist a plan atomically; resume reuses only byte-identical shards."""

    if not manifest_name or Path(manifest_name).name != manifest_name:
        raise ShardingError("manifest_name must be a filename without directories")
    root = Path(output_dir)
    root.mkdir(parents=True, exist_ok=True)
    manifest_path = root / manifest_name
    expected_paths = {shard.path for shard in plan.shards}

    temporary_paths = list(root.glob(f".{SHARD_PREFIX}*.jsonl.tmp"))
    temporary_paths.append(manifest_path.with_name(f".{manifest_path.name}.tmp"))
    for temporary in temporary_paths:
        if temporary.is_file():
            temporary.unlink()

    if not resume:
        if manifest_path.is_file():
            manifest_path.unlink()
        for existing in root.glob(f"{SHARD_PREFIX}*.jsonl"):
            if existing.is_file():
                existing.unlink()

    for shard in plan.shards:
        _write_if_needed(root / shard.path, shard.data, resume=resume)

    for existing in root.glob(f"{SHARD_PREFIX}*.jsonl"):
        if existing.is_file() and existing.name not in expected_paths:
            existing.unlink()

    manifest_bytes = canonical_jsonl_line(plan.manifest)
    _write_if_needed(manifest_path, manifest_bytes, resume=resume)
    return plan


def write_shards(
    records: Iterable[Any],
    output_dir: str | os.PathLike[str],
    *,
    key_path: str | None = "id",
    target_bytes: int = DEFAULT_TARGET_BYTES,
    hard_cap_bytes: int = DEFAULT_HARD_CAP_BYTES,
    line_cap_bytes: int = DEFAULT_LINE_CAP_BYTES,
    fragment_target_bytes: int | None = None,
    resume: bool = False,
    manifest_name: str = "manifest.json",
) -> ShardPlan:
    """Plan and write deterministic raw JSONL shards."""

    plan = plan_shards(
        records,
        key_path=key_path,
        target_bytes=target_bytes,
        hard_cap_bytes=hard_cap_bytes,
        line_cap_bytes=line_cap_bytes,
        fragment_target_bytes=fragment_target_bytes,
    )
    return write_plan(
        plan,
        output_dir,
        resume=resume,
        manifest_name=manifest_name,
    )
