"""Manifest loading and end-to-end verification for canonical shards."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .canonical import (
    CANONICALIZATION,
    CanonicalJSONError,
    canonical_json_bytes,
    canonical_jsonl_line,
    canonical_loads,
    sha256_digest,
)
from .sharding import (
    DEFAULT_HARD_CAP_BYTES,
    DEFAULT_LINE_CAP_BYTES,
    FRAGMENT_SCHEMA,
    MANIFEST_SCHEMA,
    SHARD_PREFIX,
    ShardingError,
    extract_key,
)

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_ARTIFACT_ID_RE = re.compile(
    r"^urn:rappterverse:[a-z][a-z0-9-]{1,40}:sha256:[0-9a-f]{64}$"
)
_SHARD_NAME_RE = re.compile(rf"^{re.escape(SHARD_PREFIX)}[0-9]{{5,}}\.jsonl$")
_UNRESOLVED = object()


class ManifestError(ValueError):
    """Raised when a manifest or one of its shards fails verification."""


@dataclass(frozen=True)
class VerificationResult:
    """Summary of a successfully verified logical dataset."""

    content_hash: str
    records: int
    lines: int
    shards: int
    canonical_bytes: int
    layout_bytes: int


@dataclass
class _FragmentAccumulator:
    artifact_id: str
    count: int
    artifact_kind: str
    media_type: str
    chunks: list[bytes] = field(default_factory=list)
    key_slots: list[tuple[list[Any], int]] = field(default_factory=list)
    last_sha256: str | None = None


def _expect_int(
    value: Any, field_name: str, *, minimum: int = 0, maximum: int | None = None
) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ManifestError(f"{field_name} must be an integer")
    if value < minimum:
        raise ManifestError(f"{field_name} must be at least {minimum}")
    if maximum is not None and value > maximum:
        raise ManifestError(f"{field_name} must be at most {maximum}")
    return value


def _expect_string(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ManifestError(f"{field_name} must be a string")
    return value


def _same_json(left: Any, right: Any) -> bool:
    try:
        return canonical_json_bytes(left) == canonical_json_bytes(right)
    except CanonicalJSONError:
        return False


def _load_manifest_file(path: Path) -> dict[str, Any]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ManifestError(f"cannot read manifest {path}: {exc}") from exc
    try:
        value = canonical_loads(raw)
    except CanonicalJSONError as exc:
        raise ManifestError(f"manifest is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ManifestError("manifest root must be an object")
    if canonical_jsonl_line(value) != raw:
        raise ManifestError("manifest is not canonical UTF-8 JSON followed by LF")
    return value


def load_manifest(path: str | Path) -> dict[str, Any]:
    """Load a manifest and require its canonical on-disk representation."""

    return _load_manifest_file(Path(path))


def _resolve_manifest(
    root: Path, manifest: str | Path | Mapping[str, Any]
) -> tuple[Path, dict[str, Any]]:
    if isinstance(manifest, Mapping):
        try:
            value = canonical_loads(canonical_json_bytes(manifest))
        except CanonicalJSONError as exc:
            raise ManifestError(f"manifest is not canonicalizable: {exc}") from exc
        if not isinstance(value, dict):
            raise ManifestError("manifest root must be an object")
        return root, value

    manifest_path = Path(manifest)
    if root.is_file():
        manifest_path = root
        root = root.parent
    elif not manifest_path.is_absolute():
        manifest_path = root / manifest_path
    return root, _load_manifest_file(manifest_path)


def _extract_logical_key(value: Any, key_path: str | None, body: bytes) -> Any:
    if key_path is None:
        return f"urn:rappterverse:record:{sha256_digest(body)}"
    try:
        return extract_key(value, key_path)
    except (CanonicalJSONError, ShardingError) as exc:
        raise ManifestError(str(exc)) from exc


def _decode_fragment(
    value: Any,
    active: _FragmentAccumulator | None,
    key_slots: list[Any],
    key_slot: int,
    fragment_target: int,
) -> tuple[_FragmentAccumulator, bool]:
    if not isinstance(value, dict):
        raise ManifestError("fragment line must be an object")
    expected_fields = {
        "artifactId",
        "artifactKind",
        "count",
        "data",
        "encoding",
        "index",
        "mediaType",
        "previousFragmentSha256",
        "schemaVersion",
        "sha256",
        "utf8Bytes",
    }
    if set(value) != expected_fields:
        raise ManifestError("fragment fields do not match the fragment schema")
    if value["schemaVersion"] != FRAGMENT_SCHEMA:
        raise ManifestError("fragment schema is not supported")
    if value["artifactKind"] != "record":
        raise ManifestError("canonical JSON shards require record fragments")
    if value["mediaType"] != "application/json":
        raise ManifestError("record fragment mediaType must be application/json")
    if value["encoding"] != "utf-8":
        raise ManifestError("fragment encoding must be utf-8")

    artifact_id = _expect_string(value["artifactId"], "fragment artifactId")
    if not _ARTIFACT_ID_RE.fullmatch(artifact_id):
        raise ManifestError("fragment artifactId must be content-addressed")
    count = _expect_int(value["count"], "fragment count", minimum=1)
    index = _expect_int(value["index"], "fragment index", maximum=count - 1)
    data = _expect_string(value["data"], "fragment data")
    try:
        chunk = data.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ManifestError("fragment data is not valid UTF-8") from exc
    if not chunk:
        raise ManifestError("fragment data cannot be empty")
    utf8_bytes = _expect_int(
        value["utf8Bytes"],
        "fragment utf8Bytes",
        minimum=1,
        maximum=min(262_144, fragment_target),
    )
    if utf8_bytes != len(chunk):
        raise ManifestError("fragment utf8Bytes does not match data")
    fragment_sha = _expect_string(value["sha256"], "fragment sha256")
    if not _DIGEST_RE.fullmatch(fragment_sha) or fragment_sha != sha256_digest(chunk):
        raise ManifestError("fragment sha256 does not match data")

    previous = value["previousFragmentSha256"]
    if index == 0:
        if active is not None:
            raise ManifestError("a new fragment chain started before the prior chain ended")
        if previous is not None:
            raise ManifestError("the first fragment must have no previous digest")
        active = _FragmentAccumulator(
            artifact_id=artifact_id,
            count=count,
            artifact_kind=value["artifactKind"],
            media_type=value["mediaType"],
        )
    else:
        if active is None:
            raise ManifestError("fragment chain does not start at index zero")
        if index != len(active.chunks):
            raise ManifestError("fragment indexes are not contiguous")
        if (
            active.artifact_id != artifact_id
            or active.count != count
            or active.artifact_kind != value["artifactKind"]
            or active.media_type != value["mediaType"]
        ):
            raise ManifestError("fragment metadata changed within a chain")
        if previous != active.last_sha256:
            raise ManifestError("fragment hash chain is broken")

    active.chunks.append(chunk)
    active.key_slots.append((key_slots, key_slot))
    active.last_sha256 = fragment_sha
    return active, index == 0


def _verify_manifest_header(
    manifest: dict[str, Any],
) -> tuple[int, int, int, int, str | None]:
    required_fields = {
        "canonicalBytes",
        "canonicalization",
        "compression",
        "contentHash",
        "encoding",
        "fragmentTargetBytes",
        "keyPath",
        "layoutBytes",
        "lineMaxBytes",
        "lines",
        "records",
        "schemaVersion",
        "shardMaxBytes",
        "shardTargetBytes",
        "shards",
        "unicodeNormalization",
    }
    missing = required_fields - set(manifest)
    if missing:
        raise ManifestError(
            f"manifest is missing required fields: {', '.join(sorted(missing))}"
        )
    if manifest.get("schemaVersion") != MANIFEST_SCHEMA:
        raise ManifestError("manifest schema is not supported")
    if manifest.get("encoding") != "utf-8":
        raise ManifestError("manifest encoding must be utf-8")
    if manifest.get("canonicalization") != CANONICALIZATION:
        raise ManifestError("manifest canonicalization is not supported")
    if manifest.get("unicodeNormalization") != "NFC":
        raise ManifestError("manifest Unicode normalization must be NFC")
    if manifest.get("compression") != "none":
        raise ManifestError("canonical shards must be uncompressed")

    target = _expect_int(
        manifest.get("shardTargetBytes"), "shardTargetBytes", minimum=1
    )
    hard_cap = _expect_int(
        manifest.get("shardMaxBytes"), "shardMaxBytes", minimum=1
    )
    line_cap = _expect_int(manifest.get("lineMaxBytes"), "lineMaxBytes", minimum=1)
    fragment_target = _expect_int(
        manifest.get("fragmentTargetBytes"), "fragmentTargetBytes", minimum=1
    )
    if target > hard_cap:
        raise ManifestError("shardTargetBytes exceeds shardMaxBytes")
    if hard_cap > DEFAULT_HARD_CAP_BYTES:
        raise ManifestError("shardMaxBytes exceeds the published hard cap")
    if line_cap > hard_cap:
        raise ManifestError("lineMaxBytes exceeds shardMaxBytes")
    if line_cap > DEFAULT_LINE_CAP_BYTES:
        raise ManifestError("lineMaxBytes exceeds the published hard cap")
    if fragment_target > line_cap:
        raise ManifestError("fragmentTargetBytes exceeds lineMaxBytes")

    key_path = manifest.get("keyPath")
    if key_path is not None and (not isinstance(key_path, str) or not key_path):
        raise ManifestError("keyPath must be null or a non-empty string")
    return target, hard_cap, line_cap, fragment_target, key_path


def verify_manifest(
    root: str | Path,
    manifest: str | Path | Mapping[str, Any] = "manifest.json",
    *,
    strict_layout: bool = True,
) -> VerificationResult:
    """Verify canonical bytes, shard metadata, fragment chains, and content hash."""

    root_path, value = _resolve_manifest(Path(root), manifest)
    target, hard_cap, line_cap, fragment_target, key_path = (
        _verify_manifest_header(value)
    )

    entries = value.get("shards")
    if not isinstance(entries, list):
        raise ManifestError("shards must be an array")

    expected_paths: set[str] = set()
    content_digest = hashlib.sha256()
    logical_records = 0
    physical_lines = 0
    canonical_bytes = 0
    layout_bytes = 0
    active: _FragmentAccumulator | None = None
    logical_sort_tokens: list[tuple[bytes, bytes]] = []
    shard_summaries: list[tuple[dict[str, Any], str, list[Any]]] = []

    for expected_index, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ManifestError(f"shards[{expected_index}] must be an object")
        required_entry_fields = {
            "bytes",
            "index",
            "logicalRecords",
            "maxKey",
            "minKey",
            "path",
            "records",
            "sha256",
        }
        missing = required_entry_fields - set(entry)
        if missing:
            raise ManifestError(
                f"shards[{expected_index}] is missing required fields: "
                f"{', '.join(sorted(missing))}"
            )
        index = _expect_int(entry.get("index"), f"shards[{expected_index}].index")
        if index != expected_index:
            raise ManifestError("shard indexes must be contiguous and ordered")

        relative = _expect_string(
            entry.get("path"), f"shards[{expected_index}].path"
        )
        posix_path = PurePosixPath(relative)
        if (
            posix_path.is_absolute()
            or ".." in posix_path.parts
            or len(posix_path.parts) != 1
            or not _SHARD_NAME_RE.fullmatch(relative)
        ):
            raise ManifestError(f"unsafe or non-canonical shard path {relative!r}")
        if relative in expected_paths:
            raise ManifestError(f"duplicate shard path {relative!r}")
        expected_paths.add(relative)

        shard_path = root_path / relative
        try:
            data = shard_path.read_bytes()
        except OSError as exc:
            raise ManifestError(f"cannot read shard {relative}: {exc}") from exc
        layout_bytes += len(data)

        declared_bytes = _expect_int(
            entry.get("bytes"), f"shards[{expected_index}].bytes", minimum=1
        )
        if declared_bytes != len(data):
            raise ManifestError(f"byte count mismatch for shard {relative}")
        if len(data) > hard_cap:
            raise ManifestError(f"shard {relative} exceeds shardMaxBytes")

        declared_sha = _expect_string(
            entry.get("sha256"), f"shards[{expected_index}].sha256"
        )
        if (
            not _DIGEST_RE.fullmatch(declared_sha)
            or declared_sha != sha256_digest(data)
        ):
            raise ManifestError(f"SHA-256 mismatch for shard {relative}")

        if not data.endswith(b"\n"):
            raise ManifestError(f"shard {relative} does not end with LF")
        bodies = data[:-1].split(b"\n")
        if any(not body for body in bodies):
            raise ManifestError(f"shard {relative} contains an empty line")
        declared_records = _expect_int(
            entry.get("records"), f"shards[{expected_index}].records", minimum=1
        )
        if declared_records != len(bodies):
            raise ManifestError(f"record count mismatch for shard {relative}")
        if len(data) > target and len(bodies) != 1:
            raise ManifestError(
                f"shard {relative} exceeds the soft target without being a singleton"
            )

        shard_keys: list[Any] = []
        shard_logical_records = 0
        for line_number, body in enumerate(bodies, start=1):
            line = body + b"\n"
            if len(line) > line_cap:
                raise ManifestError(
                    f"{relative}:{line_number} exceeds lineMaxBytes"
                )
            try:
                parsed = canonical_loads(body)
                if canonical_json_bytes(parsed) != body:
                    raise ManifestError(
                        f"{relative}:{line_number} is not canonical JSON"
                    )
            except CanonicalJSONError as exc:
                raise ManifestError(
                    f"{relative}:{line_number} is not valid canonical JSON: {exc}"
                ) from exc

            if (
                isinstance(parsed, dict)
                and parsed.get("schemaVersion") == FRAGMENT_SCHEMA
            ):
                key_slot = len(shard_keys)
                shard_keys.append(_UNRESOLVED)
                active, logical_start = _decode_fragment(
                    parsed,
                    active,
                    shard_keys,
                    key_slot,
                    fragment_target,
                )
                if logical_start:
                    shard_logical_records += 1

                if len(active.chunks) == active.count:
                    payload = b"".join(active.chunks)
                    expected_id = (
                        f"urn:rappterverse:record:{sha256_digest(payload)}"
                    )
                    if expected_id != active.artifact_id:
                        raise ManifestError("fragment artifactId does not match payload")
                    try:
                        logical_value = canonical_loads(payload)
                        if canonical_json_bytes(logical_value) != payload:
                            raise ManifestError(
                                "fragment payload is not canonical JSON"
                            )
                    except CanonicalJSONError as exc:
                        raise ManifestError(
                            f"fragment payload is not valid JSON: {exc}"
                        ) from exc
                    logical_key = _extract_logical_key(
                        logical_value, key_path, payload
                    )
                    for key_list, slot in active.key_slots:
                        key_list[slot] = logical_key
                    content_digest.update(payload + b"\n")
                    logical_records += 1
                    canonical_bytes += len(payload) + 1
                    logical_sort_tokens.append(
                        (canonical_json_bytes(logical_key), payload)
                    )
                    active = None
            else:
                if active is not None:
                    raise ManifestError("fragment chain was interrupted")
                key = _extract_logical_key(parsed, key_path, body)
                shard_keys.append(key)
                shard_logical_records += 1
                content_digest.update(line)
                logical_records += 1
                canonical_bytes += len(line)
                logical_sort_tokens.append((canonical_json_bytes(key), body))

            physical_lines += 1

        declared_logical = _expect_int(
            entry.get("logicalRecords"),
            f"shards[{expected_index}].logicalRecords",
        )
        if declared_logical != shard_logical_records:
            raise ManifestError(f"logical record count mismatch for shard {relative}")
        shard_summaries.append((entry, relative, shard_keys))

    if active is not None:
        raise ManifestError("final fragment chain is incomplete")
    for entry, relative, shard_keys in shard_summaries:
        if any(key is _UNRESOLVED for key in shard_keys):
            raise ManifestError(f"fragment key was not resolved for shard {relative}")
        if not _same_json(entry.get("minKey"), shard_keys[0]):
            raise ManifestError(f"minKey mismatch for shard {relative}")
        if not _same_json(entry.get("maxKey"), shard_keys[-1]):
            raise ManifestError(f"maxKey mismatch for shard {relative}")
    if logical_sort_tokens != sorted(logical_sort_tokens):
        raise ManifestError("logical records are not in deterministic key/content order")

    if strict_layout:
        actual_paths = {
            path.name
            for path in root_path.glob(f"{SHARD_PREFIX}*.jsonl")
            if path.is_file()
        }
        if actual_paths != expected_paths:
            raise ManifestError("on-disk shard set does not match the manifest")

    declared_content_hash = _expect_string(value.get("contentHash"), "contentHash")
    if (
        not _DIGEST_RE.fullmatch(declared_content_hash)
        or declared_content_hash != f"sha256:{content_digest.hexdigest()}"
    ):
        raise ManifestError("contentHash does not match logical records")
    if _expect_int(value.get("records"), "records") != logical_records:
        raise ManifestError("manifest logical record total does not match")
    if _expect_int(value.get("lines"), "lines") != physical_lines:
        raise ManifestError("manifest physical line total does not match")
    if _expect_int(value.get("canonicalBytes"), "canonicalBytes") != canonical_bytes:
        raise ManifestError("manifest canonical byte total does not match")
    if _expect_int(value.get("layoutBytes"), "layoutBytes") != layout_bytes:
        raise ManifestError("manifest layout byte total does not match")

    return VerificationResult(
        content_hash=declared_content_hash,
        records=logical_records,
        lines=physical_lines,
        shards=len(entries),
        canonical_bytes=canonical_bytes,
        layout_bytes=layout_bytes,
    )
