# SPDX-License-Identifier: Apache-2.0

"""Fail-closed validation of public data publication candidates."""

from __future__ import annotations

import fnmatch
import hashlib
import json
import math
import re
import stat
import subprocess
import sys
import unicodedata
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Iterator, Optional, Sequence, Union

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from contracts.registry import (  # noqa: E402
    ARTIFACT_KIND_TO_SCHEMA_VERSION,
    JSONL_ARTIFACT_KIND_TO_SCHEMA_VERSION,
    TrustedSchemaRegistry,
)
from contracts.canonical import (  # noqa: E402
    MAX_JSON_NESTING_DEPTH,
    CanonicalJSONV2DepthError,
    ensure_json_depth,
)
from contracts.release_trust import (  # noqa: E402
    ReleaseTrustValidator,
    TrustedPredecessorAnchor,
)

try:
    from .policy import PolicySet
    from .scanners import (
        governed_digest_paths,
        scan_json,
        scan_path,
        scan_text,
    )
except ImportError:  # Direct execution through validate.py.
    from policy import PolicySet
    from scanners import (
        governed_digest_paths,
        scan_json,
        scan_path,
        scan_text,
    )


_HEX_40 = re.compile(r"^[0-9a-f]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_HASH_REF = re.compile(r"^sha256:[0-9a-f]{64}$")
_DATASET_ID = re.compile(r"^d(?:0[1-9]|10)-[a-z0-9]+(?:-[a-z0-9]+)*$")
_REVIEWER_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{2,63}$")
_RECORD_ID = re.compile(r"^urn:rappterverse:record:sha256:[0-9a-f]{64}$")
_TOMBSTONE_ID = re.compile(r"^urn:rappterverse:tombstone:sha256:[0-9a-f]{64}$")
_CONTROL_CHARACTER = re.compile(r"[\x00-\x1f\x7f]")
_FORMAL_V2 = re.compile(r"^rappterverse\.[a-z0-9-]+/v2$")
_V2_RELEASE_POINTER_PATH = re.compile(
    r"^catalog/releases/release-[0-9]{4}-[0-9]{2}-[0-9]{2}-"
    r"[a-z0-9][a-z0-9.-]{0,63}\.json$"
)
_V2_CONTROL_OBJECT_PATH = re.compile(
    r"^objects/(?:active-review-sets|review-receipts)/sha256/"
    r"[0-9a-f]{2}/[0-9a-f]{64}\.json$"
)
_CONTENT_ADDRESSED_PATH = re.compile(
    r"^objects/[a-z0-9-]+/sha256/[0-9a-f]{2}/"
    r"[0-9a-f]{64}\.(?:json|jsonl|txt)$"
)


@dataclass(frozen=True, order=True)
class Finding:
    """A deliberately redacted validation result."""

    severity: str
    code: str
    path: str
    line: int
    column: int
    message: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "code": self.code,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
        }


class ValidationReport:
    MAX_FINDINGS = 200

    def __init__(self) -> None:
        self._findings: list[Finding] = []

    @property
    def findings(self) -> tuple[Finding, ...]:
        return tuple(sorted(set(self._findings)))

    @property
    def ok(self) -> bool:
        return not any(item.severity == "error" for item in self._findings)

    def error(
        self,
        code: str,
        path: str,
        message: str,
        line: int = 0,
        column: int = 0,
    ) -> None:
        if len(self._findings) >= self.MAX_FINDINGS:
            return
        safe_path = path
        if _CONTROL_CHARACTER.search(path) or scan_path(path):
            safe_path = "<redacted-path>"
        self._findings.append(Finding("error", code, safe_path, line, column, message))

    def as_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "findingCount": len(self.findings),
            "findings": [item.as_dict() for item in self.findings],
        }


@dataclass(frozen=True)
class Change:
    status: str
    path: str
    old_path: Optional[str] = None

    @property
    def operation(self) -> str:
        return self.status[:1]


def canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def artifact_set_digest(artifacts: Sequence[dict[str, Any]]) -> str:
    normalized = [
        {
            "bytes": item.get("bytes"),
            "path": item.get("path"),
            "sha256": item.get("sha256"),
        }
        for item in artifacts
    ]
    normalized.sort(key=lambda item: str(item["path"]))
    return canonical_sha256(normalized)


def _is_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.utcoffset() is not None and parsed.utcoffset().total_seconds() == 0


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _normalized_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]", "", value.lower())


def _walk_objects(value: Any) -> Iterator[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_objects(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_objects(child)


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _strict_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise ValueError("non-finite JSON number")
    return parsed


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _strict_json_loads(text: str) -> Any:
    try:
        value = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
            parse_float=_strict_float,
        )
    except RecursionError as exc:
        raise CanonicalJSONV2DepthError(
            "maximum JSON nesting depth {} exceeded".format(
                MAX_JSON_NESTING_DEPTH
            )
        ) from exc
    ensure_json_depth(value)
    return value


def _safe_relative_path(value: Any) -> bool:
    if not isinstance(value, str) or not value or "\\" in value:
        return False
    if _CONTROL_CHARACTER.search(value) or unicodedata.normalize("NFC", value) != value:
        return False
    candidate = PurePosixPath(value)
    return (
        not candidate.is_absolute()
        and all(part not in {"", ".", ".."} for part in candidate.parts)
        and str(candidate) == value
    )


def _read_json_bytes(
    data: bytes, path: str, report: ValidationReport
) -> Optional[Any]:
    try:
        return _strict_json_loads(data.decode("utf-8"))
    except UnicodeError:
        report.error("TEXT_UTF8", path, "public text must be valid UTF-8")
    except json.JSONDecodeError as exc:
        report.error(
            "JSON_INVALID",
            path,
            "JSON is not syntactically valid",
            exc.lineno,
            exc.colno,
        )
    except CanonicalJSONV2DepthError:
        report.error(
            "JSON_DEPTH",
            path,
            "JSON nesting exceeds maximum depth {}".format(
                MAX_JSON_NESTING_DEPTH
            ),
        )
    except ValueError:
        report.error("JSON_INVALID", path, "JSON is not strictly valid")
    return None


def resolve_git_revision(root: Path, revision: str) -> str:
    process = subprocess.run(
        ["git", "rev-parse", "--verify", f"{revision}^{{commit}}"],
        cwd=root,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    resolved = process.stdout.strip()
    if process.returncode != 0 or not _HEX_40.fullmatch(resolved):
        raise ValueError("unable to resolve a requested Git revision")
    return resolved


def collect_git_changes(root: Path, base: str, head: str) -> tuple[list[Change], int]:
    base_sha = resolve_git_revision(root, base)
    head_sha = resolve_git_revision(root, head)
    names = subprocess.run(
        ["git", "diff", "--name-status", "-z", "--find-renames", base_sha, head_sha, "--"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    parts = names.split(b"\0")
    changes: list[Change] = []
    index = 0
    while index < len(parts) and parts[index]:
        status = parts[index].decode("ascii", errors="strict")
        index += 1
        if status[:1] in {"R", "C"}:
            old_path = parts[index].decode("utf-8", errors="strict")
            new_path = parts[index + 1].decode("utf-8", errors="strict")
            index += 2
            changes.append(Change(status, new_path, old_path))
        else:
            path = parts[index].decode("utf-8", errors="strict")
            index += 1
            changes.append(Change(status, path))
    patch = subprocess.run(
        ["git", "diff", "--no-ext-diff", "--binary", base_sha, head_sha, "--"],
        cwd=root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout
    return changes, len(patch)


class GovernanceValidator:
    """Validate a candidate tree using policy loaded from a trusted tree."""

    def __init__(
        self,
        root: Union[Path, str],
        policies: PolicySet,
        *,
        base_revision: Optional[str] = None,
        trusted_schema_root: Optional[Union[Path, str]] = None,
        allow_historical_v1: bool = False,
    ) -> None:
        self.root = Path(root).resolve()
        self.policies = policies
        self.base_revision = (
            resolve_git_revision(self.root, base_revision) if base_revision else None
        )
        schema_root = (
            Path(trusted_schema_root)
            if trusted_schema_root is not None
            else policies.root.parent / "schemas" / "v2"
        )
        self.v2_registry = TrustedSchemaRegistry.load(schema_root)
        self.v2_trust = ReleaseTrustValidator(
            self.root,
            self.v2_registry,
            policies.trust_document_bytes,
            policies.rights_v2_document_bytes,
        )
        self.allow_historical_v1 = allow_historical_v1
        self.report = ValidationReport()
        self._parsed: dict[str, Any] = {}
        self._bytes: dict[str, bytes] = {}
        self._deferred_v2_scan_paths: set[str] = set()
        self._deferred_path_scan_paths: set[str] = set()
        self._verified_v2_scan_paths: set[str] = set()

    def validate(self, changes: Iterable[Change], *, diff_bytes: int = 0) -> ValidationReport:
        """Validate changes and convert recursion exhaustion to a stable finding."""

        try:
            return self._validate(changes, diff_bytes=diff_bytes)
        except RecursionError:
            self.report.error(
                "JSON_DEPTH",
                ".",
                "JSON nesting exceeds maximum depth {}".format(
                    MAX_JSON_NESTING_DEPTH
                ),
            )
            return self.report

    def _validate(
        self, changes: Iterable[Change], *, diff_bytes: int = 0
    ) -> ValidationReport:
        materialized = list(changes)
        hard_diff = self.policies.publication["limits"]["pullRequestDiffHardBytes"]
        if diff_bytes > hard_diff:
            self.report.error(
                "PR_DIFF_LIMIT",
                ".",
                "pull request raw diff exceeds the publication hard limit",
            )

        seen_paths: set[str] = set()
        for change in materialized:
            if change.path in seen_paths:
                self.report.error(
                    "PATH_DUPLICATE", change.path, "a changed path appears more than once"
                )
            seen_paths.add(change.path)
            self._validate_change(change)

        self._validate_v2_contracts(materialized)
        candidate_changes = [
            item for item in materialized if self._is_candidate(item.path)
        ]
        if candidate_changes:
            self._validate_candidate_set(candidate_changes, materialized)
        self._validate_deferred_scans()
        return self.report

    @staticmethod
    def _is_contract_fixture(path: str) -> bool:
        parts = PurePosixPath(path).parts
        return (
            len(parts) >= 5
            and parts[:4]
            == ("tests", "fixtures", "contracts", "invalid")
        ) or (
            len(parts) >= 6
            and parts[:5]
            == (
                "tests",
                "fixtures",
                "contracts",
                "v2",
                "release-graph",
            )
        )

    @staticmethod
    def _contains_formal_v2(value: Any) -> bool:
        if isinstance(value, dict):
            version = value.get("schemaVersion")
            if isinstance(version, str) and _FORMAL_V2.fullmatch(version):
                return True
            return any(
                GovernanceValidator._contains_formal_v2(item)
                for item in value.values()
            )
        if isinstance(value, list):
            return any(
                GovernanceValidator._contains_formal_v2(item) for item in value
            )
        return False

    def _validate_v2_contracts(self, changes: Sequence[Change]) -> None:
        descriptor_kinds: dict[str, str] = {}
        for value in self._parsed.values():
            if not isinstance(value, dict):
                continue
            version = value.get("schemaVersion")
            descriptors = (
                value.get("shards", [])
                if version == "rappterverse.dataset-manifest/v2"
                else value.get("approvedArtifacts", [])
                if version == "rappterverse.public-review-receipt/v2"
                else []
            )
            for shard in descriptors:
                if (
                    isinstance(shard, dict)
                    and isinstance(shard.get("path"), str)
                    and isinstance(shard.get("artifactKind"), str)
                ):
                    descriptor_kinds[shard["path"]] = shard["artifactKind"]

        for change in changes:
            if change.operation == "D" or self._is_contract_fixture(change.path):
                continue
            value = self._parsed.get(change.path)
            data = self._bytes.get(change.path)
            if data is None:
                continue
            if change.path.endswith(".json") and isinstance(value, dict):
                if (
                    change.path.startswith("templates/")
                    and isinstance(value.get("$template"), str)
                ):
                    continue
                version = value.get("schemaVersion")
                if not (
                    isinstance(version, str)
                    and (
                        version in self.v2_registry.schemas_by_version
                        or _FORMAL_V2.fullmatch(version)
                    )
                ):
                    continue
                expected = None
                descriptor_kind = descriptor_kinds.get(change.path)
                if descriptor_kind is not None:
                    expected = ARTIFACT_KIND_TO_SCHEMA_VERSION.get(
                        descriptor_kind
                    )
                self.v2_trust.validate_formal_json_bytes(
                    change.path,
                    data,
                    expected_schema_version=expected,
                )
            elif change.path.endswith(".jsonl") and isinstance(value, list):
                versions = {
                    item.get("schemaVersion")
                    for item in value
                    if isinstance(item, dict)
                    and isinstance(item.get("schemaVersion"), str)
                    and _FORMAL_V2.fullmatch(item["schemaVersion"])
                }
                if not versions:
                    continue
                reverse = {
                    version: kind
                    for kind, version in (
                        JSONL_ARTIFACT_KIND_TO_SCHEMA_VERSION.items()
                    )
                }
                inferred = (
                    reverse.get(next(iter(versions)))
                    if len(versions) == 1
                    else None
                )
                declared = descriptor_kinds.get(change.path)
                artifact_kind = declared or inferred
                if artifact_kind is None:
                    self.report.error(
                        "V2_SHARD_KIND",
                        change.path,
                        "v2 JSONL does not have one trusted artifact kind",
                    )
                    continue
                if declared is None and self._is_candidate(change.path):
                    self.report.error(
                        "V2_SHARD_DESCRIPTOR_REQUIRED",
                        change.path,
                        "published v2 JSONL requires a dataset-manifest descriptor",
                    )
                self.v2_trust.validate_jsonl_bytes(
                    change.path, data, artifact_kind
                )

        for item in self.v2_trust.diagnostics:
            self.report.error(
                "V2_{}".format(item.code),
                item.path,
                item.message,
            )

    def _validate_deferred_scans(self) -> None:
        for path in sorted(self._deferred_path_scan_paths):
            hits = scan_path(
                path,
                verified_content_address=(
                    path in self._verified_v2_scan_paths
                ),
            )
            if hits:
                self.report.error(
                    "PATH_SENSITIVE",
                    path,
                    "repository path appears to contain prohibited sensitive data",
                )

        for path in sorted(self._deferred_v2_scan_paths):
            value = self._parsed.get(path)
            verified = path in self._verified_v2_scan_paths
            values = value if isinstance(value, list) else [value]
            for number, item in enumerate(values, start=1):
                digest_paths = (
                    governed_digest_paths(item) if verified else set()
                )
                for hit in scan_json(
                    item,
                    verified_digest_paths=digest_paths,
                ):
                    self.report.error(
                        hit.code,
                        path,
                        hit.message,
                        number if isinstance(value, list) else 0,
                        hit.column,
                    )

    def _validate_change(self, change: Change) -> None:
        if not _safe_relative_path(change.path):
            self.report.error("PATH_UNSAFE", change.path, "repository path is not canonical")
            return
        negative_fixture = self._is_contract_fixture(change.path)
        defer_path_scan = (
            not negative_fixture
            and self._is_candidate(change.path)
            and _CONTENT_ADDRESSED_PATH.fullmatch(change.path) is not None
        )
        if defer_path_scan:
            self._deferred_path_scan_paths.add(change.path)
        elif not negative_fixture and scan_path(change.path):
            self.report.error(
                "PATH_SENSITIVE",
                change.path,
                "repository path appears to contain prohibited sensitive data",
            )
            return
        if change.old_path and not _safe_relative_path(change.old_path):
            self.report.error(
                "PATH_UNSAFE", change.path, "renamed source path is not canonical"
            )
        elif change.old_path and scan_path(change.old_path):
            self.report.error(
                "PATH_SENSITIVE",
                change.old_path,
                "renamed source path appears to contain prohibited sensitive data",
            )

        operation = change.operation
        if self._is_immutable(change.path) and operation != "A":
            self.report.error(
                "RELEASE_IMMUTABLE",
                change.path,
                "an existing released path cannot be changed or deleted",
            )
        if change.old_path and self._is_immutable(change.old_path):
            self.report.error(
                "RELEASE_IMMUTABLE",
                change.old_path,
                "an existing released path cannot be renamed or copied",
            )
        if operation == "D":
            if change.path.startswith("policies/"):
                self.report.error(
                    "POLICY_REQUIRED", change.path, "required governance policy cannot be deleted"
                )
            return

        path = self.root / change.path
        try:
            resolved = path.resolve(strict=True)
            resolved.relative_to(self.root)
            if resolved != path:
                self.report.error(
                    "SYMLINK_FORBIDDEN",
                    change.path,
                    "changed path may not traverse a symbolic link",
                )
                return
            mode = path.lstat().st_mode
        except (OSError, ValueError):
            self.report.error("FILE_MISSING", change.path, "changed file is unavailable")
            return
        if stat.S_ISLNK(mode):
            self.report.error("SYMLINK_FORBIDDEN", change.path, "symbolic links are prohibited")
            return
        if not stat.S_ISREG(mode):
            self.report.error("FILE_TYPE", change.path, "changed path must be a regular file")
            return
        try:
            data = path.read_bytes()
        except OSError:
            self.report.error("FILE_UNREADABLE", change.path, "changed file cannot be read")
            return
        self._bytes[change.path] = data

        limits = self.policies.publication["limits"]
        file_limit = limits["fileHardBytes"]
        lowered_name = PurePosixPath(change.path).name.lower()
        if "manifest" in lowered_name or lowered_name == "data-card.json":
            file_limit = min(file_limit, limits["manifestHardBytes"])
        if len(data) > file_limit:
            self.report.error(
                "FILE_SIZE_LIMIT", change.path, "changed file exceeds its hard byte limit"
            )
        if b"\x00" in data:
            self.report.error("BINARY_FORBIDDEN", change.path, "binary content is prohibited")
            return
        try:
            text = data.decode("utf-8")
        except UnicodeError:
            self.report.error("TEXT_UTF8", change.path, "public text must be valid UTF-8")
            return
        if change.path.endswith(".jsonl"):
            self._parse_jsonl(change.path, data)
        elif change.path.endswith(".json"):
            document = _read_json_bytes(data, change.path, self.report)
            if document is not None:
                self._parsed[change.path] = document
                if (
                    not negative_fixture
                    and self._is_candidate(change.path)
                    and self._contains_formal_v2(document)
                ):
                    self._deferred_v2_scan_paths.add(change.path)
                elif not negative_fixture:
                    for hit in scan_json(document):
                        self.report.error(
                            hit.code, change.path, hit.message
                        )
                if not negative_fixture:
                    self._validate_forbidden_fields(document, change.path)
            elif not negative_fixture:
                for hit in scan_text(text):
                    self.report.error(
                        hit.code,
                        change.path,
                        hit.message,
                        hit.line,
                        hit.column,
                    )
        elif not negative_fixture:
            for hit in scan_text(text):
                self.report.error(
                    hit.code,
                    change.path,
                    hit.message,
                    hit.line,
                    hit.column,
                )

    def _parse_jsonl(self, path: str, data: bytes) -> None:
        objects: list[Any] = []
        negative_fixture = self._is_contract_fixture(path)
        line_limit = self.policies.publication["limits"]["jsonlLineHardBytes"]
        for number, raw_line in enumerate(data.splitlines(), start=1):
            if len(raw_line) > line_limit:
                self.report.error(
                    "JSONL_LINE_LIMIT",
                    path,
                    "JSONL line exceeds the hard byte limit",
                    number,
                )
                continue
            if not raw_line.strip():
                self.report.error(
                    "JSONL_EMPTY_LINE", path, "JSONL must not contain empty lines", number
                )
                continue
            try:
                line_text = raw_line.decode("utf-8")
                value = _strict_json_loads(line_text)
            except UnicodeError:
                self.report.error(
                    "TEXT_UTF8", path, "public text must be valid UTF-8", number
                )
                continue
            except json.JSONDecodeError as exc:
                if not negative_fixture:
                    for hit in scan_text(line_text):
                        self.report.error(
                            hit.code, path, hit.message, number, hit.column
                        )
                self.report.error(
                    "JSON_INVALID",
                    path,
                    "JSONL record is not syntactically valid",
                    number,
                    exc.colno,
                )
                continue
            except CanonicalJSONV2DepthError:
                if not negative_fixture:
                    for hit in scan_text(line_text):
                        self.report.error(
                            hit.code, path, hit.message, number, hit.column
                        )
                self.report.error(
                    "JSON_DEPTH",
                    path,
                    "JSON nesting exceeds maximum depth {}".format(
                        MAX_JSON_NESTING_DEPTH
                    ),
                    number,
                )
                continue
            except ValueError:
                if not negative_fixture:
                    for hit in scan_text(line_text):
                        self.report.error(
                            hit.code, path, hit.message, number, hit.column
                        )
                self.report.error(
                    "JSON_INVALID",
                    path,
                    "JSONL record is not strictly valid",
                    number,
                )
                continue
            objects.append(value)
            if (
                not negative_fixture
                and self._is_candidate(path)
                and self._contains_formal_v2(value)
            ):
                self._deferred_v2_scan_paths.add(path)
            elif not negative_fixture:
                for hit in scan_json(value):
                    self.report.error(
                        hit.code, path, hit.message, number, hit.column
                    )
            if not negative_fixture:
                self._validate_forbidden_fields(value, path, number)
        self._parsed[path] = objects

    def _validate_forbidden_fields(
        self, value: Any, path: str, line: int = 0
    ) -> None:
        forbidden = {
            _normalized_key(item)
            for item in self.policies.fields.get("forbiddenRecursiveFieldNames", [])
        }
        forbidden.update(
            _normalized_key(item)
            for item in self.policies.fields.get("forbiddenSourceFields", [])
        )
        for item in _walk_objects(value):
            for key in item:
                if isinstance(key, str) and _normalized_key(key) in forbidden:
                    self.report.error(
                        "FIELD_FORBIDDEN",
                        path,
                        "a prohibited public field name is present",
                        line,
                    )

    def _is_candidate(self, path: str) -> bool:
        publication = self.policies.publication
        if any(
            fnmatch.fnmatchcase(path, pattern)
            for pattern in publication.get("publicationPathGlobs", [])
        ):
            return True
        if any(
            path.startswith(prefix)
            for prefix in publication.get("sourcePathPrefixes", [])
        ):
            return False
        return any(
            path.startswith(prefix)
            for prefix in publication["candidatePathPrefixes"]
        )

    def _is_immutable(self, path: str) -> bool:
        publication = self.policies.publication
        if any(
            fnmatch.fnmatchcase(path, pattern)
            for pattern in publication.get("immutablePathGlobs", [])
        ):
            return True
        if any(
            path.startswith(prefix)
            for prefix in publication.get("sourcePathPrefixes", [])
        ):
            return False
        return any(
            path.startswith(prefix) for prefix in publication["immutablePathPrefixes"]
        )

    def _is_withdrawal_path(self, path: str) -> bool:
        withdrawal = self.policies.withdrawal
        return path.startswith(withdrawal["tombstonePathPrefix"]) or path == withdrawal[
            "removalIndexPath"
        ]

    def _validate_candidate_set(
        self, candidates: list[Change], all_changes: list[Change]
    ) -> None:
        if any(item.operation == "D" for item in candidates):
            for item in candidates:
                if item.operation == "D":
                    self.report.error(
                        "PUBLICATION_DELETE",
                        item.path,
                        "public data is withdrawn by tombstone, never by deletion",
                    )

        if (
            self.policies.publication["rejectMixedPolicyAndPublicationChanges"]
            and any(
                item.path.startswith(
                    (
                        "policies/",
                        "schemas/v2/",
                        "scripts/contracts/",
                        "scripts/governance/",
                    )
                )
                for item in all_changes
            )
        ):
            self.report.error(
                "POLICY_PUBLICATION_MIXED",
                ".",
                "trust-layer changes and publication changes require separate pull requests",
            )

        final_paths = {item.path for item in candidates if item.operation != "D"}
        changed_paths = {item.path for item in candidates}
        maximum = self.policies.publication["limits"]["publicationFilesHard"]
        if len(changed_paths) > maximum:
            self.report.error(
                "PUBLICATION_FILE_LIMIT",
                ".",
                "publication changes exceed the five-file hard limit",
            )

        if candidates and all(self._is_withdrawal_path(item.path) for item in candidates):
            self._validate_withdrawal_set(candidates)
            return
        if any(self._is_withdrawal_path(item.path) for item in candidates):
            self.report.error(
                "WITHDRAWAL_MIXED",
                ".",
                "withdrawals and ordinary publications require separate pull requests",
            )
            return

        has_v2 = any(
            path in final_paths and self._contains_formal_v2(value)
            for path, value in self._parsed.items()
        )
        if has_v2:
            self._validate_v2_publication_set(candidates)
            return
        if not self.allow_historical_v1:
            self.report.error(
                "RELEASE_CONTRACT_INACTIVE",
                ".",
                "new public releases must use the v2 trust graph",
            )
            return

        manifest_schema = self.policies.publication["publicationManifestSchema"]
        manifests = [
            (path, value)
            for path, value in self._parsed.items()
            if isinstance(value, dict) and value.get("schema") == manifest_schema
        ]
        if len(manifests) != 1:
            self.report.error(
                "PUBLICATION_MANIFEST_REQUIRED",
                ".",
                "candidate publication requires exactly one publication manifest",
            )
            return
        manifest_path, manifest = manifests[0]
        self._validate_publication_manifest(manifest_path, manifest, final_paths)
        artifact_roles = {
            item.get("path"): item.get("role")
            for item in manifest.get("artifacts", [])
            if isinstance(item, dict)
        }

        for path, value in self._parsed.items():
            if path not in final_paths:
                continue
            if PurePosixPath(path).name.lower() == "data-card.json":
                self._validate_data_card(path, value)
            if (
                path.startswith("objects/records/")
                or artifact_roles.get(path) == "records"
            ):
                records = value if isinstance(value, list) else [value]
                for index, record in enumerate(records, start=1):
                    self._validate_record(path, record, index)
            elif isinstance(value, (dict, list)):
                for item in _walk_objects(value):
                    if item.get("schemaVersion") == "rappterverse.public-record/v1":
                        self._validate_record(path, item)

    def _validate_v2_publication_set(self, candidates: Sequence[Change]) -> None:
        final_paths = {
            item.path for item in candidates if item.operation != "D"
        }
        if "catalog/latest.json" not in final_paths:
            self._validate_v2_artifact_batch(candidates)
            return

        latest = self._parsed.get("catalog/latest.json")
        if not isinstance(latest, dict) or latest.get("schemaVersion") != (
            "rappterverse.catalog-latest-pointer/v2"
        ):
            self.report.error(
                "V2_LATEST_REQUIRED",
                "catalog/latest.json",
                "release activation requires a formal v2 latest pointer",
            )
            return

        for path in sorted(final_paths):
            if not self._is_v2_activation_control(path):
                self.report.error(
                    "V2_ACTIVATION_PAYLOAD",
                    path,
                    "release activation may change only v2 control files",
                )

        anchor = self._trusted_predecessor_anchor()
        graph = ReleaseTrustValidator(
            self.root,
            self.v2_registry,
            self.policies.trust_document_bytes,
            self.policies.rights_v2_document_bytes,
            trusted_predecessor_anchor=anchor,
        )
        for item in graph.validate_release_graph("catalog/latest.json"):
            self.report.error(
                "V2_{}".format(item.code),
                item.path,
                item.message,
            )
        covered = set(graph.validated_paths)
        for change in sorted(candidates, key=lambda item: item.path):
            if change.operation != "D" and change.path not in covered:
                self.report.error(
                    "V2_ARTIFACT_COVERAGE",
                    change.path,
                    "changed public artifact is not reachable from catalog latest",
                )
        if graph.ok and final_paths <= covered:
            self._verified_v2_scan_paths.update(final_paths)

    @staticmethod
    def _is_v2_activation_control(path: str) -> bool:
        return bool(
            path == "catalog/latest.json"
            or _V2_RELEASE_POINTER_PATH.fullmatch(path)
            or _V2_CONTROL_OBJECT_PATH.fullmatch(path)
        )

    def _validate_v2_artifact_batch(
        self, candidates: Sequence[Change]
    ) -> None:
        final_paths = {
            item.path for item in candidates if item.operation != "D"
        }
        for path in sorted(final_paths):
            if not self._is_immutable(path):
                self.report.error(
                    "V2_BATCH_IMMUTABLE",
                    path,
                    "artifact batches may add only immutable v2 files",
                )
        graph = ReleaseTrustValidator(
            self.root,
            self.v2_registry,
            self.policies.trust_document_bytes,
            self.policies.rights_v2_document_bytes,
        )
        for item in graph.validate_artifact_batch(final_paths):
            self.report.error(
                "V2_{}".format(item.code),
                item.path,
                item.message,
            )
        covered = set(graph.validated_paths)
        for path in sorted(final_paths - covered):
            self.report.error(
                "V2_ARTIFACT_COVERAGE",
                path,
                "changed public artifact was not validated by its batch receipt",
            )
        if graph.ok and final_paths <= covered:
            self._verified_v2_scan_paths.update(final_paths)

    def _validate_publication_manifest(
        self, path: str, manifest: dict[str, Any], candidate_paths: set[str]
    ) -> None:
        if manifest.get("policyVersion") != self.policies.version:
            self.report.error(
                "POLICY_VERSION", path, "publication policy version is missing or stale"
            )
        if not isinstance(manifest.get("publicationId"), str) or not manifest.get(
            "publicationId"
        ):
            self.report.error(
                "PUBLICATION_ID", path, "publication identifier is required"
            )
        self._require_dataset_id(manifest.get("datasetId"), path)
        if manifest.get("licenses") != {"data": "CC-BY-4.0", "code": "Apache-2.0"}:
            self.report.error(
                "LICENSE_METADATA",
                path,
                "publication must declare CC-BY-4.0 data and Apache-2.0 code",
            )
        candidate_digest = manifest.get("candidateSha256")
        public_digest = manifest.get("publicArtifactSha256")
        if not isinstance(candidate_digest, str) or not _HEX_64.fullmatch(candidate_digest):
            self.report.error(
                "CANDIDATE_HASH", path, "candidate SHA-256 is required"
            )

        self._validate_provenance(manifest.get("provenance"), path)
        layers = manifest.get("layers")
        self._validate_reasoning_layers(
            layers, path, candidate_digest, public_digest
        )

        artifacts = manifest.get("artifacts")
        if not isinstance(artifacts, list) or not artifacts:
            self.report.error(
                "ARTIFACTS_REQUIRED", path, "publication must declare at least one artifact"
            )
            artifacts = []
        declared_paths: set[str] = set()
        allowed_roles = {
            "records",
            "visible-transcript",
            "public-deliberation",
            "provider-reasoning",
            "verifier",
            "data-card",
            "dataset-manifest",
            "release-manifest",
            "world-pack",
            "catalog-index",
        }
        for artifact in artifacts:
            if not isinstance(artifact, dict):
                self.report.error(
                    "ARTIFACT_INVALID", path, "artifact entries must be objects"
                )
                continue
            artifact_path = artifact.get("path")
            if not _safe_relative_path(artifact_path):
                self.report.error(
                    "ARTIFACT_PATH", path, "artifact path is not canonical"
                )
                continue
            if artifact_path == path or artifact_path in declared_paths:
                self.report.error(
                    "ARTIFACT_PATH", path, "artifact paths must be unique and exclude the manifest"
                )
                continue
            declared_paths.add(artifact_path)
            expected_hash = artifact.get("sha256")
            expected_bytes = artifact.get("bytes")
            if not isinstance(expected_hash, str) or not _HEX_64.fullmatch(expected_hash):
                self.report.error(
                    "ARTIFACT_HASH", path, "artifact SHA-256 is invalid"
                )
            data = self._bytes.get(artifact_path)
            if data is None:
                self.report.error(
                    "ARTIFACT_UNAVAILABLE",
                    path,
                    "declared artifact is not part of this publication change",
                )
            else:
                if hashlib.sha256(data).hexdigest() != expected_hash:
                    self.report.error(
                        "ARTIFACT_HASH", path, "declared artifact hash does not match"
                    )
                if expected_bytes != len(data):
                    self.report.error(
                        "ARTIFACT_BYTES", path, "declared artifact byte count does not match"
                    )
            if artifact.get("role") not in allowed_roles:
                self.report.error(
                    "ARTIFACT_ROLE", path, "artifact role is not allowed"
                )
            if not isinstance(artifact.get("mediaType"), str) or not artifact.get(
                "mediaType"
            ):
                self.report.error(
                    "ARTIFACT_MEDIA_TYPE", path, "artifact media type is required"
                )

            expected_role = self._expected_role_for_path(artifact_path)
            if expected_role is not None and artifact.get("role") != expected_role:
                self.report.error(
                    "ARTIFACT_ROLE",
                    path,
                    "content-addressed artifact path does not match its declared role",
                )
            if artifact_path.startswith("objects/") and not self._valid_object_address(
                artifact_path, expected_hash
            ):
                self.report.error(
                    "ARTIFACT_CONTENT_ADDRESS",
                    path,
                    "object-store path does not match the artifact content hash",
                )

        expected_paths = candidate_paths - {path}
        if declared_paths != expected_paths:
            self.report.error(
                "ARTIFACT_COVERAGE",
                path,
                "manifest must declare every and only changed public artifact",
            )
        calculated_digest = artifact_set_digest(
            [item for item in artifacts if isinstance(item, dict)]
        )
        if public_digest != calculated_digest:
            self.report.error(
                "PUBLIC_ARTIFACT_HASH",
                path,
                "aggregate public artifact hash does not match",
            )
        self._validate_layer_artifacts(layers, artifacts, path)

        governance = manifest.get("governance")
        if not isinstance(governance, dict):
            self.report.error(
                "GOVERNANCE_REQUIRED", path, "publication governance metadata is required"
            )
            return
        self._validate_governance_labels(governance, path)
        self._validate_publication_quality(governance.get("quality"), path)
        self._validate_receipt(
            governance.get("reviewReceipt"),
            path,
            expected_candidate=candidate_digest,
            expected_public=public_digest,
            allowed_dispositions=set(self.policies.publication["reviewDispositions"]),
        )
        withdrawal = manifest.get("withdrawal")
        if not isinstance(withdrawal, dict) or withdrawal.get("policy") != (
            "append-only-tombstone"
        ):
            self.report.error(
                "WITHDRAWAL_POLICY",
                path,
                "publication must declare the append-only tombstone policy",
            )

    def _expected_role_for_path(self, path: str) -> Optional[str]:
        prefixes = {
            "objects/records/": "records",
            "objects/transcripts/": "visible-transcript",
            "objects/deliberations/": "public-deliberation",
            "objects/reasoning/": "provider-reasoning",
        }
        for prefix, role in prefixes.items():
            if path.startswith(prefix):
                return role
        return None

    def _valid_object_address(self, path: str, digest: Any) -> bool:
        if not isinstance(digest, str) or not _HEX_64.fullmatch(digest):
            return False
        parts = PurePosixPath(path).parts
        if (
            len(parts) != 5
            or parts[0] != "objects"
            or parts[1] not in {"records", "transcripts", "deliberations", "reasoning"}
            or parts[2] != "sha256"
            or parts[3] != digest[:2]
        ):
            return False
        filename = parts[4]
        return filename == digest or filename.startswith(digest + ".")

    def _validate_layer_artifacts(
        self, layers: Any, artifacts: Any, path: str
    ) -> None:
        if not isinstance(layers, dict) or not isinstance(artifacts, list):
            return
        requirements = (
            ("visibleTranscript", "visible-transcript"),
            ("publicDeliberation", "public-deliberation"),
        )
        for layer_name, role in requirements:
            layer = layers.get(layer_name)
            if isinstance(layer, dict) and isinstance(layer.get("ref"), str):
                if not self._content_reference_resolves(layer["ref"], role, artifacts):
                    self.report.error(
                        "REASONING_LAYER_UNRESOLVED",
                        path,
                        "required reasoning-layer reference does not resolve",
                    )
        provider = layers.get("providerExposedReasoning")
        provider_artifacts = [
            item
            for item in artifacts
            if isinstance(item, dict) and item.get("role") == "provider-reasoning"
        ]
        if not isinstance(provider, dict):
            return
        if provider.get("status") != "approved-public" and provider_artifacts:
            self.report.error(
                "PROVIDER_REASONING_UNAPPROVED",
                path,
                "provider reasoning artifact requires approved-public status",
            )
        if provider.get("status") == "approved-public" and isinstance(
            provider.get("ref"), str
        ):
            if not self._content_reference_resolves(
                provider["ref"], "provider-reasoning", artifacts
            ):
                self.report.error(
                    "PROVIDER_REASONING_UNRESOLVED",
                    path,
                    "approved provider reasoning reference does not resolve",
                )

    def _content_reference_resolves(
        self, reference: str, role: str, artifacts: Sequence[Any] = ()
    ) -> bool:
        if not _HASH_REF.fullmatch(reference):
            return False
        digest = reference.removeprefix("sha256:")
        for artifact in artifacts:
            if (
                isinstance(artifact, dict)
                and artifact.get("role") == role
                and artifact.get("sha256") == digest
            ):
                return True
        stores = {
            "visible-transcript": "objects/transcripts/sha256",
            "public-deliberation": "objects/deliberations/sha256",
            "provider-reasoning": "objects/reasoning/sha256",
        }
        store = stores.get(role)
        if store is None:
            return False
        directory = self.root / store / digest[:2]
        if not directory.is_dir() or directory.is_symlink():
            return False
        for candidate in directory.glob(f"{digest}*"):
            try:
                if (
                    candidate.is_file()
                    and not candidate.is_symlink()
                    and hashlib.sha256(candidate.read_bytes()).hexdigest() == digest
                ):
                    return True
            except OSError:
                continue
        return False

    def _validate_reasoning_layers(
        self,
        layers: Any,
        path: str,
        candidate_digest: Any,
        public_digest: Any,
    ) -> None:
        if not isinstance(layers, dict):
            self.report.error(
                "REASONING_LAYERS", path, "all reasoning-layer metadata is required"
            )
            return
        for name in ("visibleTranscript", "publicDeliberation"):
            layer = layers.get(name)
            if (
                not isinstance(layer, dict)
                or layer.get("status") != "included"
                or not isinstance(layer.get("ref"), str)
                or not _HASH_REF.fullmatch(layer["ref"])
            ):
                self.report.error(
                    "REASONING_LAYER_REQUIRED",
                    path,
                    "visible transcript and public deliberation references are required",
                )
        provider = layers.get("providerExposedReasoning")
        if not isinstance(provider, dict):
            self.report.error(
                "PROVIDER_REASONING_METADATA",
                path,
                "provider-exposed reasoning availability must be explicit",
            )
            return
        status_value = provider.get("status")
        if status_value == "not-provided":
            if (
                provider.get("ref") is not None
                or provider.get("approvalReceipt") is not None
            ):
                self.report.error(
                    "PROVIDER_REASONING_ABSENT",
                    path,
                    "absent provider reasoning cannot carry a reference or receipt",
                )
            return
        if status_value != "approved-public":
            self.report.error(
                "PROVIDER_REASONING_STATUS",
                path,
                "provider-exposed reasoning status is not allowed",
            )
            return
        if not isinstance(provider.get("ref"), str) or not _HASH_REF.fullmatch(
            provider["ref"]
        ):
            self.report.error(
                "PROVIDER_REASONING_REF",
                path,
                "approved provider reasoning requires a content hash reference",
            )
        if not isinstance(provider.get("providerFormat"), str) or not provider.get(
            "providerFormat"
        ):
            self.report.error(
                "PROVIDER_REASONING_FORMAT",
                path,
                "approved provider reasoning requires its provider format",
            )
        receipt = provider.get("approvalReceipt")
        self._validate_receipt(
            receipt,
            path,
            expected_candidate=candidate_digest,
            expected_public=public_digest,
            allowed_dispositions={"approve_public"},
        )
        if not isinstance(receipt, dict):
            return
        if receipt.get("termsVerified") is not True:
            self.report.error(
                "PROVIDER_TERMS",
                path,
                "provider redistribution terms must be explicitly verified",
            )
        if receipt.get("redistributionPermitted") is not True:
            self.report.error(
                "PROVIDER_REDISTRIBUTION",
                path,
                "provider reasoning redistribution must be explicitly permitted",
            )

    def _validate_receipt(
        self,
        receipt: Any,
        path: str,
        *,
        expected_candidate: Any,
        expected_public: Any,
        allowed_dispositions: set[str],
    ) -> None:
        if not isinstance(receipt, dict):
            self.report.error(
                "REVIEW_RECEIPT_REQUIRED", path, "a matching approval receipt is required"
            )
            return
        if receipt.get("candidateSha256") != expected_candidate:
            self.report.error(
                "REVIEW_RECEIPT_CANDIDATE",
                path,
                "approval receipt does not match the candidate hash",
            )
        if receipt.get("publicArtifactSha256") != expected_public:
            self.report.error(
                "REVIEW_RECEIPT_PUBLIC",
                path,
                "approval receipt does not match the public artifact hash",
            )
        if receipt.get("policyVersion") != self.policies.version:
            self.report.error(
                "REVIEW_RECEIPT_POLICY",
                path,
                "approval receipt policy version is missing or stale",
            )
        if receipt.get("disposition") not in allowed_dispositions:
            self.report.error(
                "REVIEW_RECEIPT_DISPOSITION",
                path,
                "approval receipt disposition does not permit this publication",
            )
        reviewer = receipt.get("reviewer")
        if (
            not isinstance(reviewer, str)
            or not _REVIEWER_ID.fullmatch(reviewer)
            or reviewer not in self.policies.publication["approvedReviewerIds"]
        ):
            self.report.error(
                "REVIEW_RECEIPT_REVIEWER",
                path,
                "approval receipt reviewer identifier is invalid",
            )
        if not _is_timestamp(receipt.get("reviewedAt")):
            self.report.error(
                "REVIEW_RECEIPT_TIME",
                path,
                "approval receipt timestamp must be ISO-8601 UTC",
            )
        if receipt.get("superseded") is True:
            self.report.error(
                "REVIEW_RECEIPT_SUPERSEDED",
                path,
                "a superseded approval receipt cannot authorize publication",
            )

    def _validate_provenance(self, provenance: Any, path: str) -> None:
        if not isinstance(provenance, dict):
            self.report.error(
                "PROVENANCE_REQUIRED", path, "source provenance is required"
            )
            return
        rights_basis = provenance.get("rightsBasis")
        allowed_bases = self.policies.sources["allowedRightsBases"]
        if rights_basis not in allowed_bases:
            self.report.error(
                "SOURCE_RIGHTS_BASIS",
                path,
                "source rights basis is not synthetic or RAPPterverse-owned",
            )
            return
        statement_id = provenance.get("rightsStatementId")
        statements = self.policies.rights["statements"]
        statement = statements.get(statement_id)
        if not isinstance(statement, dict) or statement.get("rightsBasis") != rights_basis:
            self.report.error(
                "RIGHTS_STATEMENT",
                path,
                "an applicable explicit rights statement is required",
            )
            return
        explicit_statement = provenance.get("rightsStatement")
        if explicit_statement != statement.get("statement"):
            self.report.error(
                "RIGHTS_STATEMENT_TEXT",
                path,
                "explicit rights statement text is missing or does not match policy",
            )
        sources = provenance.get("sources")
        if not isinstance(sources, list) or not sources:
            self.report.error(
                "SOURCES_REQUIRED", path, "at least one allowed source is required"
            )
            return
        allowed_types = set(allowed_bases[rights_basis]["sourceTypes"])
        statement_types = set(statement.get("sourceTypes", []))
        for source in sources:
            if not isinstance(source, dict):
                self.report.error(
                    "SOURCE_INVALID", path, "source entries must be objects"
                )
                continue
            source_type = source.get("type")
            if source_type not in allowed_types or source_type not in statement_types:
                self.report.error(
                    "SOURCE_TYPE", path, "source type is not allowed by its rights statement"
                )
                continue
            if any(
                key in source
                for key in ("url", "externalUrl", "downloadUrl", "corpusUrl")
            ):
                self.report.error(
                    "SOURCE_EXTERNAL", path, "external source locations are prohibited"
                )
            if source_type in {"deterministic-synthetic", "model-generated-synthetic"}:
                source_id = source.get("sourceId")
                if not isinstance(source_id, str) or not source_id.startswith(
                    "urn:rappterverse:synthetic:"
                ):
                    self.report.error(
                        "SOURCE_SYNTHETIC_ID",
                        path,
                        "synthetic source identifier is required",
                    )
                if not isinstance(source.get("generatorCommit"), str) or not _HEX_40.fullmatch(
                    source["generatorCommit"]
                ):
                    self.report.error(
                        "SOURCE_GENERATOR_COMMIT",
                        path,
                        "synthetic source must pin a generator commit",
                    )
            elif source_type == "rappterverse-repository":
                self._validate_repository_source(source, path)
            elif source_type == "system-controlled-agent":
                self._validate_agent_source(source, path)
            elif source_type == "consented-human-judgment":
                self._validate_consented_source(source, path)

    def _validate_repository_source(self, source: dict[str, Any], path: str) -> None:
        if source.get("repository") not in self.policies.sources["allowedRepositories"]:
            self.report.error(
                "SOURCE_REPOSITORY", path, "repository source is not RAPPterverse-owned"
            )
        if not isinstance(source.get("commit"), str) or not _HEX_40.fullmatch(
            source["commit"]
        ):
            self.report.error(
                "SOURCE_COMMIT", path, "repository source must pin a full commit"
            )
        blobs = source.get("blobs")
        if not isinstance(blobs, list) or not blobs:
            self.report.error(
                "SOURCE_BLOBS", path, "repository source must pin at least one blob"
            )
            return
        for blob in blobs:
            if not isinstance(blob, dict) or not _safe_relative_path(blob.get("path")):
                self.report.error(
                    "SOURCE_BLOB", path, "source blob path is invalid"
                )
                continue
            digest = blob.get("gitBlob")
            if not isinstance(digest, str) or not (
                _HEX_40.fullmatch(digest) or _HEX_64.fullmatch(digest)
            ):
                self.report.error(
                    "SOURCE_BLOB", path, "source blob digest is invalid"
                )

    def _validate_agent_source(self, source: dict[str, Any], path: str) -> None:
        if not isinstance(source.get("agentId"), str) or not source.get("agentId"):
            self.report.error(
                "SOURCE_AGENT", path, "system-controlled agent identifier is required"
            )
        attestation = source.get("ownershipAttestation")
        if not isinstance(attestation, dict):
            self.report.error(
                "SOURCE_OWNERSHIP",
                path,
                "system-controlled agent ownership attestation is required",
            )
            return
        if (
            attestation.get("attested") is not True
            or attestation.get("license") != "CC-BY-4.0"
            or not _is_timestamp(attestation.get("attestedAt"))
        ):
            self.report.error(
                "SOURCE_OWNERSHIP",
                path,
                "agent ownership attestation is incomplete",
            )
        reviewer = attestation.get("attestedBy")
        if not isinstance(reviewer, str) or not _REVIEWER_ID.fullmatch(reviewer):
            self.report.error(
                "SOURCE_OWNERSHIP", path, "agent ownership attestor is invalid"
            )

    def _validate_consented_source(self, source: dict[str, Any], path: str) -> None:
        receipt = source.get("consentReceipt")
        if not isinstance(receipt, dict):
            self.report.error(
                "SOURCE_CONSENT", path, "public-data consent receipt is required"
            )
            return
        if (
            receipt.get("publicDataConsent") is not True
            or receipt.get("license") != "CC-BY-4.0"
            or not _is_timestamp(receipt.get("consentedAt"))
            or not isinstance(receipt.get("receiptSha256"), str)
            or not _HEX_64.fullmatch(receipt["receiptSha256"])
        ):
            self.report.error(
                "SOURCE_CONSENT", path, "public-data consent receipt is incomplete"
            )

    def _validate_governance_labels(
        self, governance: dict[str, Any], path: str
    ) -> None:
        if governance.get("privacy") != self.policies.safety["requiredPrivacyLabel"]:
            self.report.error(
                "PRIVACY_LABEL", path, "synthetic nonpersonal privacy label is required"
            )
        if governance.get("safetyStatus") != self.policies.safety["requiredSafetyStatus"]:
            self.report.error(
                "SAFETY_STATUS", path, "safety checks must have passing status"
            )
        labels = governance.get("safetyLabels")
        allowed_labels = set(self.policies.safety["allowedSafetyLabels"])
        if (
            not isinstance(labels, list)
            or not labels
            or any(not isinstance(item, str) or item not in allowed_labels for item in labels)
        ):
            self.report.error(
                "SAFETY_LABEL", path, "safety labels are missing or not allowed"
            )
        contamination = governance.get("contamination")
        label = contamination.get("label") if isinstance(contamination, dict) else None
        if label not in self.policies.quality["requiredContaminationLabels"]:
            self.report.error(
                "CONTAMINATION_LABEL", path, "approved contamination label is required"
            )
        exposure = governance.get("publicExposure")
        exposure_label = exposure.get("label") if isinstance(exposure, dict) else None
        if exposure_label != self.policies.quality["requiredPublicExposureLabel"]:
            self.report.error(
                "PUBLIC_EXPOSURE_LABEL", path, "public-exposure label is required"
            )
        if governance.get("evaluationUse") != self.policies.quality[
            "requiredEvaluationUseLabel"
        ]:
            self.report.error(
                "EVALUATION_USE_LABEL",
                path,
                "contamination-prone evaluation-use label is required",
            )

    def _validate_publication_quality(self, quality: Any, path: str) -> None:
        if not isinstance(quality, dict):
            self.report.error(
                "QUALITY_REQUIRED", path, "publication quality metrics are required"
            )
            return
        thresholds = self.policies.quality["publicationThresholds"]
        record_count = quality.get("recordCount")
        if (
            not isinstance(record_count, int)
            or isinstance(record_count, bool)
            or record_count < thresholds["minimumRecordCount"]
        ):
            self.report.error(
                "QUALITY_RECORD_COUNT", path, "publication record count is below threshold"
            )
        metrics = quality.get("metrics")
        if not isinstance(metrics, dict):
            self.report.error(
                "QUALITY_METRICS", path, "publication quality metrics are required"
            )
            return
        for name, threshold in thresholds["minimum"].items():
            value = metrics.get(name)
            if not _is_number(value) or value < threshold:
                self.report.error(
                    "QUALITY_MINIMUM", path, "a required quality minimum is not met"
                )
        for name, threshold in thresholds["maximum"].items():
            value = metrics.get(name)
            if not _is_number(value) or value > threshold:
                self.report.error(
                    "QUALITY_MAXIMUM", path, "a required quality maximum is exceeded"
                )

    def _validate_record(self, path: str, record: Any, line: int = 0) -> None:
        if not isinstance(record, dict):
            self.report.error(
                "RECORD_OBJECT", path, "public records must be JSON objects", line
            )
            return
        required = set(self.policies.fields["requiredRecordSections"])
        if not required.issubset(record):
            self.report.error(
                "RECORD_FIELDS", path, "public record envelope is incomplete", line
            )
        if record.get("schemaVersion") != "rappterverse.public-record/v1":
            self.report.error(
                "RECORD_SCHEMA", path, "public record schema version is invalid", line
            )
        self._require_dataset_id(record.get("datasetId"), path, line)
        if not isinstance(record.get("recordType"), str) or not record.get("recordType"):
            self.report.error(
                "RECORD_TYPE", path, "record type is required", line
            )
        if not isinstance(record.get("recordId"), str) or not _RECORD_ID.fullmatch(
            record["recordId"]
        ):
            self.report.error(
                "RECORD_ID", path, "content-addressed record identifier is invalid", line
            )
        if not isinstance(record.get("episodeId"), str) or not record.get("episodeId"):
            self.report.error(
                "EPISODE_ID", path, "episode identifier is required", line
            )
        if (
            not isinstance(record.get("sequence"), int)
            or isinstance(record.get("sequence"), bool)
            or record.get("sequence", -1) < 0
        ):
            self.report.error(
                "RECORD_SEQUENCE", path, "record sequence must be a nonnegative integer", line
            )
        if record.get("split") not in {"train", "validation", "test", "unsplit"}:
            self.report.error(
                "RECORD_SPLIT", path, "record split is invalid", line
            )
        if not _is_timestamp(record.get("eventTime")):
            self.report.error(
                "RECORD_TIME", path, "record event time must be ISO-8601 UTC", line
            )
        if not isinstance(record.get("payload"), dict):
            self.report.error(
                "RECORD_PAYLOAD", path, "record payload must be an object", line
            )

        self._validate_provenance(record.get("provenance"), path)
        generation = record.get("generation")
        if not isinstance(generation, dict):
            self.report.error(
                "GENERATION_REQUIRED", path, "record generation metadata is required", line
            )
        else:
            for field in ("transcriptRef", "deliberationRef"):
                value = generation.get(field)
                if not isinstance(value, str) or not _HASH_REF.fullmatch(value):
                    self.report.error(
                        "REASONING_LAYER_REQUIRED",
                        path,
                        "record requires transcript and deliberation references",
                        line,
                    )
                else:
                    role = (
                        "visible-transcript"
                        if field == "transcriptRef"
                        else "public-deliberation"
                    )
                    if not self._content_reference_resolves(value, role):
                        self.report.error(
                            "REASONING_LAYER_UNRESOLVED",
                            path,
                            "record reasoning-layer reference does not resolve",
                            line,
                        )
            provider_ref = generation.get("providerReasoningRef")
            if provider_ref is not None:
                if not isinstance(provider_ref, str) or not _HASH_REF.fullmatch(provider_ref):
                    self.report.error(
                        "PROVIDER_REASONING_REF",
                        path,
                        "provider reasoning reference is invalid",
                        line,
                    )
                elif not self._content_reference_resolves(
                    provider_ref, "provider-reasoning"
                ):
                    self.report.error(
                        "PROVIDER_REASONING_UNRESOLVED",
                        path,
                        "record provider reasoning reference does not resolve",
                        line,
                    )
                approval = generation.get("providerReasoningApprovalReceiptRef")
                embedded = generation.get("providerReasoningApprovalReceipt")
                if not (
                    isinstance(approval, str)
                    and _HASH_REF.fullmatch(approval)
                    or isinstance(embedded, dict)
                ):
                    self.report.error(
                        "PROVIDER_REASONING_APPROVAL",
                        path,
                        "provider reasoning requires an approval receipt",
                        line,
                    )

        governance = record.get("governance")
        if not isinstance(governance, dict):
            self.report.error(
                "GOVERNANCE_REQUIRED", path, "record governance metadata is required", line
            )
        else:
            if governance.get("license") != "CC-BY-4.0":
                self.report.error(
                    "LICENSE_METADATA", path, "record data license must be CC-BY-4.0", line
                )
            self._validate_governance_labels(governance, path)
            quality = governance.get("quality")
            record_thresholds = self.policies.quality["recordThresholds"]
            if (
                not isinstance(quality, dict)
                or quality.get("status") != record_thresholds["status"]
                or quality.get("verifierPassed") is not record_thresholds["verifierPassed"]
                or not _is_number(quality.get("score"))
                or quality.get("score", 0) < record_thresholds["minimumScore"]
            ):
                self.report.error(
                    "RECORD_QUALITY", path, "record quality threshold is not met", line
                )

        integrity = record.get("integrity")
        if not isinstance(integrity, dict):
            self.report.error(
                "INTEGRITY_REQUIRED", path, "record integrity metadata is required", line
            )
        else:
            payload_hash = integrity.get("payloadSha256")
            record_hash = integrity.get("recordSha256")
            if not isinstance(payload_hash, str) or not _HEX_64.fullmatch(payload_hash):
                self.report.error(
                    "PAYLOAD_HASH", path, "payload SHA-256 is invalid", line
                )
            elif isinstance(record.get("payload"), dict) and payload_hash != canonical_sha256(
                record["payload"]
            ):
                self.report.error(
                    "PAYLOAD_HASH", path, "payload SHA-256 does not match", line
                )
            if not isinstance(record_hash, str) or not _HEX_64.fullmatch(record_hash):
                self.report.error(
                    "RECORD_HASH", path, "record SHA-256 is invalid", line
                )

    def _validate_data_card(self, path: str, card: Any) -> None:
        if not isinstance(card, dict) or card.get("schema") != "rappterverse.data-card/v1":
            self.report.error(
                "DATA_CARD_SCHEMA", path, "data card schema is invalid"
            )
            return
        if card.get("policyVersion") != self.policies.version:
            self.report.error(
                "POLICY_VERSION", path, "data card policy version is missing or stale"
            )
        self._require_dataset_id(card.get("datasetId"), path)
        if card.get("licenses") != {"data": "CC-BY-4.0", "code": "Apache-2.0"}:
            self.report.error(
                "LICENSE_METADATA",
                path,
                "data card must declare CC-BY-4.0 data and Apache-2.0 code",
            )
        sources = card.get("sources")
        if not isinstance(sources, dict):
            self.report.error(
                "PROVENANCE_REQUIRED", path, "data card source metadata is required"
            )
        else:
            self._validate_provenance(
                {
                    "rightsBasis": sources.get("rightsBasis"),
                    "rightsStatementId": sources.get("rightsStatementId"),
                    "rightsStatement": sources.get("rightsStatement"),
                    "sources": sources.get("lineage"),
                },
                path,
            )
            if sources.get("boundary") != "synthetic-or-rappterverse-owned-only":
                self.report.error(
                    "SOURCE_BOUNDARY", path, "data card source boundary is invalid"
                )
        layers = card.get("reasoningLayers")
        if (
            not isinstance(layers, dict)
            or layers.get("visibleTranscript") != "included"
            or layers.get("publicDeliberation") != "included"
            or layers.get("providerExposedReasoning")
            not in {"not-provided", "approved-public"}
        ):
            self.report.error(
                "REASONING_LAYERS", path, "data card reasoning-layer declaration is invalid"
            )
        privacy = card.get("privacyAndSafety")
        if (
            not isinstance(privacy, dict)
            or privacy.get("privacy") != "synthetic-nonpersonal"
            or privacy.get("realPii") is not False
            or privacy.get("secrets") is not False
            or privacy.get("unownedContent") is not False
            or privacy.get("safetyStatus") != "pass"
        ):
            self.report.error(
                "DATA_CARD_SAFETY", path, "data card privacy and safety declaration is invalid"
            )
        contamination = card.get("contamination")
        if (
            not isinstance(contamination, dict)
            or contamination.get("label")
            not in self.policies.quality["requiredContaminationLabels"]
            or contamination.get("publicExposure")
            != self.policies.quality["requiredPublicExposureLabel"]
            or contamination.get("evaluationUse")
            != self.policies.quality["requiredEvaluationUseLabel"]
        ):
            self.report.error(
                "DATA_CARD_CONTAMINATION",
                path,
                "data card contamination and public-exposure labels are invalid",
            )
        self._validate_publication_quality(card.get("quality"), path)
        withdrawal = card.get("withdrawal")
        if not isinstance(withdrawal, dict) or withdrawal.get("policy") != (
            "append-only-tombstone"
        ):
            self.report.error(
                "WITHDRAWAL_POLICY", path, "data card withdrawal policy is invalid"
            )

    def _validate_withdrawal_set(self, candidates: list[Change]) -> None:
        policy = self.policies.withdrawal
        tombstone_paths = [
            item.path
            for item in candidates
            if item.path.startswith(policy["tombstonePathPrefix"])
        ]
        index_changed = any(item.path == policy["removalIndexPath"] for item in candidates)
        if not tombstone_paths or not index_changed:
            self.report.error(
                "WITHDRAWAL_ATOMIC",
                ".",
                "withdrawal requires both a new tombstone and removal-index update",
            )
        for item in candidates:
            if item.path in tombstone_paths and item.operation != "A":
                self.report.error(
                    "TOMBSTONE_IMMUTABLE",
                    item.path,
                    "withdrawal tombstones are append-only",
                )
        for path in tombstone_paths:
            self._validate_tombstone(path, self._parsed.get(path))
        if index_changed:
            self._validate_removal_index(
                policy["removalIndexPath"], tombstone_paths
            )

    def _validate_tombstone(self, path: str, tombstone: Any) -> None:
        policy = self.policies.withdrawal
        if not isinstance(tombstone, dict) or tombstone.get("schema") != policy[
            "tombstoneSchema"
        ]:
            self.report.error(
                "TOMBSTONE_SCHEMA", path, "withdrawal tombstone schema is invalid"
            )
            return
        if tombstone.get("policyVersion") != self.policies.version:
            self.report.error(
                "POLICY_VERSION", path, "tombstone policy version is missing or stale"
            )
        tombstone_id = tombstone.get("tombstoneId")
        if not isinstance(tombstone_id, str) or not _TOMBSTONE_ID.fullmatch(tombstone_id):
            self.report.error(
                "TOMBSTONE_ID", path, "content-addressed tombstone identifier is invalid"
            )
        target = tombstone.get("target")
        if not isinstance(target, dict):
            self.report.error(
                "TOMBSTONE_TARGET", path, "tombstone target is required"
            )
        else:
            target_path = target.get("path")
            target_hash = target.get("sha256")
            if not _safe_relative_path(target_path) or not self._is_immutable(target_path):
                self.report.error(
                    "TOMBSTONE_TARGET", path, "tombstone target must be a released path"
                )
            if not isinstance(target_hash, str) or not _HEX_64.fullmatch(target_hash):
                self.report.error(
                    "TOMBSTONE_TARGET_HASH", path, "tombstone target hash is invalid"
                )
            elif _safe_relative_path(target_path):
                try:
                    existing = (self.root / target_path).read_bytes()
                except OSError:
                    self.report.error(
                        "TOMBSTONE_TARGET",
                        path,
                        "tombstone target does not exist in the candidate tree",
                    )
                else:
                    if hashlib.sha256(existing).hexdigest() != target_hash:
                        self.report.error(
                            "TOMBSTONE_TARGET_HASH",
                            path,
                            "tombstone target hash does not match",
                        )
            record_ids = target.get("recordIds")
            if not isinstance(record_ids, list) or any(
                not isinstance(item, str) or not _RECORD_ID.fullmatch(item)
                for item in record_ids
            ):
                self.report.error(
                    "TOMBSTONE_RECORD_IDS", path, "tombstone record identifiers are invalid"
                )
        if tombstone.get("status") != policy["requiredStatus"]:
            self.report.error(
                "TOMBSTONE_STATUS", path, "tombstone status is invalid"
            )
        if tombstone.get("reasonCode") not in policy["allowedReasonCodes"]:
            self.report.error(
                "TOMBSTONE_REASON", path, "tombstone reason code is invalid"
            )
        public_reason = tombstone.get("publicReason")
        if (
            not isinstance(public_reason, str)
            or not public_reason.strip()
            or len(public_reason) > 500
        ):
            self.report.error(
                "TOMBSTONE_PUBLIC_REASON",
                path,
                "tombstone public reason must be brief and redacted",
            )
        for key in ("requestedAt", "reviewedAt"):
            if not _is_timestamp(tombstone.get(key)):
                self.report.error(
                    "TOMBSTONE_TIME", path, "tombstone timestamps must be ISO-8601 UTC"
                )
        reviewer = tombstone.get("reviewer")
        if (
            not isinstance(reviewer, str)
            or not _REVIEWER_ID.fullmatch(reviewer)
            or reviewer not in self.policies.publication["approvedReviewerIds"]
        ):
            self.report.error(
                "TOMBSTONE_REVIEWER", path, "tombstone reviewer identifier is invalid"
            )
        if tombstone.get("originalRemainsAvailable") is not True:
            self.report.error(
                "TOMBSTONE_PRESERVATION",
                path,
                "withdrawal must preserve the original released bytes",
            )
        if tombstone.get("license") != "CC-BY-4.0":
            self.report.error(
                "LICENSE_METADATA", path, "tombstone data license must be CC-BY-4.0"
            )

    def _validate_removal_index(
        self, path: str, changed_tombstones: list[str]
    ) -> None:
        value = self._parsed.get(path)
        if not isinstance(value, dict) or value.get("schema") != (
            "rappterverse.removals/v1"
        ):
            self.report.error(
                "REMOVAL_INDEX_SCHEMA", path, "removal index schema is invalid"
            )
            return
        if value.get("policyVersion") != self.policies.version:
            self.report.error(
                "POLICY_VERSION", path, "removal index policy version is missing or stale"
            )
        removals = value.get("removals")
        if not isinstance(removals, list):
            self.report.error(
                "REMOVAL_INDEX", path, "removal index entries must be an array"
            )
            return
        references = {
            item.get("tombstone")
            for item in removals
            if isinstance(item, dict)
            and item.get("status") == self.policies.withdrawal["requiredStatus"]
        }
        if not set(changed_tombstones).issubset(references):
            self.report.error(
                "REMOVAL_INDEX_COVERAGE",
                path,
                "removal index must reference every new tombstone",
            )
        previous = self._read_base_json(path)
        if previous is None:
            return
        old_removals = previous.get("removals") if isinstance(previous, dict) else None
        if not isinstance(old_removals, list) or removals[: len(old_removals)] != old_removals:
            self.report.error(
                "REMOVAL_INDEX_APPEND_ONLY",
                path,
                "existing removal-index entries cannot be changed or reordered",
            )

    def _read_base_bytes(self, path: str) -> Optional[bytes]:
        if self.base_revision is None:
            return None
        if not _safe_relative_path(path):
            return None
        tree = subprocess.run(
            ["git", "ls-tree", "-z", self.base_revision, "--", path],
            cwd=self.root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        entries = tree.stdout.rstrip(b"\0").split(b"\0")
        if tree.returncode != 0 or len(entries) != 1 or not entries[0]:
            return None
        try:
            metadata, encoded_path = entries[0].split(b"\t", 1)
            mode, object_type, _ = metadata.split(b" ", 2)
            listed_path = encoded_path.decode("utf-8", errors="strict")
        except (UnicodeError, ValueError):
            return None
        if (
            listed_path != path
            or object_type != b"blob"
            or mode not in {b"100644", b"100755"}
        ):
            return None
        process = subprocess.run(
            ["git", "show", f"{self.base_revision}:{path}"],
            cwd=self.root,
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if process.returncode != 0:
            return None
        if len(process.stdout) > self.policies.publication["limits"]["fileHardBytes"]:
            return None
        return process.stdout

    def _trusted_predecessor_anchor(
        self,
    ) -> Optional[TrustedPredecessorAnchor]:
        latest_bytes = self._read_base_bytes("catalog/latest.json")
        if latest_bytes is None:
            if self.base_revision is not None:
                self.report.error(
                    "BASE_PREDECESSOR_INVALID",
                    "catalog/latest.json",
                    "trusted base latest pointer is unavailable",
                )
            return None
        try:
            latest = _strict_json_loads(latest_bytes.decode("utf-8"))
        except (UnicodeError, ValueError):
            self.report.error(
                "BASE_PREDECESSOR_INVALID",
                "catalog/latest.json",
                "trusted base latest pointer cannot be validated",
            )
            return None
        if (
            not isinstance(latest, dict)
            or latest.get("schemaVersion")
            != "rappterverse.catalog-latest-pointer/v2"
        ):
            if (
                isinstance(latest, dict)
                and latest.get("schema") == "rappterverse.latest/v1"
                and latest.get("release") is None
            ):
                return None
            self.report.error(
                "BASE_PREDECESSOR_INVALID",
                "catalog/latest.json",
                "trusted base latest pointer has an unknown release state",
            )
            return None
        try:
            return TrustedPredecessorAnchor.from_release_graph(
                self.root,
                self.v2_registry,
                self.policies.trust_document_bytes,
                self.policies.rights_v2_document_bytes,
                artifact_reader=self._read_base_bytes,
            )
        except ValueError:
            self.report.error(
                "BASE_PREDECESSOR_INVALID",
                "catalog/latest.json",
                "trusted base release graph cannot anchor a successor",
            )
            return None

    def _read_base_json(self, path: str) -> Optional[Any]:
        data = self._read_base_bytes(path)
        if data is None:
            return None
        try:
            return _strict_json_loads(data.decode("utf-8"))
        except (UnicodeError, ValueError):
            self.report.error(
                "BASE_STATE_INVALID", path, "base removal index cannot be validated"
            )
            return None

    def _require_dataset_id(
        self, value: Any, path: str, line: int = 0
    ) -> None:
        if not isinstance(value, str) or not _DATASET_ID.fullmatch(value):
            self.report.error(
                "DATASET_ID", path, "dataset identifier is invalid", line
            )
