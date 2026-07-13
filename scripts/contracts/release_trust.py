# SPDX-License-Identifier: Apache-2.0

"""Semantic validation for the public release v2 graph."""

from __future__ import annotations

import hashlib
import re
import stat
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from types import MappingProxyType
from typing import (
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Set,
    Tuple,
)

from .canonical import (
    MAX_JSON_NESTING_DEPTH,
    CanonicalJSONV2Error,
    CanonicalJSONV2DepthError,
    canonical_json_v2,
    parse_json_v2,
)
from .registry import (
    ARTIFACT_KIND_TO_SCHEMA_VERSION,
    JSONL_ARTIFACT_KIND_TO_SCHEMA_VERSION,
    TrustedSchemaRegistry,
)
from .validator import ContractValidator

_OBJECT_PATH = re.compile(
    r"^objects/[a-z0-9-]+/sha256/([0-9a-f]{2})/([0-9a-f]{64})"
    r"\.(?:json|jsonl|txt)$"
)
_RELEASE_POINTER_PATH = re.compile(
    r"^catalog/releases/(release-[0-9]{4}-[0-9]{2}-[0-9]{2}-"
    r"[a-z0-9][a-z0-9.-]{0,63})\.json$"
)
_RELEASE_MANIFEST_PATH = re.compile(
    r"^releases/(release-[0-9]{4}-[0-9]{2}-[0-9]{2}-"
    r"[a-z0-9][a-z0-9.-]{0,63})/manifest\.json$"
)
_DATASET_MANIFEST_PATH = re.compile(
    r"^releases/(release-[0-9]{4}-[0-9]{2}-[0-9]{2}-"
    r"[a-z0-9][a-z0-9.-]{0,63})/datasets/"
    r"(d(?:0[1-9]|10)-[a-z0-9]+(?:-[a-z0-9]+)*)\.json$"
)
_FORMAL_V2 = re.compile(r"^rappterverse\.[a-z0-9-]+/v2$")
_RAW_ARTIFACT_FIELDS = (
    "path",
    "artifactKind",
    "mediaType",
    "bytes",
    "sha256",
)
_RIGHTS_ATTESTATIONS = {
    "deterministic-synthetic": {"generatorCommit", "sourceId"},
    "model-generated-synthetic": {"generatorCommit", "sourceId"},
    "rappterverse-repository": {
        "blobSha256",
        "commit",
        "path",
        "repository",
    },
    "system-controlled-agent": {"agentId", "ownershipEvidence"},
    "consented-human-judgment": {
        "consentEvidence",
        "consentedAt",
        "license",
        "publicDataConsent",
    },
}
_RIGHTS_BASIS_BY_SOURCE = {
    "deterministic-synthetic": "synthetic",
    "model-generated-synthetic": "synthetic",
    "rappterverse-repository": "rappterverse-owned",
    "system-controlled-agent": "rappterverse-owned",
    "consented-human-judgment": "rappterverse-owned",
}
_ID_FIELD_BY_SHARD_KIND = {
    "record-shard": "recordId",
    "transcript-shard": "transcriptId",
    "deliberation-shard": "deliberationId",
    "provider-reasoning-shard": "reasoningId",
}
_COUNT_FIELD_BY_SHARD_KIND = {
    "record-shard": "records",
    "transcript-shard": "transcripts",
    "deliberation-shard": "deliberations",
    "provider-reasoning-shard": "providerReasoning",
}
_RECEIPT_SCOPE_KINDS = {
    "dataset-leaves": {
        "record-shard",
        "transcript-shard",
        "deliberation-shard",
        "provider-reasoning-shard",
        "data-card",
        "provider-terms",
        "review-evidence",
        "projection-recipe",
        "world-pack-source",
    },
    "dataset-manifests": {"dataset-manifest"},
    "release": {"release-manifest", "active-review-set"},
    "catalog-pointer": {"catalog-release-pointer"},
}
_OBJECT_CONTRACT_BY_KIND = {
    "record-shard": ("records", {"application/x-ndjson": "jsonl"}),
    "transcript-shard": (
        "transcripts",
        {"application/x-ndjson": "jsonl"},
    ),
    "deliberation-shard": (
        "deliberations",
        {"application/x-ndjson": "jsonl"},
    ),
    "provider-reasoning-shard": (
        "provider-reasoning",
        {"application/x-ndjson": "jsonl"},
    ),
    "data-card": ("data-cards", {"application/json": "json"}),
    "provider-terms": ("provider-terms", {"text/plain": "txt"}),
    "review-evidence": (
        "review-evidence",
        {"application/json": "json", "text/plain": "txt"},
    ),
    "projection-recipe": (
        "projection-recipes",
        {"application/json": "json"},
    ),
    "world-pack-source": (
        "world-pack-sources",
        {"application/json": "json"},
    ),
    "active-review-set": (
        "active-review-sets",
        {"application/json": "json"},
    ),
}


@dataclass(frozen=True, order=True)
class TrustDiagnostic:
    """One bounded, deterministic, value-free semantic diagnostic."""

    path: str
    code: str
    message: str


ArtifactReader = Callable[[str], Optional[bytes]]


@dataclass(frozen=True)
class TrustedPredecessorAnchor:
    """Exact trusted-base latest pointer and its validated immutable closure."""

    latest_bytes: bytes
    pointer_descriptor: Mapping[str, Any]
    pointer_bytes: bytes
    release_id: str
    sequence: int
    immutable_closure: Mapping[str, bytes]

    @classmethod
    def from_release_graph(
        cls,
        root: Path,
        registry: TrustedSchemaRegistry,
        trusted_policy_bytes: bytes,
        trusted_rights_bytes: bytes,
        *,
        latest_path: str = "catalog/latest.json",
        artifact_reader: Optional[ArtifactReader] = None,
    ) -> "TrustedPredecessorAnchor":
        """Validate trusted-base bytes and freeze the exact predecessor anchor."""

        validator = ReleaseTrustValidator(
            root,
            registry,
            trusted_policy_bytes,
            trusted_rights_bytes,
            artifact_reader=artifact_reader,
            _trusted_anchor_validation=True,
        )
        diagnostics = validator.validate_release_graph(latest_path)
        if diagnostics:
            raise ValueError("trusted predecessor release graph is invalid")
        latest = validator._json.get(latest_path)
        if not isinstance(latest, dict):
            raise ValueError("trusted predecessor latest pointer is unavailable")
        pointer_descriptor = latest.get("releasePointer")
        if not isinstance(pointer_descriptor, dict):
            raise ValueError("trusted predecessor pointer descriptor is unavailable")
        pointer_path = pointer_descriptor.get("path")
        if not isinstance(pointer_path, str):
            raise ValueError("trusted predecessor pointer path is unavailable")
        pointer = validator._json.get(pointer_path)
        pointer_bytes = validator._bytes.get(pointer_path)
        latest_bytes = validator._bytes.get(latest_path)
        if (
            not isinstance(pointer, dict)
            or not isinstance(pointer_bytes, bytes)
            or not isinstance(latest_bytes, bytes)
            or not isinstance(pointer.get("releaseId"), str)
            or isinstance(pointer.get("sequence"), bool)
            or not isinstance(pointer.get("sequence"), int)
        ):
            raise ValueError("trusted predecessor pointer is malformed")
        closure = {
            path: data
            for path, data in validator._bytes.items()
            if path != latest_path
        }
        if pointer_path not in closure:
            raise ValueError("trusted predecessor pointer is outside its closure")
        return cls(
            latest_bytes=bytes(latest_bytes),
            pointer_descriptor=MappingProxyType(
                dict(pointer_descriptor)
            ),
            pointer_bytes=bytes(pointer_bytes),
            release_id=pointer["releaseId"],
            sequence=pointer["sequence"],
            immutable_closure=MappingProxyType(dict(closure)),
        )


def _safe_path(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        or unicodedata.normalize("NFC", value) != value
    ):
        return False
    candidate = PurePosixPath(value)
    return (
        not candidate.is_absolute()
        and str(candidate) == value
        and all(part not in {"", ".", ".."} for part in candidate.parts)
    )


def _raw_descriptor(value: Mapping[str, Any]) -> Dict[str, Any]:
    return {name: value.get(name) for name in _RAW_ARTIFACT_FIELDS}


def _descriptor_sort_key(value: Mapping[str, Any]) -> Tuple[str, str]:
    return (str(value.get("path")), str(value.get("sha256")))


def _walk_mappings(value: Any) -> Iterable[Mapping[str, Any]]:
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, Mapping):
            yield item
            stack.extend(item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend(item)


def object_path_matches_sha256(path: str, digest: str) -> bool:
    """Return whether an object-store path is the address of raw-byte digest."""

    match = _OBJECT_PATH.fullmatch(path)
    return bool(
        match is not None
        and match.group(1) == digest[:2]
        and match.group(2) == digest
    )


def review_supersession_diagnostics(
    receipts: Mapping[str, Mapping[str, Any]],
    declared_heads: Iterable[str],
    required_heads: Iterable[str],
) -> Tuple[TrustDiagnostic, ...]:
    """Validate fork-free, acyclic supersession and current approval heads."""

    successors: Dict[str, List[str]] = {path: [] for path in receipts}
    predecessors: Dict[str, Optional[str]] = {}
    diagnostics: List[TrustDiagnostic] = []
    for path, receipt in sorted(receipts.items()):
        predecessor = receipt.get("predecessor")
        predecessor_path = (
            predecessor.get("path") if isinstance(predecessor, dict) else None
        )
        predecessors[path] = predecessor_path
        if predecessor_path is None:
            continue
        if predecessor_path not in receipts:
            diagnostics.append(
                TrustDiagnostic(
                    path,
                    "REVIEW_PREDECESSOR",
                    "receipt predecessor is absent from the active review set",
                )
            )
            continue
        successors[predecessor_path].append(path)
    for path, children in sorted(successors.items()):
        if len(children) > 1:
            diagnostics.append(
                TrustDiagnostic(
                    path,
                    "REVIEW_FORK",
                    "one receipt has multiple superseding successors",
                )
            )

    visiting: Set[str] = set()
    visited: Set[str] = set()

    def visit(node: str) -> None:
        if node in visiting:
            diagnostics.append(
                TrustDiagnostic(
                    node,
                    "REVIEW_CYCLE",
                    "receipt supersession contains a cycle",
                )
            )
            return
        if node in visited:
            return
        visiting.add(node)
        predecessor = predecessors.get(node)
        if predecessor in receipts:
            visit(str(predecessor))
        visiting.remove(node)
        visited.add(node)

    for path in sorted(receipts):
        visit(path)

    calculated_heads = {
        path for path, children in successors.items() if not children
    }
    declared = set(declared_heads)
    required = set(required_heads)
    if declared != calculated_heads:
        diagnostics.append(
            TrustDiagnostic(
                ".",
                "REVIEW_HEADS",
                "declared heads do not equal supersession heads",
            )
        )
    if declared != required:
        diagnostics.append(
            TrustDiagnostic(
                ".",
                "REVIEW_SET_STALE",
                "active heads do not equal governed receipt references",
            )
        )
    for path in sorted(declared):
        receipt = receipts.get(path)
        if receipt is not None and receipt.get("disposition") != "approve_public":
            diagnostics.append(
                TrustDiagnostic(
                    path,
                    "REVIEW_HEAD_REJECT",
                    "active review head must approve public release",
                )
            )
    return tuple(sorted(set(diagnostics)))


class ReleaseTrustValidator:
    """Validate exact bytes and cross-document semantics for one v2 release."""

    def __init__(
        self,
        root: Path,
        registry: TrustedSchemaRegistry,
        trusted_policy_bytes: bytes,
        trusted_rights_bytes: bytes,
        *,
        trusted_predecessor_anchor: Optional[
            TrustedPredecessorAnchor
        ] = None,
        artifact_reader: Optional[ArtifactReader] = None,
        max_diagnostics: int = 50,
        _trusted_anchor_validation: bool = False,
    ) -> None:
        self.root = Path(root).resolve()
        self.registry = registry
        self.contracts = ContractValidator(
            registry.schemas_by_id, max_diagnostics=max_diagnostics
        )
        self.max_diagnostics = max_diagnostics
        self._diagnostics: List[TrustDiagnostic] = []
        self._bytes: Dict[str, bytes] = {}
        self._json: Dict[str, Any] = {}
        self._receipts: Dict[str, Dict[str, Any]] = {}
        self._descriptors_by_receipt: Dict[str, List[Dict[str, Any]]] = {}
        self._registered_descriptor_paths: Set[str] = set()
        self._governed_receipt_refs: Set[str] = set()
        self._provider_terms_by_receipt: Dict[str, List[Dict[str, Any]]] = {}
        self._record_ids: Set[str] = set()
        self.trusted_predecessor_anchor = trusted_predecessor_anchor
        self._artifact_reader = artifact_reader
        self._trusted_anchor_validation = _trusted_anchor_validation

        self.trusted_policy_bytes = trusted_policy_bytes
        try:
            policy = parse_json_v2(trusted_policy_bytes)
        except CanonicalJSONV2Error as exc:
            raise ValueError("trusted v2 policy is not strict JSON") from exc
        if canonical_json_v2(policy, stored=True) != trusted_policy_bytes:
            raise ValueError("trusted v2 policy is not canonical stored JSON")
        if not isinstance(policy, dict):
            raise ValueError("trusted v2 policy must be an object")
        schema_version = policy.get("schemaVersion")
        schema = registry.schema_for_version(str(schema_version))
        errors = self.contracts.validate(policy, schema)
        if errors:
            raise ValueError("trusted v2 policy violates its contract")
        self.policy = policy
        self.policy_ref = {
            "policyId": policy["policyId"],
            "policyVersion": policy["policyVersion"],
            "path": "policies/publication-trust-v2.json",
            "sha256": hashlib.sha256(trusted_policy_bytes).hexdigest(),
        }
        self.trusted_rights_bytes = trusted_rights_bytes
        try:
            rights = parse_json_v2(trusted_rights_bytes)
        except CanonicalJSONV2Error as exc:
            raise ValueError("trusted v2 rights registry is not strict JSON") from exc
        if canonical_json_v2(rights, stored=True) != trusted_rights_bytes:
            raise ValueError("trusted v2 rights registry is not canonical stored JSON")
        if not isinstance(rights, dict):
            raise ValueError("trusted v2 rights registry must be an object")
        if rights.get("schemaVersion") != "rappterverse.rights-statements/v2":
            raise ValueError("trusted v2 rights registry identity is invalid")
        rights_schema = registry.schema_for_version(
            "rappterverse.rights-statements/v2"
        )
        if self.contracts.validate(rights, rights_schema):
            raise ValueError("trusted v2 rights registry violates its contract")
        expected_rights_ref = {
            "schemaVersion": "rappterverse.rights-statements/v2",
            "path": "policies/rights-statements-v2.json",
            "bytes": len(trusted_rights_bytes),
            "sha256": hashlib.sha256(trusted_rights_bytes).hexdigest(),
        }
        if policy.get("rightsRegistry") != expected_rights_ref:
            raise ValueError(
                "trusted v2 policy does not pin the trusted rights registry"
            )
        statements = rights.get("statements")
        if not isinstance(statements, list):
            raise ValueError("trusted v2 rights statements are unavailable")
        statement_ids = [
            item.get("rightsStatementId")
            for item in statements
            if isinstance(item, dict)
        ]
        if (
            len(statement_ids) != len(statements)
            or statement_ids != sorted(statement_ids)
            or len(statement_ids) != len(set(statement_ids))
        ):
            raise ValueError("trusted v2 rights statement registry is not closed")
        active_source_types: Set[str] = set()
        for statement in statements:
            if not isinstance(statement, dict):
                raise ValueError("trusted v2 rights statement is malformed")
            source_types = statement.get("sourceTypes")
            attestations = statement.get("attestations")
            if not isinstance(source_types, list) or not isinstance(
                attestations, list
            ):
                raise ValueError("trusted v2 rights statement is malformed")
            attestation_map = {
                item.get("sourceType"): item.get("requiredFields")
                for item in attestations
                if isinstance(item, dict)
            }
            if (
                len(attestation_map) != len(attestations)
                or set(attestation_map) != set(source_types)
                or any(
                    set(attestation_map.get(source_type, []))
                    != _RIGHTS_ATTESTATIONS.get(source_type)
                    or statement.get("rightsBasis")
                    != _RIGHTS_BASIS_BY_SOURCE.get(source_type)
                    for source_type in source_types
                )
            ):
                raise ValueError(
                    "trusted v2 rights attestations are incomplete"
                )
            if statement.get("status") == "active":
                active_source_types.update(source_types)
        if active_source_types != set(_RIGHTS_ATTESTATIONS):
            raise ValueError(
                "trusted v2 rights registry lacks active source coverage"
            )
        self.rights_registry = rights
        self.rights_statements = {
            item["rightsStatementId"]: item for item in statements
        }

    @property
    def diagnostics(self) -> Tuple[TrustDiagnostic, ...]:
        return tuple(sorted(set(self._diagnostics))[: self.max_diagnostics])

    @property
    def ok(self) -> bool:
        return not self.diagnostics

    @property
    def validated_paths(self) -> Tuple[str, ...]:
        """Repository paths read while closing the current release graph."""

        return tuple(sorted(self._bytes))

    def _add(self, path: str, code: str, message: str) -> None:
        if len(self._diagnostics) < self.max_diagnostics:
            safe_path = path if _safe_path(path) or path == "." else "<invalid-path>"
            self._diagnostics.append(TrustDiagnostic(safe_path, code, message))

    def validate_formal_json_bytes(
        self,
        path: str,
        data: bytes,
        *,
        expected_schema_version: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        """Validate one stored formal v2 JSON artifact against the trusted map."""

        try:
            value = parse_json_v2(data)
        except CanonicalJSONV2DepthError:
            self._add(
                path,
                "JSON_DEPTH",
                "JSON nesting exceeds maximum depth {}".format(
                    MAX_JSON_NESTING_DEPTH
                ),
            )
            return None
        except CanonicalJSONV2Error:
            self._add(path, "V2_JSON_INVALID", "formal v2 JSON is not strict")
            return None
        if not isinstance(value, dict):
            self._add(path, "V2_JSON_OBJECT", "formal v2 JSON must be an object")
            return None
        if canonical_json_v2(value, stored=True) != data:
            self._add(
                path,
                "V2_JSON_CANONICAL",
                "stored formal v2 JSON must use project canonical v2 bytes and LF",
            )
        schema_version = value.get("schemaVersion")
        if (
            expected_schema_version is not None
            and schema_version != expected_schema_version
        ):
            self._add(
                path,
                "V2_SCHEMA_KIND",
                "artifact kind does not match its schemaVersion",
            )
        if not isinstance(schema_version, str) or schema_version not in self.registry.schemas_by_version:
            code = (
                "V2_SCHEMA_UNKNOWN"
                if isinstance(schema_version, str)
                and _FORMAL_V2.fullmatch(schema_version)
                else "V2_SCHEMA_REQUIRED"
            )
            self._add(path, code, "formal v2 schemaVersion is not trusted")
            if expected_schema_version is None:
                return value
        selected_version = expected_schema_version or schema_version
        if not isinstance(selected_version, str):
            return value
        schema = self.registry.schema_for_version(selected_version)
        for item in self.contracts.validate(value, schema):
            self._add(
                path,
                "CONTRACT_{}".format(item.code),
                "formal v2 artifact violates its closed contract at {}".format(
                    item.path
                ),
            )
        return value

    def validate_jsonl_bytes(
        self, path: str, data: bytes, artifact_kind: str
    ) -> List[Dict[str, Any]]:
        """Validate every canonical line under the closed shard-kind map."""

        expected = JSONL_ARTIFACT_KIND_TO_SCHEMA_VERSION.get(artifact_kind)
        if expected is None:
            self._add(
                path,
                "V2_SHARD_KIND_UNKNOWN",
                "JSONL artifact kind is not trusted",
            )
            return []
        if not data.endswith(b"\n"):
            self._add(path, "V2_JSONL_LF", "v2 JSONL must end in one LF")
            return []
        bodies = data[:-1].split(b"\n")
        if not bodies or any(not body for body in bodies):
            self._add(path, "V2_JSONL_EMPTY", "v2 JSONL contains an empty line")
            return []
        values: List[Dict[str, Any]] = []
        for number, body in enumerate(bodies, start=1):
            if len(body) + 1 > 262144:
                self._add(
                    path,
                    "V2_JSONL_LINE_SIZE",
                    "v2 JSONL line exceeds the hard byte limit",
                )
                continue
            try:
                value = parse_json_v2(body)
            except CanonicalJSONV2DepthError:
                self._add(
                    path,
                    "JSON_DEPTH",
                    "JSONL value exceeds maximum depth {}".format(
                        MAX_JSON_NESTING_DEPTH
                    ),
                )
                continue
            except CanonicalJSONV2Error:
                self._add(
                    path,
                    "V2_JSONL_INVALID",
                    "v2 JSONL line is not strict JSON",
                )
                continue
            if not isinstance(value, dict):
                self._add(
                    path,
                    "V2_JSONL_OBJECT",
                    "v2 JSONL line must be an object",
                )
                continue
            if canonical_json_v2(value, stored=True) != body + b"\n":
                self._add(
                    path,
                    "V2_JSONL_CANONICAL",
                    "v2 JSONL line is not project canonical v2",
                )
            if value.get("schemaVersion") != expected:
                self._add(
                    path,
                    "V2_SCHEMA_KIND",
                    "JSONL line schemaVersion does not match artifact kind",
                )
                continue
            schema = self.registry.schema_for_version(expected)
            for item in self.contracts.validate(value, schema):
                self._add(
                    path,
                    "CONTRACT_{}".format(item.code),
                    "v2 JSONL line violates its closed contract at line {} {}".format(
                        number, item.path
                    ),
                )
            values.append(value)
        return values

    def _read(self, path: str) -> Optional[bytes]:
        if path in self._bytes:
            return self._bytes[path]
        if not _safe_path(path):
            self._add(path, "PATH_UNSAFE", "artifact path is not canonical")
            return None
        if self._artifact_reader is not None:
            try:
                data = self._artifact_reader(path)
            except (OSError, UnicodeError, ValueError):
                data = None
            if not isinstance(data, bytes):
                self._add(path, "FILE_MISSING", "referenced artifact is unavailable")
                return None
        else:
            candidate = self.root / path
            try:
                resolved = candidate.resolve(strict=True)
                resolved.relative_to(self.root)
                if resolved != candidate:
                    self._add(
                        path,
                        "SYMLINK_FORBIDDEN",
                        "artifact path may not traverse a symbolic link",
                    )
                    return None
                mode = candidate.lstat().st_mode
                if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
                    self._add(path, "FILE_TYPE", "artifact must be a regular file")
                    return None
                data = candidate.read_bytes()
            except (OSError, ValueError):
                self._add(path, "FILE_MISSING", "referenced artifact is unavailable")
                return None
        if len(data) > 1000000:
            self._add(path, "FILE_SIZE", "artifact exceeds one megabyte")
            return None
        self._bytes[path] = data
        return data

    def _load_json(
        self, path: str, expected_schema_version: str
    ) -> Optional[Dict[str, Any]]:
        if path in self._json:
            value = self._json[path]
            return value if isinstance(value, dict) else None
        data = self._read(path)
        if data is None:
            return None
        value = self.validate_formal_json_bytes(
            path, data, expected_schema_version=expected_schema_version
        )
        if value is not None:
            self._json[path] = value
        return value

    def _check_receipt_address(self, path: str, digest: str) -> None:
        expected = "objects/review-receipts/sha256/{}/{}.json".format(
            digest[:2], digest
        )
        if path != expected:
            self._add(
                path,
                "OBJECT_ADDRESS",
                "review receipt path does not equal its kind-specific raw-byte address",
            )

    def _check_descriptor_path(
        self, descriptor: Mapping[str, Any], digest: str
    ) -> None:
        path = descriptor.get("path")
        kind = descriptor.get("artifactKind")
        media_type = descriptor.get("mediaType")
        if not isinstance(path, str) or not isinstance(kind, str):
            return

        object_contract = _OBJECT_CONTRACT_BY_KIND.get(kind)
        if object_contract is not None:
            namespace, extensions = object_contract
            extension = extensions.get(str(media_type))
            expected = (
                "objects/{}/sha256/{}/{}.{}".format(
                    namespace, digest[:2], digest, extension
                )
                if extension is not None and len(digest) == 64
                else None
            )
            if path != expected:
                self._add(
                    path,
                    "ARTIFACT_PATH",
                    "artifact path does not equal its kind-specific raw-byte address",
                )
            return

        valid_control_path = (
            kind == "dataset-manifest"
            and media_type == "application/json"
            and _DATASET_MANIFEST_PATH.fullmatch(path) is not None
        ) or (
            kind == "release-manifest"
            and media_type == "application/json"
            and _RELEASE_MANIFEST_PATH.fullmatch(path) is not None
        ) or (
            kind == "catalog-release-pointer"
            and media_type == "application/json"
            and _RELEASE_POINTER_PATH.fullmatch(path) is not None
        )
        if not valid_control_path:
            self._add(
                path,
                "ARTIFACT_PATH",
                "artifact kind is not permitted at this repository path",
            )

    def _verify_descriptor(
        self,
        descriptor: Mapping[str, Any],
        *,
        expected_kind: Optional[str] = None,
        expected_media_type: Optional[str] = None,
        reviewed: bool = True,
        register: bool = True,
        governed: bool = False,
    ) -> Optional[bytes]:
        path = descriptor.get("path")
        if not isinstance(path, str):
            self._add(".", "DESCRIPTOR_PATH", "artifact descriptor path is invalid")
            return None
        if expected_kind is not None and descriptor.get("artifactKind") != expected_kind:
            self._add(path, "DESCRIPTOR_KIND", "artifact descriptor kind is wrong")
        if (
            expected_media_type is not None
            and descriptor.get("mediaType") != expected_media_type
        ):
            self._add(path, "DESCRIPTOR_MEDIA", "artifact media type is wrong")
        data = self._read(path)
        digest = hashlib.sha256(data).hexdigest() if data is not None else ""
        if data is not None:
            if (
                descriptor.get("artifactKind")
                in {"data-card", "dataset-manifest", "release-manifest"}
                and len(data) > 512000
            ):
                self._add(
                    path,
                    "MANIFEST_SIZE",
                    "card or manifest exceeds the policy hard byte limit",
                )
            if descriptor.get("bytes") != len(data):
                self._add(path, "DESCRIPTOR_BYTES", "artifact byte count does not match")
            if descriptor.get("sha256") != digest:
                self._add(path, "DESCRIPTOR_HASH", "artifact SHA-256 does not match")
            self._check_descriptor_path(descriptor, digest)

        if reviewed:
            receipt_ref = descriptor.get("reviewReceiptRef")
            if not isinstance(receipt_ref, str):
                self._add(
                    path,
                    "REVIEW_REF",
                    "reviewed artifact has no immutable receipt reference",
                )
            elif register:
                raw = _raw_descriptor(descriptor)
                if path in self._registered_descriptor_paths:
                    self._add(
                        path,
                        "ARTIFACT_DUPLICATE",
                        "artifact path is referenced more than once in the graph",
                    )
                else:
                    self._registered_descriptor_paths.add(path)
                    self._descriptors_by_receipt.setdefault(receipt_ref, []).append(raw)
                if governed:
                    self._governed_receipt_refs.add(receipt_ref)
        return data

    def _check_policy_ref(self, path: str, value: Any) -> None:
        if value != self.policy_ref:
            self._add(
                path,
                "POLICY_REF",
                "artifact does not pin the trusted policy identity and bytes",
            )

    def _validate_record_rights(
        self,
        path: str,
        record: Mapping[str, Any],
        supporting_pairs: Set[Tuple[Any, Any]],
        supporting_kind_by_pair: Mapping[Tuple[Any, Any], Any],
    ) -> None:
        provenance = record.get("provenance")
        if not isinstance(provenance, dict):
            return
        statement_id = provenance.get("rightsStatementId")
        statement = self.rights_statements.get(statement_id)
        if not isinstance(statement, dict):
            self._add(
                path,
                "RIGHTS_STATEMENT_UNKNOWN",
                "record rights statement is not in the trusted registry",
            )
            return
        if statement.get("status") != "active":
            self._add(
                path,
                "RIGHTS_STATEMENT_REVOKED",
                "record rights statement is not active",
            )
        if provenance.get("rightsBasis") != statement.get("rightsBasis"):
            self._add(
                path,
                "RIGHTS_BASIS_MISMATCH",
                "record rights basis does not match its registered statement",
            )
        sources = provenance.get("sources")
        if not isinstance(sources, list):
            return
        allowed_types = set(statement.get("sourceTypes", []))
        attestation_by_type = {
            item.get("sourceType"): item.get("requiredFields")
            for item in statement.get("attestations", [])
            if isinstance(item, dict)
            and isinstance(item.get("sourceType"), str)
            and isinstance(item.get("requiredFields"), list)
        }
        source_types: Set[str] = set()
        for source in sources:
            if not isinstance(source, dict):
                continue
            source_type = source.get("sourceType")
            if not isinstance(source_type, str):
                continue
            source_types.add(source_type)
            if source_type not in allowed_types:
                self._add(
                    path,
                    "RIGHTS_SOURCE_TYPE",
                    "record source type is not authorized by its rights statement",
                )
                continue
            required_fields = attestation_by_type.get(source_type)
            if not isinstance(required_fields, list) or any(
                field not in source
                or source.get(field) is None
                or source.get(field) == ""
                for field in required_fields
            ):
                self._add(
                    path,
                    "RIGHTS_ATTESTATION_MISSING",
                    "record source lacks a registered ownership or consent attestation",
                )
            evidence_field = {
                "system-controlled-agent": "ownershipEvidence",
                "consented-human-judgment": "consentEvidence",
            }.get(source_type)
            if evidence_field is None:
                continue
            evidence = source.get(evidence_field)
            pair = (
                evidence.get("artifactPath"),
                evidence.get("artifactSha256"),
            ) if isinstance(evidence, dict) else (None, None)
            if (
                pair not in supporting_pairs
                or supporting_kind_by_pair.get(pair) != "review-evidence"
            ):
                self._add(
                    path,
                    "SOURCE_EVIDENCE_CLOSURE",
                    "ownership or consent evidence is not a reviewed supporting artifact",
                )
        if source_types and not source_types <= allowed_types:
            self._add(
                path,
                "RIGHTS_SOURCE_SET",
                "record source set exceeds its registered rights statement",
            )
        synthetic_types = {
            "deterministic-synthetic",
            "model-generated-synthetic",
        }
        expected_basis = (
            "synthetic"
            if source_types and source_types <= synthetic_types
            else "rappterverse-owned"
        )
        if provenance.get("rightsBasis") != expected_basis:
            self._add(
                path,
                "SOURCE_RIGHTS_BASIS",
                "record rights basis does not match its source types",
            )

    def _check_sorted_unique_descriptors(
        self, path: str, values: Sequence[Mapping[str, Any]]
    ) -> None:
        keys = [_descriptor_sort_key(item) for item in values]
        if keys != sorted(keys):
            self._add(
                path,
                "ARTIFACT_ORDER",
                "artifact descriptors must be sorted by path and digest",
            )
        if len(keys) != len(set(keys)) or len({item[0] for item in keys}) != len(keys):
            self._add(
                path,
                "ARTIFACT_DUPLICATE",
                "artifact descriptor paths must be unique",
            )

    def _load_reviewed_json(
        self,
        descriptor: Mapping[str, Any],
        artifact_kind: str,
        schema_version: str,
        *,
        governed: bool,
    ) -> Optional[Dict[str, Any]]:
        data = self._verify_descriptor(
            descriptor,
            expected_kind=artifact_kind,
            expected_media_type="application/json",
            governed=governed,
        )
        path = descriptor.get("path")
        if data is None or not isinstance(path, str):
            return None
        return self._load_json(path, schema_version)

    def _validate_dataset_manifest(
        self,
        descriptor: Mapping[str, Any],
        release_entry: Mapping[str, Any],
        release_id: str,
    ) -> Optional[Dict[str, Any]]:
        manifest = self._load_reviewed_json(
            descriptor,
            "dataset-manifest",
            "rappterverse.dataset-manifest/v2",
            governed=True,
        )
        path = str(descriptor.get("path", "."))
        if manifest is None:
            return None
        expected_path = "releases/{}/datasets/{}.json".format(
            release_id, release_entry.get("datasetId")
        )
        if path != expected_path:
            self._add(
                path,
                "DATASET_MANIFEST_PATH",
                "dataset manifest path does not match release and dataset",
            )
        self._check_policy_ref(path, manifest.get("policy"))
        for field in ("datasetId", "datasetVersion", "counts", "contentBytes"):
            if manifest.get(field) != release_entry.get(field):
                self._add(
                    path,
                    "DATASET_RELEASE_MISMATCH",
                    "release dataset entry does not equal its manifest",
                )

        data_card_descriptor = manifest.get("dataCard")
        shards = manifest.get("shards")
        supporting = manifest.get("supportingArtifacts")
        if (
            not isinstance(data_card_descriptor, dict)
            or not isinstance(shards, list)
            or not isinstance(supporting, list)
        ):
            return manifest
        all_descriptors: List[Mapping[str, Any]] = [
            data_card_descriptor,
            *[item for item in shards if isinstance(item, dict)],
            *[item for item in supporting if isinstance(item, dict)],
        ]
        self._check_sorted_unique_descriptors(
            path, [item for item in shards if isinstance(item, dict)]
        )
        self._check_sorted_unique_descriptors(
            path, [item for item in supporting if isinstance(item, dict)]
        )
        all_paths = [str(item.get("path")) for item in all_descriptors]
        if len(all_paths) != len(set(all_paths)):
            self._add(
                path,
                "ARTIFACT_DUPLICATE",
                "artifact descriptor paths must be unique across the manifest",
            )

        card = self._load_reviewed_json(
            data_card_descriptor,
            "data-card",
            "rappterverse.data-card/v2",
            governed=True,
        )
        supporting_raw: List[Dict[str, Any]] = []
        for item in supporting:
            if not isinstance(item, dict):
                continue
            self._verify_descriptor(item, governed=True)
            supporting_raw.append(_raw_descriptor(item))
        supporting_pairs = {
            (item.get("path"), item.get("sha256")) for item in supporting_raw
        }
        supporting_kind_by_pair = {
            (item.get("path"), item.get("sha256")): item.get("artifactKind")
            for item in supporting_raw
        }

        actual_counts = {
            "records": 0,
            "transcripts": 0,
            "deliberations": 0,
            "providerReasoning": 0,
        }
        actual_splits = {
            "train": 0,
            "validation": 0,
            "test": 0,
            "unassigned": 0,
        }
        records: Dict[str, Dict[str, Any]] = {}
        transcripts: Dict[str, Dict[str, Any]] = {}
        deliberations: Dict[str, Dict[str, Any]] = {}
        provider: Dict[str, Dict[str, Any]] = {}

        for shard in shards:
            if not isinstance(shard, dict):
                continue
            kind = shard.get("artifactKind")
            shard_path = str(shard.get("path", "."))
            data = self._verify_descriptor(
                shard,
                expected_media_type="application/x-ndjson",
                governed=True,
            )
            if data is None or not isinstance(kind, str):
                continue
            values = self.validate_jsonl_bytes(shard_path, data, kind)
            count_field = _COUNT_FIELD_BY_SHARD_KIND.get(kind)
            id_field = _ID_FIELD_BY_SHARD_KIND.get(kind)
            if count_field is None or id_field is None:
                continue
            ids = [item.get(id_field) for item in values]
            if ids != sorted(ids) or len(ids) != len(set(ids)):
                self._add(
                    shard_path,
                    "SHARD_ORDER",
                    "shard item identifiers must be sorted and unique",
                )
            if shard.get("itemCount") != len(values):
                self._add(
                    shard_path,
                    "SHARD_COUNT",
                    "shard item count does not match its lines",
                )
            if ids and (
                shard.get("firstItemId") != ids[0]
                or shard.get("lastItemId") != ids[-1]
            ):
                self._add(
                    shard_path,
                    "SHARD_RANGE",
                    "shard first or last item identifier does not match",
                )
            bodies = data[:-1].split(b"\n") if data.endswith(b"\n") else []
            max_line = max((len(item) + 1 for item in bodies), default=0)
            if shard.get("maxLineBytes") != max_line:
                self._add(
                    shard_path,
                    "SHARD_LINE_BYTES",
                    "shard maximum line byte count does not match",
                )
            actual_counts[count_field] += len(values)
            target = {
                "record-shard": records,
                "transcript-shard": transcripts,
                "deliberation-shard": deliberations,
                "provider-reasoning-shard": provider,
            }[kind]
            for item in values:
                item_id = item.get(id_field)
                if isinstance(item_id, str):
                    if item_id in target:
                        self._add(
                            shard_path,
                            "ITEM_DUPLICATE",
                            "item identifier appears more than once",
                        )
                    target[item_id] = item
                if kind == "record-shard":
                    split = item.get("split")
                    if split in actual_splits:
                        actual_splits[split] += 1
                if kind == "provider-reasoning-shard":
                    source = item.get("source")
                    terms = (
                        source.get("redistributionTermsRef")
                        if isinstance(source, dict)
                        else None
                    )
                    if not isinstance(terms, dict):
                        continue
                    raw_terms = _raw_descriptor(terms)
                    if raw_terms not in supporting_raw:
                        self._add(
                            shard_path,
                            "PROVIDER_TERMS_CLOSURE",
                            "provider terms are not a supporting artifact",
                        )
                    self._verify_descriptor(
                        terms,
                        expected_kind="provider-terms",
                        reviewed=False,
                        register=False,
                    )
                    receipt_ref = shard.get("reviewReceiptRef")
                    if isinstance(receipt_ref, str):
                        self._provider_terms_by_receipt.setdefault(
                            receipt_ref, []
                        ).append(raw_terms)

        if manifest.get("counts") != actual_counts:
            self._add(path, "MANIFEST_COUNTS", "dataset counts do not close")
        if manifest.get("splits") != actual_splits:
            self._add(path, "MANIFEST_SPLITS", "dataset split counts do not close")
        if manifest.get("artifactCount") != len(all_descriptors):
            self._add(path, "MANIFEST_ARTIFACT_COUNT", "artifact count does not close")
        actual_bytes = sum(
            item.get("bytes", 0)
            for item in all_descriptors
            if isinstance(item.get("bytes"), int)
            and not isinstance(item.get("bytes"), bool)
        )
        if manifest.get("contentBytes") != actual_bytes:
            self._add(path, "MANIFEST_BYTES", "dataset content bytes do not close")

        dataset_id = manifest.get("datasetId")
        required_visible_kinds = {
            "system-prompt",
            "user-prompt",
            "assistant-output",
            "final-outcome",
        }
        for transcript in transcripts.values():
            events = transcript.get("events")
            if not isinstance(events, list):
                continue
            sequences = [
                event.get("sequence")
                for event in events
                if isinstance(event, dict)
            ]
            event_ids = [
                event.get("eventId")
                for event in events
                if isinstance(event, dict)
            ]
            kinds = {
                event.get("kind")
                for event in events
                if isinstance(event, dict)
            }
            if sequences != list(range(len(events))) or len(event_ids) != len(
                set(event_ids)
            ):
                self._add(
                    path,
                    "TRANSCRIPT_SEQUENCE",
                    "transcript events must be contiguous and uniquely identified",
                )
            if not required_visible_kinds <= kinds:
                self._add(
                    path,
                    "TRANSCRIPT_COMPLETENESS",
                    "transcript lacks a required visible event class",
                )
            started = transcript.get("startedAt")
            completed = transcript.get("completedAt")
            timestamps = [
                event.get("timestamp")
                for event in events
                if isinstance(event, dict)
            ]
            if (
                not isinstance(started, str)
                or not isinstance(completed, str)
                or started > completed
                or any(
                    not isinstance(timestamp, str)
                    or timestamp < started
                    or timestamp > completed
                    for timestamp in timestamps
                )
            ):
                self._add(
                    path,
                    "TRANSCRIPT_TIME",
                    "transcript event times fall outside its interval",
                )
        for transcript_id, transcript in transcripts.items():
            record = records.get(str(transcript.get("recordId")))
            generation = (
                record.get("generation")
                if isinstance(record, dict)
                else None
            )
            if (
                not isinstance(record, dict)
                or not isinstance(generation, dict)
                or transcript.get("datasetId") != dataset_id
                or record.get("datasetId") != dataset_id
                or generation.get("transcriptId") != transcript_id
                or transcript.get("runId") != generation.get("runId")
                or transcript.get("episodeId") != record.get("episodeId")
            ):
                self._add(
                    path,
                    "TRANSCRIPT_CLOSURE",
                    "transcript does not uniquely close to its generation record",
                )
        for record_id, record in records.items():
            if record_id in self._record_ids:
                self._add(
                    path,
                    "RECORD_ID_GLOBAL_DUPLICATE",
                    "record identifier is reused across release datasets",
                )
            else:
                self._record_ids.add(record_id)
            if record.get("datasetId") != dataset_id:
                self._add(path, "DATASET_ID_MISMATCH", "record dataset does not match")
            generation = record.get("generation")
            self._validate_record_rights(
                path,
                record,
                supporting_pairs,
                supporting_kind_by_pair,
            )
            if not isinstance(generation, dict):
                continue
            transcript = transcripts.get(str(generation.get("transcriptId")))
            deliberation = deliberations.get(str(generation.get("deliberationId")))
            if (
                transcript is None
                or transcript.get("recordId") != record_id
                or transcript.get("datasetId") != dataset_id
                or transcript.get("runId") != generation.get("runId")
                or transcript.get("episodeId") != record.get("episodeId")
            ):
                self._add(
                    path,
                    "TRANSCRIPT_CLOSURE",
                    "record transcript reference does not close",
                )
            if (
                deliberation is None
                or deliberation.get("recordId") != record_id
                or deliberation.get("datasetId") != dataset_id
                or deliberation.get("transcriptId")
                != generation.get("transcriptId")
            ):
                self._add(
                    path,
                    "DELIBERATION_CLOSURE",
                    "record deliberation reference does not close",
                )
            provider_id = generation.get("providerReasoningId")
            if provider_id is not None:
                reasoning = provider.get(str(provider_id))
                if (
                    reasoning is None
                    or reasoning.get("recordId") != record_id
                    or reasoning.get("datasetId") != dataset_id
                    or reasoning.get("transcriptId")
                    != generation.get("transcriptId")
                ):
                    self._add(
                        path,
                        "PROVIDER_REASONING_CLOSURE",
                        "record provider reasoning reference does not close",
                    )
        if set(item.get("recordId") for item in transcripts.values()) != set(records):
            self._add(path, "TRANSCRIPT_CLOSURE", "transcript set does not close")
        if set(item.get("recordId") for item in deliberations.values()) != set(records):
            self._add(path, "DELIBERATION_CLOSURE", "deliberation set does not close")

        if card is not None:
            self._check_policy_ref(str(data_card_descriptor.get("path")), card.get("policy"))
            if (
                card.get("datasetId") != manifest.get("datasetId")
                or card.get("datasetVersion") != manifest.get("datasetVersion")
                or card.get("composition", {}).get("records")
                != actual_counts["records"]
                or card.get("composition", {}).get("transcripts")
                != actual_counts["transcripts"]
                or card.get("composition", {}).get("deliberations")
                != actual_counts["deliberations"]
                or card.get("composition", {}).get("providerReasoning")
                != actual_counts["providerReasoning"]
                or card.get("composition", {}).get("splits") != actual_splits
            ):
                self._add(
                    str(data_card_descriptor.get("path")),
                    "DATA_CARD_CLOSURE",
                    "data card composition does not equal the dataset manifest",
                )
        return manifest

    def _validate_world_pack(
        self, descriptor: Mapping[str, Any], release_id: str
    ) -> None:
        value = self._load_reviewed_json(
            descriptor,
            "world-pack-source",
            "rappterverse.world-pack-source/v2",
            governed=True,
        )
        path = str(descriptor.get("path", "."))
        if value is None:
            return
        if value.get("releaseId") != release_id:
            self._add(path, "WORLD_RELEASE", "world-pack releaseId does not match")
        recipe = value.get("projectionRecipe")
        if isinstance(recipe, dict):
            self._load_reviewed_json(
                recipe,
                "projection-recipe",
                "rappterverse.projection-recipe/v2",
                governed=True,
            )
        entities = value.get("entities")
        if not isinstance(entities, list):
            return
        channels = value.get("seedChannels")
        if isinstance(channels, list):
            channel_names = [
                item.get("channel")
                for item in channels
                if isinstance(item, dict)
            ]
            if channel_names != sorted(channel_names) or len(
                channel_names
            ) != len(set(channel_names)):
                self._add(
                    path,
                    "WORLD_SEED_CHANNELS",
                    "world-pack seed channels must be sorted and unique",
                )
        ids = [
            item.get("entityId")
            for item in entities
            if isinstance(item, dict)
        ]
        if ids != sorted(ids) or len(ids) != len(set(ids)):
            self._add(
                path,
                "WORLD_ENTITY_ORDER",
                "world-pack entities must be sorted and unique",
            )
        for item in entities:
            if not isinstance(item, dict):
                continue
            source_ids = item.get("sourceRecordIds")
            if isinstance(source_ids, list) and not set(source_ids) <= self._record_ids:
                self._add(
                    path,
                    "WORLD_RECORD_CLOSURE",
                    "world-pack source record does not resolve in the release",
                )
            for reference in item.get("references", []):
                if (
                    isinstance(reference, dict)
                    and reference.get("required") is True
                    and reference.get("targetEntityId") not in set(ids)
                ):
                    self._add(
                        path,
                        "WORLD_REFERENCE_CLOSURE",
                        "required world-pack entity reference does not resolve",
                    )

    def _load_receipt(
        self, path: str, expected_sha256: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        if path in self._receipts:
            receipt = self._receipts[path]
            if expected_sha256 is not None:
                data = self._read(path)
                if data is not None and hashlib.sha256(data).hexdigest() != expected_sha256:
                    self._add(
                        path,
                        "RECEIPT_REF_HASH",
                        "receipt reference digest does not match",
                    )
            return receipt
        receipt = self._load_json(
            path, "rappterverse.public-review-receipt/v2"
        )
        data = self._read(path)
        if receipt is None or data is None:
            return None
        digest = hashlib.sha256(data).hexdigest()
        self._check_receipt_address(path, digest)
        if expected_sha256 is not None and digest != expected_sha256:
            self._add(
                path,
                "RECEIPT_REF_HASH",
                "receipt reference digest does not match",
            )
        self._check_policy_ref(path, receipt.get("policy"))
        artifacts = receipt.get("approvedArtifacts")
        if not isinstance(artifacts, list):
            return receipt
        artifact_values = [item for item in artifacts if isinstance(item, dict)]
        self._check_sorted_unique_descriptors(path, artifact_values)
        allowed = _RECEIPT_SCOPE_KINDS.get(receipt.get("scope"), set())
        if any(item.get("artifactKind") not in allowed for item in artifact_values):
            self._add(
                path,
                "RECEIPT_SCOPE",
                "receipt scope does not permit an approved artifact kind",
            )
        for artifact in artifact_values:
            self._verify_descriptor(
                artifact, reviewed=False, register=False
            )
        artifact_pairs = {
            (item.get("path"), item.get("sha256")) for item in artifact_values
        }
        checks = receipt.get("checks")
        if isinstance(checks, dict):
            for check in checks.values():
                evidence = check.get("evidence") if isinstance(check, dict) else None
                if not isinstance(evidence, list):
                    continue
                pairs = [
                    (item.get("artifactPath"), item.get("artifactSha256"))
                    for item in evidence
                    if isinstance(item, dict)
                ]
                if pairs != sorted(pairs) or len(pairs) != len(set(pairs)):
                    self._add(
                        path,
                        "RECEIPT_EVIDENCE_ORDER",
                        "receipt evidence references must be sorted and unique",
                    )
                if any(pair not in artifact_pairs for pair in pairs):
                    self._add(
                        path,
                        "RECEIPT_EVIDENCE",
                        "receipt evidence does not bind an approved artifact",
                    )
        approval_reference = receipt.get("approvalReference")
        if approval_reference is not None:
            if self.policy["approvalMechanisms"]["signedApprovals"] == "not-enabled":
                self._add(
                    path,
                    "SIGNED_APPROVAL_NOT_ENABLED",
                    "signed approval references are not an active operational gate",
                )
            if isinstance(approval_reference, dict):
                approval_path = approval_reference.get("path")
                approval_data = self._read(str(approval_path))
                if (
                    approval_data is not None
                    and hashlib.sha256(approval_data).hexdigest()
                    != approval_reference.get("sha256")
                ):
                    self._add(
                        path,
                        "SIGNED_APPROVAL_HASH",
                        "future approval reference digest does not match",
                    )
        self._receipts[path] = receipt
        return receipt

    def _validate_receipt_closure(self) -> None:
        for receipt_ref in sorted(self._descriptors_by_receipt):
            receipt = self._load_receipt(receipt_ref)
            if receipt is None:
                continue
            if (
                receipt_ref not in self._governed_receipt_refs
                and receipt.get("predecessor") is not None
            ):
                self._add(
                    receipt_ref,
                    "RECEIPT_PREDECESSOR_UNTRACKED",
                    "receipt outside the active review set cannot supersede another receipt",
                )
            if receipt.get("disposition") != "approve_public":
                self._add(
                    receipt_ref,
                    "RECEIPT_REJECT",
                    "a rejection cannot authorize an artifact",
                )
            declared = receipt.get("approvedArtifacts")
            if not isinstance(declared, list):
                continue
            actual = sorted(
                self._descriptors_by_receipt[receipt_ref],
                key=_descriptor_sort_key,
            )
            if declared != actual:
                self._add(
                    receipt_ref,
                    "RECEIPT_ARTIFACT_CLOSURE",
                    "receipt artifacts do not equal referencing descriptors",
                )
            provider_terms = self._provider_terms_by_receipt.get(receipt_ref, [])
            approval = receipt.get("providerRedistributionApproval")
            has_provider = any(
                item.get("artifactKind") == "provider-reasoning-shard"
                for item in actual
            )
            if has_provider:
                terms = (
                    approval.get("termsReference")
                    if isinstance(approval, dict)
                    else None
                )
                if (
                    receipt.get("disposition") != "approve_public"
                    or not isinstance(approval, dict)
                    or approval.get("approved") is not True
                    or not isinstance(terms, dict)
                    or _raw_descriptor(terms) not in provider_terms
                    or _raw_descriptor(terms) not in actual
                    or any(
                        item != _raw_descriptor(terms)
                        for item in provider_terms
                    )
                ):
                    self._add(
                        receipt_ref,
                        "PROVIDER_APPROVAL",
                        "provider reasoning requires approve_public and exact redistribution terms",
                    )
            elif approval is not None:
                self._add(
                    receipt_ref,
                    "PROVIDER_APPROVAL_UNNEEDED",
                    "provider approval is present without provider reasoning",
                )

    def _validate_review_set(
        self, descriptor: Mapping[str, Any], release_id: str
    ) -> None:
        value = self._load_reviewed_json(
            descriptor,
            "active-review-set",
            "rappterverse.active-review-set/v2",
            governed=False,
        )
        path = str(descriptor.get("path", "."))
        if value is None:
            return
        if value.get("releaseId") != release_id:
            self._add(path, "REVIEW_SET_RELEASE", "review set releaseId does not match")
        self._check_policy_ref(path, value.get("policy"))
        refs = value.get("receipts")
        heads = value.get("heads")
        if not isinstance(refs, list) or not isinstance(heads, list):
            return
        ref_values = [item for item in refs if isinstance(item, dict)]
        head_values = [item for item in heads if isinstance(item, dict)]
        for collection, code in (
            (ref_values, "REVIEW_SET_ORDER"),
            (head_values, "REVIEW_HEAD_ORDER"),
        ):
            keys = [_descriptor_sort_key(item) for item in collection]
            if keys != sorted(keys) or len(keys) != len(set(keys)):
                self._add(
                    path,
                    code,
                    "review references must be sorted and unique",
                )
        by_path = {
            str(item.get("path")): item
            for item in ref_values
            if isinstance(item.get("path"), str)
        }
        if len(by_path) != len(ref_values):
            self._add(path, "REVIEW_SET_DUPLICATE", "receipt paths must be unique")
        receipts: Dict[str, Dict[str, Any]] = {}
        for receipt_path, reference in sorted(by_path.items()):
            receipt = self._load_receipt(
                receipt_path, str(reference.get("sha256"))
            )
            if receipt is not None:
                receipts[receipt_path] = receipt
        review_ids = [receipt.get("reviewId") for receipt in receipts.values()]
        if len(review_ids) != len(set(review_ids)):
            self._add(path, "REVIEW_ID_DUPLICATE", "review IDs must be unique")

        successors: Dict[str, List[str]] = {item: [] for item in receipts}
        predecessor_by_path: Dict[str, Optional[str]] = {}
        for receipt_path, receipt in sorted(receipts.items()):
            predecessor = receipt.get("predecessor")
            predecessor_path = (
                predecessor.get("path") if isinstance(predecessor, dict) else None
            )
            predecessor_by_path[receipt_path] = predecessor_path
            if predecessor_path is None:
                continue
            predecessor_receipt = receipts.get(predecessor_path)
            reference = by_path.get(predecessor_path)
            if predecessor_receipt is None or reference != predecessor:
                self._add(
                    receipt_path,
                    "REVIEW_PREDECESSOR",
                    "receipt predecessor is absent or not content-bound",
                )
                continue
            successors[predecessor_path].append(receipt_path)
            if (
                predecessor_receipt.get("scope") != receipt.get("scope")
                or predecessor_receipt.get("datasetId")
                != receipt.get("datasetId")
            ):
                self._add(
                    receipt_path,
                    "REVIEW_PREDECESSOR_SCOPE",
                    "supersession must stay within one review scope",
                )
            if (
                predecessor_receipt.get("reviewedAt", "")
                >= receipt.get("reviewedAt", "")
            ):
                self._add(
                    receipt_path,
                    "REVIEW_TIME_ORDER",
                    "superseding receipt must be newer than its predecessor",
                )
        for receipt_path, children in sorted(successors.items()):
            if len(children) > 1:
                self._add(
                    receipt_path,
                    "REVIEW_FORK",
                    "one receipt has multiple superseding successors",
                )

        visiting: Set[str] = set()
        visited: Set[str] = set()

        def visit(node: str) -> None:
            if node in visiting:
                self._add(path, "REVIEW_CYCLE", "receipt supersession contains a cycle")
                return
            if node in visited:
                return
            visiting.add(node)
            predecessor = predecessor_by_path.get(node)
            if predecessor in receipts:
                visit(str(predecessor))
            visiting.remove(node)
            visited.add(node)

        for receipt_path in sorted(receipts):
            visit(receipt_path)

        calculated_heads = {
            receipt_path
            for receipt_path, children in successors.items()
            if not children
        }
        declared_heads = {
            str(item.get("path"))
            for item in head_values
            if isinstance(item.get("path"), str)
        }
        if calculated_heads != declared_heads:
            self._add(
                path,
                "REVIEW_HEADS",
                "declared review heads do not equal supersession heads",
            )
        for head in sorted(declared_heads):
            reference = by_path.get(head)
            if reference not in head_values:
                self._add(path, "REVIEW_HEAD_HASH", "review head digest does not match")
            receipt = receipts.get(head)
            if receipt is not None and receipt.get("disposition") != "approve_public":
                self._add(
                    head,
                    "REVIEW_HEAD_REJECT",
                    "active review head must approve public release",
                )
        if declared_heads != self._governed_receipt_refs:
            self._add(
                path,
                "REVIEW_SET_STALE",
                "active heads must equal all governed artifact receipt references",
            )
        for item in review_supersession_diagnostics(
            receipts, declared_heads, self._governed_receipt_refs
        ):
            self._add(
                path if item.path == "." else item.path,
                item.code,
                item.message,
            )

    def validate_artifact_batch(
        self, changed_paths: Iterable[str]
    ) -> Tuple[TrustDiagnostic, ...]:
        """Validate one receipt-covered immutable artifact publication batch."""

        paths = sorted(set(changed_paths))
        receipt_paths = {
            path
            for path in paths
            if path.startswith("objects/review-receipts/sha256/")
            and path.endswith(".json")
        }
        if not receipt_paths:
            self._add(
                ".",
                "BATCH_RECEIPT_REQUIRED",
                "artifact batch requires a content-addressed review receipt",
            )
            return self.diagnostics

        receipts: Dict[str, Dict[str, Any]] = {}
        claims_by_path: Dict[
            str, List[Tuple[str, Dict[str, Any]]]
        ] = {}
        for receipt_path in sorted(receipt_paths):
            receipt = self._load_receipt(receipt_path)
            if receipt is None:
                continue
            receipts[receipt_path] = receipt
            if receipt.get("disposition") != "approve_public":
                self._add(
                    receipt_path,
                    "RECEIPT_REJECT",
                    "artifact batch receipt must approve public release",
                )
            predecessor = receipt.get("predecessor")
            if isinstance(predecessor, dict):
                predecessor_path = predecessor.get("path")
                predecessor_hash = predecessor.get("sha256")
                if isinstance(predecessor_path, str):
                    self._load_receipt(
                        predecessor_path,
                        str(predecessor_hash),
                    )
            approved = receipt.get("approvedArtifacts")
            if not isinstance(approved, list):
                continue
            for descriptor in approved:
                if not isinstance(descriptor, dict):
                    continue
                descriptor_path = descriptor.get("path")
                if isinstance(descriptor_path, str):
                    claims_by_path.setdefault(descriptor_path, []).append(
                        (receipt_path, descriptor)
                    )

        non_receipt_paths = set(paths) - receipt_paths
        claimed_paths = set(claims_by_path)
        for path in sorted(non_receipt_paths - claimed_paths):
            self._add(
                path,
                "BATCH_ARTIFACT_UNCLAIMED",
                "changed artifact is not approved by a batch receipt",
            )
        for path in sorted(claimed_paths - non_receipt_paths):
            self._add(
                path,
                "BATCH_RECEIPT_UNUSED_CLAIM",
                "batch receipt approves an artifact not changed in this batch",
            )
        for path, claims in sorted(claims_by_path.items()):
            if len(claims) != 1:
                self._add(
                    path,
                    "BATCH_RECEIPT_DUPLICATE_CLAIM",
                    "changed artifact is approved more than once",
                )

        parsed_by_kind: Dict[str, List[Dict[str, Any]]] = {}
        parsed_by_path: Dict[str, List[Dict[str, Any]]] = {}
        descriptor_by_path: Dict[str, Dict[str, Any]] = {}
        receipt_by_artifact: Dict[str, str] = {}
        for path in sorted(non_receipt_paths):
            claims = claims_by_path.get(path, [])
            if len(claims) != 1:
                continue
            receipt_path, descriptor = claims[0]
            descriptor_by_path[path] = descriptor
            receipt_by_artifact[path] = receipt_path
            data = self._verify_descriptor(
                descriptor,
                reviewed=False,
                register=False,
            )
            if data is None:
                continue
            kind = descriptor.get("artifactKind")
            media_type = descriptor.get("mediaType")
            values: List[Dict[str, Any]] = []
            if (
                isinstance(kind, str)
                and media_type == "application/x-ndjson"
            ):
                values = self.validate_jsonl_bytes(path, data, kind)
            elif media_type == "application/json":
                expected = ARTIFACT_KIND_TO_SCHEMA_VERSION.get(str(kind))
                if expected is not None:
                    value = self._load_json(path, expected)
                    if value is not None:
                        values = [value]
                else:
                    try:
                        parsed = parse_json_v2(data)
                    except CanonicalJSONV2Error:
                        self._add(
                            path,
                            "BATCH_JSON_INVALID",
                            "batch JSON artifact is not strict JSON",
                        )
                    else:
                        if canonical_json_v2(parsed, stored=True) != data:
                            self._add(
                                path,
                                "BATCH_JSON_CANONICAL",
                                "batch JSON artifact is not canonical stored JSON",
                            )
                        if (
                            isinstance(parsed, dict)
                            and isinstance(
                                parsed.get("schemaVersion"), str
                            )
                            and _FORMAL_V2.fullmatch(
                                parsed["schemaVersion"]
                            )
                        ):
                            self._add(
                                path,
                                "V2_SCHEMA_KIND",
                                "formal v2 JSON is not allowed for this artifact kind",
                            )
            if isinstance(kind, str) and values:
                parsed_by_kind.setdefault(kind, []).extend(values)
                parsed_by_path[path] = values

            for value in values:
                for nested in _walk_mappings(value):
                    if not set(_RAW_ARTIFACT_FIELDS) <= set(nested):
                        continue
                    reviewed = isinstance(
                        nested.get("reviewReceiptRef"), str
                    )
                    self._verify_descriptor(
                        nested,
                        reviewed=reviewed,
                        register=False,
                    )
                    if not reviewed:
                        continue
                    dependency_receipt_path = nested.get(
                        "reviewReceiptRef"
                    )
                    dependency_receipt = self._load_receipt(
                        str(dependency_receipt_path)
                    )
                    approved = (
                        dependency_receipt.get("approvedArtifacts")
                        if isinstance(dependency_receipt, dict)
                        else None
                    )
                    if (
                        not isinstance(approved, list)
                        or _raw_descriptor(nested) not in approved
                        or dependency_receipt.get("disposition")
                        != "approve_public"
                    ):
                        self._add(
                            str(nested.get("path", path)),
                            "BATCH_DEPENDENCY_REVIEW",
                            "unchanged dependency lacks an exact approving receipt",
                        )

        supporting_pairs = {
            (item.get("path"), item.get("sha256"))
            for item in descriptor_by_path.values()
        }
        supporting_kind_by_pair = {
            (item.get("path"), item.get("sha256")): item.get(
                "artifactKind"
            )
            for item in descriptor_by_path.values()
        }
        records = {
            str(item.get("recordId")): item
            for item in parsed_by_kind.get("record-shard", [])
            if isinstance(item.get("recordId"), str)
        }
        transcripts = {
            str(item.get("transcriptId")): item
            for item in parsed_by_kind.get("transcript-shard", [])
            if isinstance(item.get("transcriptId"), str)
        }
        deliberations = {
            str(item.get("deliberationId")): item
            for item in parsed_by_kind.get("deliberation-shard", [])
            if isinstance(item.get("deliberationId"), str)
        }
        provider = {
            str(item.get("reasoningId")): item
            for item in parsed_by_kind.get(
                "provider-reasoning-shard", []
            )
            if isinstance(item.get("reasoningId"), str)
        }
        record_values = parsed_by_kind.get("record-shard", [])
        record_ids = [
            item.get("recordId")
            for item in record_values
            if isinstance(item.get("recordId"), str)
        ]
        if len(record_ids) != len(set(record_ids)):
            self._add(
                ".",
                "RECORD_ID_GLOBAL_DUPLICATE",
                "record identifier is reused within the artifact batch",
            )
        for record in record_values:
            self._validate_record_rights(
                ".",
                record,
                supporting_pairs,
                supporting_kind_by_pair,
            )
            generation = record.get("generation")
            if not isinstance(generation, dict):
                continue
            transcript = transcripts.get(
                str(generation.get("transcriptId"))
            )
            if (
                transcript is None
                or transcript.get("datasetId") != record.get("datasetId")
                or transcript.get("recordId") != record.get("recordId")
                or transcript.get("runId") != generation.get("runId")
                or transcript.get("episodeId") != record.get("episodeId")
            ):
                self._add(
                    ".",
                    "TRANSCRIPT_CLOSURE",
                    "batch record transcript identity does not close",
                )
            deliberation = deliberations.get(
                str(generation.get("deliberationId"))
            )
            if (
                deliberation is None
                or deliberation.get("datasetId")
                != record.get("datasetId")
                or deliberation.get("recordId")
                != record.get("recordId")
                or deliberation.get("transcriptId")
                != generation.get("transcriptId")
            ):
                self._add(
                    ".",
                    "DELIBERATION_CLOSURE",
                    "batch record deliberation identity does not close",
                )
            provider_id = generation.get("providerReasoningId")
            if provider_id is not None and str(provider_id) in provider:
                reasoning = provider[str(provider_id)]
                if (
                    reasoning.get("datasetId") != record.get("datasetId")
                    or reasoning.get("recordId") != record.get("recordId")
                    or reasoning.get("transcriptId")
                    != generation.get("transcriptId")
                ):
                    self._add(
                        ".",
                        "PROVIDER_REASONING_CLOSURE",
                        "batch provider reasoning identity does not close",
                    )

        for reasoning_path, descriptor in sorted(
            descriptor_by_path.items()
        ):
            if descriptor.get("artifactKind") != "provider-reasoning-shard":
                continue
            receipt_path = receipt_by_artifact.get(reasoning_path)
            receipt = receipts.get(str(receipt_path))
            approved = (
                receipt.get("approvedArtifacts")
                if isinstance(receipt, dict)
                else None
            )
            approval = (
                receipt.get("providerRedistributionApproval")
                if isinstance(receipt, dict)
                else None
            )
            terms = (
                approval.get("termsReference")
                if isinstance(approval, dict)
                else None
            )
            reasoning_terms = []
            for reasoning in parsed_by_path.get(reasoning_path, []):
                source = reasoning.get("source")
                reference = (
                    source.get("redistributionTermsRef")
                    if isinstance(source, dict)
                    else None
                )
                if isinstance(reference, dict):
                    reasoning_terms.append(_raw_descriptor(reference))
            if (
                not isinstance(approved, list)
                or not isinstance(terms, dict)
                or approval.get("approved") is not True
                or _raw_descriptor(terms) not in approved
                or terms.get("artifactKind") != "provider-terms"
                or not reasoning_terms
                or any(
                    item != _raw_descriptor(terms)
                    for item in reasoning_terms
                )
            ):
                self._add(
                    reasoning_path,
                    "PROVIDER_APPROVAL",
                    "provider reasoning batch requires exact approved redistribution terms",
                )
        return self.diagnostics

    def _validate_release_chain(
        self,
        release_path: str,
        release: Mapping[str, Any],
        pointer_path: str,
        pointer: Mapping[str, Any],
    ) -> None:
        sequence = release.get("sequence")
        previous_id = release.get("previousReleaseId")
        previous_descriptor = release.get("previousReleasePointer")
        expected_digest = (
            previous_descriptor.get("sha256")
            if isinstance(previous_descriptor, dict)
            else None
        )

        if (
            pointer.get("sequence") != sequence
            or pointer.get("previousReleaseId") != previous_id
        ):
            self._add(
                pointer_path,
                "RELEASE_CHAIN_MISMATCH",
                "catalog pointer does not repeat the release identity chain",
            )
        if pointer.get("previousReleasePointerSha256") != expected_digest:
            self._add(
                pointer_path,
                "PREVIOUS_RELEASE_DIGEST",
                "catalog predecessor digest does not match the release descriptor",
            )

        if sequence == 1:
            if previous_id is not None or previous_descriptor is not None:
                self._add(
                    release_path,
                    "RELEASE_GENESIS",
                    "release sequence 1 must have a null predecessor",
                )
            if (
                self.trusted_predecessor_anchor is not None
                and not self._trusted_anchor_validation
            ):
                self._add(
                    release_path,
                    "RELEASE_ROLLBACK",
                    "genesis cannot replace an anchored trusted release history",
                )
            return
        if (
            isinstance(sequence, bool)
            or not isinstance(sequence, int)
            or sequence < 2
            or not isinstance(previous_id, str)
            or not isinstance(previous_descriptor, dict)
        ):
            self._add(
                release_path,
                "PREVIOUS_RELEASE_REQUIRED",
                "non-genesis release requires an explicit prior identity and pointer",
            )
            return

        anchor = self.trusted_predecessor_anchor
        if anchor is None and not self._trusted_anchor_validation:
            self._add(
                release_path,
                "PREDECESSOR_ANCHOR_REQUIRED",
                "non-genesis release requires an explicit trusted predecessor anchor",
            )
        elif anchor is not None:
            expected_descriptor = _raw_descriptor(anchor.pointer_descriptor)
            if dict(previous_descriptor) != expected_descriptor:
                self._add(
                    release_path,
                    "PREDECESSOR_ANCHOR_MISMATCH",
                    "release predecessor does not equal trusted base latest",
                )
            if previous_id != anchor.release_id:
                self._add(
                    release_path,
                    "PREDECESSOR_ANCHOR_ID",
                    "release predecessor identity does not equal trusted base latest",
                )
            if sequence != anchor.sequence + 1:
                code = (
                    "RELEASE_ROLLBACK"
                    if sequence <= anchor.sequence
                    else "RELEASE_FORK"
                )
                self._add(
                    release_path,
                    code,
                    "release sequence does not immediately extend trusted base latest",
                )
            for closure_path, expected_bytes in sorted(
                anchor.immutable_closure.items()
            ):
                candidate_bytes = self._read(closure_path)
                if (
                    candidate_bytes is not None
                    and candidate_bytes != expected_bytes
                ):
                    self._add(
                        closure_path,
                        "PREDECESSOR_CLOSURE_TAMPER",
                        "trusted predecessor immutable closure bytes changed",
                    )

        data = self._verify_descriptor(
            previous_descriptor,
            expected_kind="catalog-release-pointer",
            expected_media_type="application/json",
            reviewed=False,
            register=False,
        )
        previous_path = previous_descriptor.get("path")
        if data is None or not isinstance(previous_path, str):
            return
        if anchor is not None and data != anchor.pointer_bytes:
            self._add(
                previous_path,
                "PREDECESSOR_POINTER_BYTES",
                "previous pointer bytes do not equal trusted base latest pointer",
            )
        previous = self._load_json(
            previous_path, "rappterverse.catalog-release-pointer/v2"
        )
        if previous is None:
            return
        self._check_policy_ref(previous_path, previous.get("policy"))
        path_match = _RELEASE_POINTER_PATH.fullmatch(previous_path)
        previous_pointer_id = previous.get("releaseId")
        if (
            path_match is None
            or path_match.group(1) != previous_id
            or previous_pointer_id != previous_id
            or previous_id == release.get("releaseId")
        ):
            self._add(
                previous_path,
                "PREVIOUS_RELEASE_ID",
                "previous pointer path and release identity do not agree",
            )
        previous_sequence = previous.get("sequence")
        if (
            isinstance(previous_sequence, bool)
            or not isinstance(previous_sequence, int)
            or previous_sequence != sequence - 1
        ):
            self._add(
                previous_path,
                "PREVIOUS_RELEASE_SEQUENCE",
                "previous pointer sequence is not the immediate predecessor",
            )

    def validate_release_graph(
        self, latest_path: str = "catalog/latest.json"
    ) -> Tuple[TrustDiagnostic, ...]:
        """Validate a graph and convert recursion exhaustion to one diagnostic."""

        try:
            return self._validate_release_graph(latest_path)
        except RecursionError:
            self._add(
                ".",
                "JSON_DEPTH",
                "JSON nesting exceeds maximum depth {}".format(
                    MAX_JSON_NESTING_DEPTH
                ),
            )
            return self.diagnostics

    def _validate_release_graph(
        self, latest_path: str = "catalog/latest.json"
    ) -> Tuple[TrustDiagnostic, ...]:
        """Validate one complete latest -> pointer -> release graph."""

        if latest_path != "catalog/latest.json":
            self._add(
                latest_path,
                "CATALOG_LATEST_PATH",
                "public latest pointer must be catalog/latest.json",
            )
        latest = self._load_json(
            latest_path, "rappterverse.catalog-latest-pointer/v2"
        )
        if latest is None:
            return self.diagnostics
        pointer_descriptor = latest.get("releasePointer")
        if not isinstance(pointer_descriptor, dict):
            return self.diagnostics
        pointer = self._load_reviewed_json(
            pointer_descriptor,
            "catalog-release-pointer",
            "rappterverse.catalog-release-pointer/v2",
            governed=False,
        )
        pointer_path = str(pointer_descriptor.get("path", "."))
        pointer_match = _RELEASE_POINTER_PATH.fullmatch(pointer_path)
        if pointer is None:
            return self.diagnostics
        release_id = str(pointer.get("releaseId"))
        if pointer_match is None or pointer_match.group(1) != release_id:
            self._add(
                pointer_path,
                "CATALOG_POINTER_PATH",
                "immutable catalog pointer path does not match releaseId",
            )
        self._check_policy_ref(pointer_path, pointer.get("policy"))

        release_descriptor = pointer.get("releaseManifest")
        review_set_descriptor = pointer.get("activeReviewSet")
        if not isinstance(release_descriptor, dict) or not isinstance(
            review_set_descriptor, dict
        ):
            return self.diagnostics
        release = self._load_reviewed_json(
            release_descriptor,
            "release-manifest",
            "rappterverse.release-manifest/v2",
            governed=False,
        )
        if release is None:
            return self.diagnostics
        release_path = str(release_descriptor.get("path", "."))
        if release_path != "releases/{}/manifest.json".format(release_id):
            self._add(
                release_path,
                "RELEASE_MANIFEST_PATH",
                "release manifest path does not match releaseId",
            )
        self._check_policy_ref(release_path, release.get("policy"))
        self._validate_release_chain(
            release_path, release, pointer_path, pointer
        )
        if (
            release.get("releaseId") != pointer.get("releaseId")
            or release.get("createdAt") != pointer.get("createdAt")
            or release.get("sequence") != pointer.get("sequence")
            or release.get("previousReleaseId")
            != pointer.get("previousReleaseId")
            or release.get("totals") != pointer.get("totals")
            or release.get("policy") != pointer.get("policy")
        ):
            self._add(
                pointer_path,
                "CATALOG_RELEASE_MISMATCH",
                "catalog pointer fields do not equal the release manifest",
            )

        dataset_entries = release.get("datasets")
        world_descriptors = release.get("worldPackSources")
        if not isinstance(dataset_entries, list) or not isinstance(
            world_descriptors, list
        ):
            return self.diagnostics
        dataset_ids = [
            item.get("datasetId")
            for item in dataset_entries
            if isinstance(item, dict)
        ]
        expected_ids = self.registry.schemas_by_id[
            "https://data.rappterverse.dev/schemas/v2/common/identifiers.schema.json"
        ]["$defs"]["DatasetId"]["enum"]
        if dataset_ids != expected_ids:
            self._add(
                release_path,
                "RELEASE_DATASETS",
                "release must contain the ten datasets once in canonical order",
            )

        manifests: List[Dict[str, Any]] = []
        for entry in dataset_entries:
            if not isinstance(entry, dict) or not isinstance(
                entry.get("manifest"), dict
            ):
                continue
            manifest = self._validate_dataset_manifest(
                entry["manifest"], entry, release_id
            )
            if manifest is not None:
                manifests.append(manifest)
        self._check_sorted_unique_descriptors(
            release_path,
            [
                item["manifest"]
                for item in dataset_entries
                if isinstance(item, dict) and isinstance(item.get("manifest"), dict)
            ],
        )

        self._check_sorted_unique_descriptors(
            release_path,
            [item for item in world_descriptors if isinstance(item, dict)],
        )
        for descriptor in world_descriptors:
            if isinstance(descriptor, dict):
                self._validate_world_pack(descriptor, release_id)

        totals = {
            "datasets": len(dataset_entries),
            "records": sum(
                item.get("counts", {}).get("records", 0)
                for item in dataset_entries
                if isinstance(item, dict)
            ),
            "transcripts": sum(
                item.get("counts", {}).get("transcripts", 0)
                for item in dataset_entries
                if isinstance(item, dict)
            ),
            "deliberations": sum(
                item.get("counts", {}).get("deliberations", 0)
                for item in dataset_entries
                if isinstance(item, dict)
            ),
            "providerReasoning": sum(
                item.get("counts", {}).get("providerReasoning", 0)
                for item in dataset_entries
                if isinstance(item, dict)
            ),
            "worldPackSources": len(world_descriptors),
            "contentBytes": sum(
                item.get("contentBytes", 0)
                for item in dataset_entries
                if isinstance(item, dict)
            )
            + sum(
                item.get("bytes", 0)
                for item in world_descriptors
                if isinstance(item, dict)
            ),
        }
        if release.get("totals") != totals:
            self._add(release_path, "RELEASE_TOTALS", "release totals do not close")

        self._validate_review_set(review_set_descriptor, release_id)
        self._validate_receipt_closure()
        return self.diagnostics


def validate_release_graph(
    root: Path,
    schema_root: Path,
    trusted_policy_bytes: bytes,
    trusted_rights_bytes: bytes,
    latest_path: str = "catalog/latest.json",
    *,
    trusted_predecessor_anchor: Optional[
        TrustedPredecessorAnchor
    ] = None,
) -> Tuple[TrustDiagnostic, ...]:
    """Convenience API for a complete release graph validation."""

    registry = TrustedSchemaRegistry.load(schema_root)
    validator = ReleaseTrustValidator(
        root,
        registry,
        trusted_policy_bytes,
        trusted_rights_bytes,
        trusted_predecessor_anchor=trusted_predecessor_anchor,
    )
    return validator.validate_release_graph(latest_path)
