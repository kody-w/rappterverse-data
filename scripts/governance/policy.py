# SPDX-License-Identifier: Apache-2.0

"""Loading and hardening for repository governance policy."""

from __future__ import annotations

import hashlib
import json
import math
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Union

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from contracts.canonical import (  # noqa: E402
    CanonicalJSONV2Error,
    canonical_json_v2,
    parse_json_v2,
)


class PolicyConfigurationError(ValueError):
    """Raised when the trusted policy bundle is absent or unsafe."""


REQUIRED_DOCUMENTS = (
    "field-allowlist.json",
    "publication-policy.json",
    "quality-policy.json",
    "reasoning-policy.json",
    "rights-statements.json",
    "safety-policy.json",
    "source-allowlist.json",
    "withdrawal-policy.json",
)
TRUST_DOCUMENT = "publication-trust-v2.json"
RIGHTS_V2_DOCUMENT = "rights-statements-v2.json"

HARD_MAXIMUMS = {
    "fileHardBytes": 1_000_000,
    "jsonlLineHardBytes": 262_144,
    "manifestHardBytes": 512_000,
    "modelRequestHardBytes": 1_000_000,
    "modelVisibleOutputHardBytes": 512_000,
    "modelContextHardPercent": 70,
    "pullRequestDiffHardBytes": 900_000,
    "publicationFilesHard": 5,
}
RIGHTS_V2_ATTESTATIONS = {
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
RIGHTS_V2_BASIS_BY_SOURCE = {
    "deterministic-synthetic": "synthetic",
    "model-generated-synthetic": "synthetic",
    "rappterverse-repository": "rappterverse-owned",
    "system-controlled-agent": "rappterverse-owned",
    "consented-human-judgment": "rappterverse-owned",
}


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


def _expect(condition: bool, message: str) -> None:
    if not condition:
        raise PolicyConfigurationError(message)


@dataclass(frozen=True)
class PolicySet:
    """A validated collection of trusted policy documents."""

    root: Path
    documents: dict[str, dict[str, Any]]
    version: str
    trust_document: dict[str, Any]
    trust_document_bytes: bytes
    rights_v2_document: dict[str, Any]
    rights_v2_document_bytes: bytes

    @classmethod
    def load(cls, root: Union[Path, str]) -> "PolicySet":
        policy_root = Path(root).resolve()
        documents: dict[str, dict[str, Any]] = {}
        for filename in REQUIRED_DOCUMENTS:
            path = policy_root / filename
            if not path.is_file() or path.is_symlink():
                raise PolicyConfigurationError(
                    f"required policy document is unavailable: {filename}"
                )
            try:
                value = json.loads(
                    path.read_text(encoding="utf-8"),
                    object_pairs_hook=_reject_duplicate_keys,
                    parse_constant=_reject_constant,
                    parse_float=_strict_float,
                )
            except (OSError, UnicodeError, ValueError) as exc:
                raise PolicyConfigurationError(
                    f"required policy document is invalid: {filename}"
                ) from exc
            if not isinstance(value, dict):
                raise PolicyConfigurationError(
                    f"required policy document is not an object: {filename}"
                )
            documents[filename] = value

        versions = {document.get("policyVersion") for document in documents.values()}
        _expect(
            len(versions) == 1 and all(isinstance(item, str) and item for item in versions),
            "policy documents must use one non-empty policyVersion",
        )
        trust_path = policy_root / TRUST_DOCUMENT
        if not trust_path.is_file() or trust_path.is_symlink():
            raise PolicyConfigurationError(
                "required v2 trust policy is unavailable"
            )
        try:
            trust_bytes = trust_path.read_bytes()
            trust_document = parse_json_v2(trust_bytes)
            if canonical_json_v2(trust_document, stored=True) != trust_bytes:
                raise CanonicalJSONV2Error(
                    "v2 trust policy is not canonical stored JSON"
                )
        except (OSError, UnicodeError, CanonicalJSONV2Error) as exc:
            raise PolicyConfigurationError(
                "required v2 trust policy is invalid"
            ) from exc
        if not isinstance(trust_document, dict):
            raise PolicyConfigurationError(
                "required v2 trust policy is not an object"
            )
        rights_v2_path = policy_root / RIGHTS_V2_DOCUMENT
        if not rights_v2_path.is_file() or rights_v2_path.is_symlink():
            raise PolicyConfigurationError(
                "required v2 rights registry is unavailable"
            )
        try:
            rights_v2_bytes = rights_v2_path.read_bytes()
            rights_v2_document = parse_json_v2(rights_v2_bytes)
            if (
                canonical_json_v2(rights_v2_document, stored=True)
                != rights_v2_bytes
            ):
                raise CanonicalJSONV2Error(
                    "v2 rights registry is not canonical stored JSON"
                )
        except (OSError, UnicodeError, CanonicalJSONV2Error) as exc:
            raise PolicyConfigurationError(
                "required v2 rights registry is invalid"
            ) from exc
        if not isinstance(rights_v2_document, dict):
            raise PolicyConfigurationError(
                "required v2 rights registry is not an object"
            )

        policy = cls(
            policy_root,
            documents,
            versions.pop(),
            trust_document,
            trust_bytes,
            rights_v2_document,
            rights_v2_bytes,
        )
        policy._validate_hard_invariants()
        return policy

    def document(self, filename: str) -> dict[str, Any]:
        return self.documents[filename]

    @property
    def publication(self) -> dict[str, Any]:
        return self.document("publication-policy.json")

    @property
    def quality(self) -> dict[str, Any]:
        return self.document("quality-policy.json")

    @property
    def reasoning(self) -> dict[str, Any]:
        return self.document("reasoning-policy.json")

    @property
    def rights(self) -> dict[str, Any]:
        return self.document("rights-statements.json")

    @property
    def safety(self) -> dict[str, Any]:
        return self.document("safety-policy.json")

    @property
    def sources(self) -> dict[str, Any]:
        return self.document("source-allowlist.json")

    @property
    def fields(self) -> dict[str, Any]:
        return self.document("field-allowlist.json")

    @property
    def withdrawal(self) -> dict[str, Any]:
        return self.document("withdrawal-policy.json")

    def _validate_hard_invariants(self) -> None:
        publication = self.publication
        _expect(publication.get("defaultAction") == "deny", "publication must deny by default")
        licenses = publication.get("licenses")
        _expect(
            licenses == {"data": "CC-BY-4.0", "code": "Apache-2.0"},
            "publication licenses must be CC-BY-4.0 data and Apache-2.0 code",
        )
        limits = publication.get("limits")
        _expect(isinstance(limits, dict), "publication limits must be an object")
        for name, maximum in HARD_MAXIMUMS.items():
            value = limits.get(name)
            _expect(
                isinstance(value, int) and not isinstance(value, bool) and 0 < value <= maximum,
                f"publication limit {name} exceeds the hard ceiling",
            )
        _expect(
            publication.get("rejectMixedPolicyAndPublicationChanges") is True,
            "policy/publication changes must not be mixed",
        )
        _expect(
            publication.get("requireDeclaredArtifactHashes") is True,
            "artifact hashes are mandatory",
        )
        _expect(
            publication.get("requireMatchingReviewReceipt") is True,
            "review receipts are mandatory",
        )
        _expect(
            publication.get("activeReleaseContract") == "v2-only",
            "new public releases must use only the v2 trust contract",
        )
        _expect(
            set(publication.get("candidatePathPrefixes", []))
            == {"catalog/", "datasets/", "objects/", "releases/", "worldpacks/"},
            "all public artifact surfaces must remain governed",
        )
        _expect(
            set(publication.get("sourcePathPrefixes", []))
            == {"datasets/", "worldpacks/projections/"},
            "only dataset definitions and projection recipes may bypass publication manifests",
        )
        _expect(
            {
                "catalog/catalog.json",
                "catalog/latest.json",
                "catalog/releases/**",
                "catalog/removals.json",
                "datasets/*/data-card.json",
                "datasets/*/publications/**",
                "datasets/*/releases/**",
                "datasets/*/shards/**",
            }
            <= set(publication.get("publicationPathGlobs", [])),
            "all finalized dataset and catalog paths must require publication manifests",
        )
        _expect(
            {
                "objects/",
                "releases/",
                "worldpacks/",
                "catalog/releases/",
                "catalog/tombstones/",
            }
            <= set(publication.get("immutablePathPrefixes", [])),
            "content-addressed and released paths must remain immutable",
        )
        _expect(
            {
                "datasets/*/publications/**",
                "datasets/*/releases/**",
                "datasets/*/shards/**",
            }
            <= set(publication.get("immutablePathGlobs", [])),
            "dataset publication paths must remain immutable",
        )
        reviewers = publication.get("approvedReviewerIds")
        _expect(
            isinstance(reviewers, list)
            and set(reviewers) == {"kody-w"},
            "approved reviewer identities must be explicitly trusted",
        )

        sources = self.sources
        _expect(sources.get("defaultAction") == "deny", "sources must deny by default")
        allowed_bases = sources.get("allowedRightsBases")
        _expect(
            isinstance(allowed_bases, dict)
            and set(allowed_bases) == {"synthetic", "rappterverse-owned"},
            "only synthetic and RAPPterverse-owned rights bases are allowed",
        )
        _expect(
            set(allowed_bases["synthetic"].get("sourceTypes", []))
            == {"deterministic-synthetic", "model-generated-synthetic"}
            and set(allowed_bases["rappterverse-owned"].get("sourceTypes", []))
            == {
                "rappterverse-repository",
                "system-controlled-agent",
                "consented-human-judgment",
            },
            "source types must remain synthetic or explicitly RAPPterverse-owned",
        )
        _expect(
            set(sources.get("allowedRepositories", []))
            == {"kody-w/rappterverse", "kody-w/rappterverse-data"},
            "repository sources must remain RAPPterverse-owned",
        )

        rights = self.rights
        _expect(rights.get("dataLicense") == "CC-BY-4.0", "data license is fixed")
        _expect(rights.get("codeLicense") == "Apache-2.0", "code license is fixed")
        _expect(bool(rights.get("statements")), "at least one explicit rights statement is required")
        allowed_source_types = {
            "deterministic-synthetic",
            "model-generated-synthetic",
            "rappterverse-repository",
            "system-controlled-agent",
            "consented-human-judgment",
        }
        _expect(
            all(
                isinstance(statement, dict)
                and bool(statement.get("statement"))
                and set(statement.get("sourceTypes", [])) <= allowed_source_types
                for statement in rights["statements"].values()
            ),
            "rights statements must be explicit and limited to owned source types",
        )

        safety = self.safety
        finding_output = safety.get("findingOutput")
        _expect(
            isinstance(finding_output, dict) and finding_output.get("redacted") is True,
            "findings must be redacted",
        )
        forbidden_finding_fields = set(finding_output.get("forbiddenFields", []))
        _expect(
            {"value", "snippet", "match", "context"}.issubset(forbidden_finding_fields),
            "finding output must prohibit sensitive content fields",
        )
        required_forbidden_fields = {
            "chainOfThought",
            "hiddenReasoning",
            "internalReasoning",
            "privateScratchpad",
            "privateSystemPrompt",
            "privateDeveloperPrompt",
            "operationalInstructions",
            "copilotSystemInstructions",
            "rawIdentity",
            "emailAddress",
            "accessToken",
            "apiKey",
            "privateKey",
        }
        _expect(
            required_forbidden_fields
            <= set(self.fields.get("forbiddenRecursiveFieldNames", [])),
            "sensitive and inaccessible reasoning fields must remain prohibited",
        )

        layers = self.reasoning.get("requiredLayers")
        _expect(isinstance(layers, dict), "reasoning layers must be declared")
        _expect(
            layers.get("visibleTranscript", {}).get("required") is True
            and layers.get("publicDeliberation", {}).get("required") is True,
            "visible transcripts and public deliberations are mandatory",
        )
        provider = layers.get("providerExposedReasoning", {})
        _expect(
            provider.get("allowedStatuses") == ["not-provided", "approved-public"]
            and provider.get("approvalRequiredFor") == "approved-public",
            "provider-exposed reasoning must be absent or explicitly approved",
        )

        thresholds = self.quality.get("publicationThresholds")
        _expect(isinstance(thresholds, dict), "publication quality thresholds are required")
        minimum = thresholds.get("minimum")
        _expect(
            isinstance(minimum, dict)
            and minimum
            and all(value == 1.0 for value in minimum.values()),
            "all publication pass and coverage rates must be 1.0",
        )
        _expect(
            self.quality.get("requiredPublicExposureLabel") == "public-on-release"
            and self.quality.get("requiredEvaluationUseLabel")
            == "contamination-prone-not-clean-evaluation",
            "public-exposure and contamination notices are mandatory",
        )

        withdrawal = self.withdrawal
        _expect(
            withdrawal.get("strategy") == "append-only-tombstone"
            and withdrawal.get("deleteOriginal") is False
            and withdrawal.get("rewriteHistory") is False,
            "withdrawals must preserve released bytes and history",
        )

        trust = self.trust_document
        _expect(
            trust.get("schemaVersion")
            == "rappterverse.publication-trust-policy/v2"
            and trust.get("policyId") == "rappterverse-publication-trust"
            and trust.get("policyVersion") == "2.0.0"
            and trust.get("releaseContract") == "v2-only",
            "v2 trust policy identity is fixed",
        )
        roster = trust.get("reviewerRoster")
        trust_reviewers = (
            roster.get("reviewers", []) if isinstance(roster, dict) else []
        )
        trust_roles = (
            trust_reviewers[0].get("roles", [])
            if isinstance(trust_reviewers, list)
            and len(trust_reviewers) == 1
            and isinstance(trust_reviewers[0], dict)
            else []
        )
        _expect(
            isinstance(roster, dict)
            and roster.get("minimumApprovals") == 1
            and isinstance(trust_reviewers, list)
            and len(trust_reviewers) == 1
            and isinstance(trust_reviewers[0], dict)
            and trust_reviewers[0].get("reviewerId") == "kody-w"
            and isinstance(trust_roles, list)
            and set(trust_roles)
            == {"public-data-reviewer", "release-reviewer"},
            "v2 reviewer roster must explicitly trust only kody-w",
        )
        mechanisms = trust.get("approvalMechanisms")
        _expect(
            isinstance(mechanisms, dict)
            and mechanisms.get("current")
            == "content-addressed-public-review-receipt"
            and mechanisms.get("futureApprovalReferenceAllowed") is True
            and mechanisms.get("signedApprovals") == "not-enabled",
            "v2 approvals must not claim an unavailable signing gate",
        )
        _expect(
            trust.get("limits")
            == {
                "diagnosticsHardCount": 50,
                "fileHardBytes": 1_000_000,
                "jsonlLineHardBytes": 262_144,
                "manifestHardBytes": 512_000,
                "publicationFilesHard": 5,
                "pullRequestDiffHardBytes": 900_000,
            },
            "v2 trust limits must preserve all frozen hard ceilings",
        )
        rights_ref = trust.get("rightsRegistry")
        _expect(
            isinstance(rights_ref, dict)
            and rights_ref
            == {
                "schemaVersion": "rappterverse.rights-statements/v2",
                "path": "policies/rights-statements-v2.json",
                "bytes": len(self.rights_v2_document_bytes),
                "sha256": hashlib.sha256(
                    self.rights_v2_document_bytes
                ).hexdigest(),
            },
            "v2 trust policy must pin the exact closed rights registry bytes",
        )
        rights_v2 = self.rights_v2_document
        statements = rights_v2.get("statements")
        _expect(
            rights_v2.get("schemaVersion")
            == "rappterverse.rights-statements/v2"
            and rights_v2.get("registryId")
            == "rappterverse-publication-rights"
            and rights_v2.get("registryVersion") == "2.0.0"
            and rights_v2.get("defaultAction") == "deny"
            and rights_v2.get("dataLicense") == "CC-BY-4.0"
            and isinstance(statements, list)
            and bool(statements),
            "v2 rights registry identity and deny-by-default behavior are fixed",
        )
        statement_ids = [
            item.get("rightsStatementId")
            for item in statements
            if isinstance(item, dict)
        ]
        _expect(
            len(statement_ids) == len(statements)
            and statement_ids == sorted(statement_ids)
            and len(statement_ids) == len(set(statement_ids)),
            "v2 rights statements must be sorted and uniquely identified",
        )
        active_source_types = set()
        for statement in statements:
            source_types = (
                statement.get("sourceTypes", [])
                if isinstance(statement, dict)
                else []
            )
            attestations = (
                statement.get("attestations", [])
                if isinstance(statement, dict)
                else []
            )
            attestation_map = {
                item.get("sourceType"): item.get("requiredFields")
                for item in attestations
                if isinstance(item, dict)
            }
            _expect(
                isinstance(statement, dict)
                and isinstance(source_types, list)
                and isinstance(attestations, list)
                and len(attestation_map) == len(attestations)
                and set(attestation_map) == set(source_types)
                and all(
                    set(attestation_map.get(source_type, []))
                    == RIGHTS_V2_ATTESTATIONS.get(source_type)
                    and statement.get("rightsBasis")
                    == RIGHTS_V2_BASIS_BY_SOURCE.get(source_type)
                    for source_type in source_types
                ),
                "v2 rights attestations must be complete for every source type",
            )
            if statement.get("status") == "active":
                active_source_types.update(source_types)
        _expect(
            active_source_types == set(RIGHTS_V2_ATTESTATIONS),
            "v2 rights registry must actively cover every allowed source type",
        )
