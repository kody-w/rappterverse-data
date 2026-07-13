# SPDX-License-Identifier: Apache-2.0

"""Loading and hardening for repository governance policy."""

from __future__ import annotations

import json
import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any


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

    @classmethod
    def load(cls, root: Path | str) -> "PolicySet":
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
        policy = cls(policy_root, documents, versions.pop())
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
            {"objects/", "releases/", "worldpacks/", "catalog/tombstones/"}
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
