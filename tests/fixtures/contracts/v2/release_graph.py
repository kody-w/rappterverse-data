"""Deterministic, synthetic, no-PII ten-dataset v2 release graph fixture."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

from scripts.contracts.canonical import canonical_json_v2

DATASET_IDS = [
    "d01-civilization-ledger",
    "d02-counterfactual-multiverse",
    "d03-human-judgment",
    "d04-work-trajectories",
    "d05-agent-lifetimes",
    "d06-social-causality",
    "d07-market-tape",
    "d08-governance-precedent",
    "d09-failure-recovery",
    "d10-agent-lineage",
]
RELEASE_ID = "release-2026-07-12-synthetic-fixture"
PREVIOUS_RELEASE_ID = "release-2026-07-11-synthetic-fixture"
CREATED_AT = "2026-07-12T20:00:00Z"
GENERATOR_COMMIT = "a" * 40
CHECK_NAMES = (
    "sourceOwnership",
    "rights",
    "privacy",
    "secrets",
    "safety",
    "transcriptPolicy",
    "contamination",
    "quality",
)


def _write(root: Path, path: str, data: bytes) -> None:
    target = root / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)


def _raw_descriptor(
    path: str, artifact_kind: str, media_type: str, data: bytes
) -> Dict[str, Any]:
    return {
        "path": path,
        "artifactKind": artifact_kind,
        "mediaType": media_type,
        "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _write_object(
    root: Path,
    namespace: str,
    artifact_kind: str,
    media_type: str,
    data: bytes,
    extension: str,
) -> Dict[str, Any]:
    digest = hashlib.sha256(data).hexdigest()
    path = "objects/{}/sha256/{}/{}.{}".format(
        namespace, digest[:2], digest, extension
    )
    _write(root, path, data)
    return _raw_descriptor(path, artifact_kind, media_type, data)


def _write_json_object(
    root: Path, namespace: str, artifact_kind: str, value: Mapping[str, Any]
) -> Dict[str, Any]:
    return _write_object(
        root,
        namespace,
        artifact_kind,
        "application/json",
        canonical_json_v2(value, stored=True),
        "json",
    )


def _write_json_at(
    root: Path, path: str, artifact_kind: str, value: Mapping[str, Any]
) -> Dict[str, Any]:
    data = canonical_json_v2(value, stored=True)
    _write(root, path, data)
    return _raw_descriptor(path, artifact_kind, "application/json", data)


def _write_shard(
    root: Path,
    namespace: str,
    artifact_kind: str,
    value: Mapping[str, Any],
    item_id: str,
) -> Dict[str, Any]:
    data = canonical_json_v2(value, stored=True)
    raw = _write_object(
        root,
        namespace,
        artifact_kind,
        "application/x-ndjson",
        data,
        "jsonl",
    )
    raw.update(
        {
            "itemCount": 1,
            "firstItemId": item_id,
            "lastItemId": item_id,
            "maxLineBytes": len(data),
            "canonicalization": "rappterverse-canonical-json/v2",
        }
    )
    return raw


def _policy_ref(policy_bytes: bytes) -> Dict[str, Any]:
    return {
        "policyId": "rappterverse-publication-trust",
        "policyVersion": "2.0.0",
        "path": "policies/publication-trust-v2.json",
        "sha256": hashlib.sha256(policy_bytes).hexdigest(),
    }


def _receipt(
    root: Path,
    policy: Mapping[str, Any],
    review_id: str,
    scope: str,
    artifacts: List[Mapping[str, Any]],
    dataset_id: Optional[str],
    *,
    provider_terms: Optional[Mapping[str, Any]] = None,
    predecessor: Optional[Mapping[str, Any]] = None,
) -> Dict[str, Any]:
    raw_artifacts = sorted(
        [
            {
                name: artifact[name]
                for name in (
                    "path",
                    "artifactKind",
                    "mediaType",
                    "bytes",
                    "sha256",
                )
            }
            for artifact in artifacts
        ],
        key=lambda item: (item["path"], item["sha256"]),
    )
    evidence_artifact = raw_artifacts[0]
    evidence = [
        {
            "artifactPath": evidence_artifact["path"],
            "artifactSha256": evidence_artifact["sha256"],
            "summary": "Synthetic fixture check evidence.",
        }
    ]
    value = {
        "schemaVersion": "rappterverse.public-review-receipt/v2",
        "reviewId": review_id,
        "scope": scope,
        "datasetId": dataset_id,
        "reviewedAt": CREATED_AT,
        "reviewer": "kody-w",
        "policy": dict(policy),
        "approvedArtifacts": raw_artifacts,
        "disposition": "approve_public",
        "checks": {
            name: {"status": "pass", "evidence": evidence}
            for name in CHECK_NAMES
        },
        "providerRedistributionApproval": (
            None
            if provider_terms is None
            else {
                "approved": True,
                "termsReference": {
                    name: provider_terms[name]
                    for name in (
                        "path",
                        "artifactKind",
                        "mediaType",
                        "bytes",
                        "sha256",
                    )
                },
            }
        ),
        "predecessor": predecessor,
        "approvalReference": None,
        "reasonCodes": ["synthetic-fixture-approved"],
    }
    descriptor = _write_json_object(
        root, "review-receipts", "public-review-receipt", value
    )
    return {"path": descriptor["path"], "sha256": descriptor["sha256"]}


def _reviewed(
    descriptor: Mapping[str, Any], receipt: Mapping[str, Any]
) -> Dict[str, Any]:
    value = dict(descriptor)
    value["reviewReceiptRef"] = receipt["path"]
    return value


def write_minimal_previous_release_pointer(
    root: Path, policy_bytes: bytes
) -> Dict[str, Any]:
    """Write a fabricated pointer for explicit fail-closed rejection tests."""

    policy = _policy_ref(policy_bytes)
    release_digest = "a" * 64
    review_set_digest = "b" * 64
    receipt_digest = "c" * 64
    pointer = {
        "schemaVersion": "rappterverse.catalog-release-pointer/v2",
        "releaseId": PREVIOUS_RELEASE_ID,
        "createdAt": "2026-07-11T20:00:00Z",
        "sequence": 1,
        "previousReleaseId": None,
        "previousReleasePointerSha256": None,
        "policy": dict(policy),
        "releaseManifest": {
            "path": "releases/{}/manifest.json".format(PREVIOUS_RELEASE_ID),
            "artifactKind": "release-manifest",
            "mediaType": "application/json",
            "bytes": 1,
            "sha256": release_digest,
            "reviewReceiptRef": (
                "objects/review-receipts/sha256/{}/{}.json".format(
                    receipt_digest[:2], receipt_digest
                )
            ),
        },
        "activeReviewSet": {
            "path": "objects/active-review-sets/sha256/{}/{}.json".format(
                review_set_digest[:2], review_set_digest
            ),
            "artifactKind": "active-review-set",
            "mediaType": "application/json",
            "bytes": 1,
            "sha256": review_set_digest,
            "reviewReceiptRef": (
                "objects/review-receipts/sha256/{}/{}.json".format(
                    receipt_digest[:2], receipt_digest
                )
            ),
        },
        "totals": {
            "datasets": 10,
            "records": 10,
            "transcripts": 10,
            "deliberations": 10,
            "providerReasoning": 0,
            "worldPackSources": 1,
            "contentBytes": 1,
        },
    }
    path = "catalog/releases/{}.json".format(PREVIOUS_RELEASE_ID)
    descriptor = _write_json_at(
        root, path, "catalog-release-pointer", pointer
    )
    return {
        "releaseId": PREVIOUS_RELEASE_ID,
        "sequence": 1,
        "descriptor": descriptor,
    }


def _record(
    dataset_id: str,
    code: str,
    *,
    provider_reasoning_id: Optional[str],
) -> Dict[str, Any]:
    return {
        "schemaVersion": "rappterverse.public-record/v2",
        "datasetId": dataset_id,
        "recordId": "record-{}-item-001".format(code),
        "recordType": "synthetic-transition",
        "episodeId": "episode-{}-001".format(code),
        "sequence": 0,
        "split": "train",
        "eventTime": CREATED_AT,
        "payload": {
            "fixture": True,
            "datasetCode": code,
            "transition": "synthetic-state-change",
        },
        "provenance": {
            "rightsBasis": "synthetic",
            "rightsStatementId": "rights-project-synthetic-v2",
            "lineageComplete": True,
            "externalContentIncluded": False,
            "sources": [
                {
                    "sourceType": "deterministic-synthetic",
                    "sourceId": "urn:rappterverse:synthetic:{}-fixture".format(
                        code
                    ),
                    "generatorCommit": GENERATOR_COMMIT,
                }
            ],
        },
        "generation": {
            "runId": "run-{}-fixture".format(code),
            "generatorCommit": GENERATOR_COMMIT,
            "seed": "fixture-seed-{}".format(code),
            "transcriptId": "transcript-{}-item-001".format(code),
            "deliberationId": "deliberation-{}-item-001".format(code),
            "providerReasoningId": provider_reasoning_id,
        },
        "governance": {
            "license": "CC-BY-4.0",
            "privacy": "synthetic-nonpersonal",
            "safetyReviewPassed": True,
            "contamination": "public-generated-contamination-risk",
            "qualityPassed": True,
        },
    }


def _transcript(dataset_id: str, code: str) -> Dict[str, Any]:
    event_base = {
        "timestamp": CREATED_AT,
        "actorId": "fixture-agent",
    }
    events = [
        {
            **event_base,
            "eventId": "event-{}-000".format(code),
            "sequence": 0,
            "kind": "system-prompt",
            "content": "Generate one synthetic fixture.",
        },
        {
            **event_base,
            "eventId": "event-{}-001".format(code),
            "sequence": 1,
            "kind": "user-prompt",
            "content": "Proceed with public-safe synthetic data.",
        },
        {
            **event_base,
            "eventId": "event-{}-002".format(code),
            "sequence": 2,
            "kind": "assistant-output",
            "content": {"plan": "create deterministic fixture"},
        },
        {
            **event_base,
            "eventId": "event-{}-003".format(code),
            "sequence": 3,
            "kind": "tool-call",
            "callId": "call-{}-001".format(code),
            "toolName": "fixture",
            "arguments": {"dataset": code},
        },
        {
            **event_base,
            "eventId": "event-{}-004".format(code),
            "sequence": 4,
            "kind": "tool-result",
            "callId": "call-{}-001".format(code),
            "toolName": "fixture",
            "success": True,
            "result": {"created": True},
        },
        {
            **event_base,
            "eventId": "event-{}-005".format(code),
            "sequence": 5,
            "kind": "verifier-result",
            "verifierId": "verifier-fixture",
            "passed": True,
            "result": "All deterministic checks passed.",
        },
        {
            **event_base,
            "eventId": "event-{}-006".format(code),
            "sequence": 6,
            "kind": "final-outcome",
            "status": "success",
            "content": "Synthetic fixture completed.",
        },
    ]
    return {
        "schemaVersion": "rappterverse.visible-transcript/v2",
        "transcriptId": "transcript-{}-item-001".format(code),
        "datasetId": dataset_id,
        "recordId": "record-{}-item-001".format(code),
        "runId": "run-{}-fixture".format(code),
        "episodeId": "episode-{}-001".format(code),
        "startedAt": CREATED_AT,
        "completedAt": CREATED_AT,
        "participants": [
            {
                "actorId": "fixture-agent",
                "role": "assistant",
                "displayName": "Synthetic Fixture Agent",
            }
        ],
        "capture": {
            "systemPrompts": True,
            "userPrompts": True,
            "assistantOutputs": True,
            "toolCalls": True,
            "toolArguments": True,
            "toolResults": True,
            "verifierResults": True,
            "finalOutcomes": True,
            "complete": True,
            "publicSafe": True,
            "inaccessibleReasoningIncluded": False,
        },
        "events": events,
    }


def _deliberation(dataset_id: str, code: str) -> Dict[str, Any]:
    return {
        "schemaVersion": "rappterverse.public-deliberation/v2",
        "deliberationId": "deliberation-{}-item-001".format(code),
        "datasetId": dataset_id,
        "recordId": "record-{}-item-001".format(code),
        "transcriptId": "transcript-{}-item-001".format(code),
        "generatedAt": CREATED_AT,
        "purpose": "explicit-publishable-deliberation",
        "evidence": ["The fixture specification requires synthetic data."],
        "assumptions": ["No external content is included."],
        "alternatives": [
            {
                "option": "Create one deterministic item.",
                "benefits": ["Small and replayable."],
                "risks": ["Limited variety."],
            },
            {
                "option": "Create two deterministic items.",
                "benefits": ["More variety."],
                "risks": ["A larger fixture."],
            },
        ],
        "uncertainty": {
            "confidenceBasisPoints": 10000,
            "summary": "The deterministic fixture has no stochastic branch.",
            "unknowns": ["Future release volumes are outside this fixture."],
        },
        "critiques": ["One item cannot represent production scale."],
        "rejectedOptions": ["External examples are excluded by policy."],
        "decision": "Create one deterministic synthetic item.",
        "expectedOutcome": "All trust-layer checks pass.",
        "limitations": ["This fixture is intentionally small."],
        "inaccessibleReasoningIncluded": False,
    }


def _data_card(
    dataset_id: str,
    policy: Mapping[str, Any],
    provider_count: int,
) -> Dict[str, Any]:
    return {
        "schemaVersion": "rappterverse.data-card/v2",
        "datasetId": dataset_id,
        "datasetVersion": "v2.0.0",
        "title": "Synthetic fixture for {}".format(dataset_id),
        "summary": "One deterministic synthetic record for trust-layer tests.",
        "maintainers": ["kody-w"],
        "policy": dict(policy),
        "license": "CC-BY-4.0",
        "sourceBoundary": {
            "allowed": ["synthetic"],
            "externalCorporaIncluded": False,
            "lineageComplete": True,
        },
        "composition": {
            "recordTypes": ["synthetic-transition"],
            "records": 1,
            "transcripts": 1,
            "deliberations": 1,
            "providerReasoning": provider_count,
            "splits": {
                "train": 1,
                "validation": 0,
                "test": 0,
                "unassigned": 0,
            },
        },
        "generation": {
            "method": "Deterministic in-repository fixture builder.",
            "visibleTranscripts": "complete",
            "explicitDeliberations": "required",
            "providerReasoningPolicy": "optional-external-receipt-gated",
        },
        "intendedUses": ["Trust-layer regression testing."],
        "outOfScopeUses": ["Real-person profiling."],
        "privacy": {
            "classification": "synthetic-nonpersonal",
            "realPiiIncluded": False,
            "secretsIncluded": False,
        },
        "rights": {
            "ownershipVerified": True,
            "externalContentIncluded": False,
        },
        "safety": {
            "reviewed": True,
            "status": "pass",
            "knownRisks": ["The fixture is not production-scale data."],
        },
        "contamination": {
            "publicDataset": True,
            "evaluationUse": "contamination-prone-not-clean-evaluation",
        },
        "quality": {
            "allRecordsSchemaValid": True,
            "allVerifiersPassed": True,
            "allProvenanceVerified": True,
            "duplicateRecords": 0,
        },
        "limitations": ["One record per dataset."],
        "maintenance": {
            "immutableRelease": True,
            "withdrawalPolicy": "append-only-tombstone",
            "contact": "https://github.com/kody-w/rappterverse-data/issues",
        },
    }


def build_release_graph(
    root: Path,
    policy_bytes: bytes,
    rights_bytes: bytes,
    *,
    release_id: str = RELEASE_ID,
    previous: Optional[Mapping[str, Any]] = None,
    world_source_path: Optional[str] = None,
    previous_digest_override: Optional[str] = None,
    mutate_artifact: Optional[
        Callable[[str, str, Dict[str, Any]], None]
    ] = None,
) -> Dict[str, Any]:
    """Write and return metadata for one complete valid release graph."""

    policy = _policy_ref(policy_bytes)
    _write(root, policy["path"], policy_bytes)
    _write(root, "policies/rights-statements-v2.json", rights_bytes)

    dataset_manifests: List[Dict[str, Any]] = []
    dataset_entries: List[Dict[str, Any]] = []
    active_receipts: List[Dict[str, Any]] = []
    world_raw: Optional[Dict[str, Any]] = None
    world_reviewed: Optional[Dict[str, Any]] = None
    recipe_raw = _write_json_object(
        root,
        "projection-recipes",
        "projection-recipe",
        {
            "schemaVersion": "rappterverse.projection-recipe/v2",
            "recipeId": "recipe-d01-fixture",
            "version": "v1",
            "engine": "rappterverse-world-pack-projection/v1",
            "configuration": {"fixture": True},
            "deterministic": True,
        },
    )
    recipe_receipt = _receipt(
        root,
        policy,
        "review-d01-projection-recipe-v2",
        "dataset-leaves",
        [recipe_raw],
        DATASET_IDS[0],
    )
    active_receipts.append(recipe_receipt)
    reviewed_recipe = _reviewed(recipe_raw, recipe_receipt)

    for index, dataset_id in enumerate(DATASET_IDS, start=1):
        code = "d{:02d}".format(index)
        provider_id = "reasoning-d01-item-001" if index == 1 else None
        record = _record(
            dataset_id, code, provider_reasoning_id=provider_id
        )
        transcript = _transcript(dataset_id, code)
        deliberation = _deliberation(dataset_id, code)
        if mutate_artifact is not None:
            mutate_artifact("record", code, record)
            mutate_artifact("transcript", code, transcript)
            mutate_artifact("deliberation", code, deliberation)
        shards = [
            _write_shard(
                root,
                "records",
                "record-shard",
                record,
                record["recordId"],
            ),
            _write_shard(
                root,
                "transcripts",
                "transcript-shard",
                transcript,
                transcript["transcriptId"],
            ),
            _write_shard(
                root,
                "deliberations",
                "deliberation-shard",
                deliberation,
                deliberation["deliberationId"],
            ),
        ]
        supporting: List[Dict[str, Any]] = []
        provider_terms: Optional[Dict[str, Any]] = None
        if index == 1:
            terms_data = (
                b"Synthetic fixture provider terms permit redistribution "
                b"under CC-BY-4.0.\n"
            )
            provider_terms = _write_object(
                root,
                "provider-terms",
                "provider-terms",
                "text/plain",
                terms_data,
                "txt",
            )
            supporting.append(provider_terms)
            reasoning = {
                "schemaVersion": "rappterverse.provider-reasoning/v2",
                "reasoningId": provider_id,
                "datasetId": dataset_id,
                "recordId": record["recordId"],
                "transcriptId": transcript["transcriptId"],
                "availability": "provider-exposed",
                "source": {
                    "provider": "fixture-provider",
                    "modelId": "fixture-model-v1",
                    "requestId": "fixture-request-001",
                    "apiField": "reasoning",
                    "providerFormat": "fixture-visible-reasoning",
                    "exposedByProvider": True,
                    "redistributionTermsRef": dict(provider_terms),
                },
                "content": {
                    "verbatim": True,
                    "complete": True,
                    "fragments": ["Provider-visible synthetic fixture rationale."],
                },
                "internalReasoningRequested": False,
                "inaccessibleReasoningIncluded": False,
            }
            if mutate_artifact is not None:
                mutate_artifact("provider-reasoning", code, reasoning)
            shards.append(
                _write_shard(
                    root,
                    "provider-reasoning",
                    "provider-reasoning-shard",
                    reasoning,
                    str(provider_id),
                )
            )
            world_source = {
                "schemaVersion": "rappterverse.world-pack-source/v2",
                "worldPackSourceId": "world-pack-source-synthetic-fixture",
                "releaseId": release_id,
                "projectionRecipe": reviewed_recipe,
                "namespace": "rappterverse/synthetic-fixture",
                "seedChannels": [
                    {
                        "channel": "immutable-layout",
                        "seed": "fixture-layout-seed",
                    }
                ],
                "entities": [
                    {
                        "entityId": "source:world:synthetic-fixture",
                        "kind": "world",
                        "name": "Synthetic Fixture World",
                        "description": "A tiny world used only by contract tests.",
                        "sourceRecordIds": [record["recordId"]],
                        "tags": ["fixture", "synthetic"],
                        "attributes": {"dataset": dataset_id},
                        "references": [],
                        "immutableBase": True,
                        "preservedOverlayFields": ["position", "status"],
                    }
                ],
                "sortedByStableKey": True,
                "canonicalization": "rappterverse-canonical-json/v2",
            }
            world_raw = (
                _write_json_object(
                    root,
                    "world-pack-sources",
                    "world-pack-source",
                    world_source,
                )
                if world_source_path is None
                else _write_json_at(
                    root,
                    world_source_path,
                    "world-pack-source",
                    world_source,
                )
            )

        card = _write_json_object(
            root,
            "data-cards",
            "data-card",
            _data_card(dataset_id, policy, 1 if index == 1 else 0),
        )
        core_shards = [
            item
            for item in shards
            if item["artifactKind"] != "provider-reasoning-shard"
        ]
        provider_shards = [
            item
            for item in shards
            if item["artifactKind"] == "provider-reasoning-shard"
        ]
        leaf_groups = [
            ("core", [card, *core_shards], None),
        ]
        if provider_shards or supporting:
            leaf_groups.append(
                (
                    "provider",
                    [*provider_shards, *supporting],
                    provider_terms,
                )
            )
        if world_raw is not None and index == 1:
            leaf_groups.append(("world", [world_raw], None))

        receipt_by_artifact_path: Dict[str, Dict[str, Any]] = {}
        for group_name, artifacts, group_terms in leaf_groups:
            if len(artifacts) > 4:
                raise AssertionError("fixture batch exceeds four artifacts")
            receipt = _receipt(
                root,
                policy,
                "review-{}-{}-leaves-v2".format(code, group_name),
                "dataset-leaves",
                artifacts,
                dataset_id,
                provider_terms=group_terms,
            )
            active_receipts.append(receipt)
            for artifact in artifacts:
                receipt_by_artifact_path[artifact["path"]] = receipt

        reviewed_card = _reviewed(
            card, receipt_by_artifact_path[card["path"]]
        )
        reviewed_shards = sorted(
            [
                _reviewed(
                    item, receipt_by_artifact_path[item["path"]]
                )
                for item in shards
            ],
            key=lambda item: item["path"],
        )
        reviewed_supporting = sorted(
            [
                _reviewed(
                    item, receipt_by_artifact_path[item["path"]]
                )
                for item in supporting
            ],
            key=lambda item: item["path"],
        )
        if world_raw is not None and index == 1:
            world_reviewed = _reviewed(
                world_raw,
                receipt_by_artifact_path[world_raw["path"]],
            )

        counts = {
            "records": 1,
            "transcripts": 1,
            "deliberations": 1,
            "providerReasoning": 1 if index == 1 else 0,
        }
        split_counts = {
            "train": 1,
            "validation": 0,
            "test": 0,
            "unassigned": 0,
        }
        described = [reviewed_card, *reviewed_shards, *reviewed_supporting]
        manifest = {
            "schemaVersion": "rappterverse.dataset-manifest/v2",
            "datasetId": dataset_id,
            "datasetVersion": "v2.0.0",
            "createdAt": CREATED_AT,
            "policy": dict(policy),
            "dataCard": reviewed_card,
            "shards": reviewed_shards,
            "supportingArtifacts": reviewed_supporting,
            "counts": counts,
            "splits": split_counts,
            "artifactCount": len(described),
            "contentBytes": sum(item["bytes"] for item in described),
        }
        manifest_path = "releases/{}/datasets/{}.json".format(
            release_id, dataset_id
        )
        manifest_raw = _write_json_at(
            root, manifest_path, "dataset-manifest", manifest
        )
        dataset_manifests.append(manifest_raw)
        dataset_entries.append(
            {
                "datasetId": dataset_id,
                "datasetVersion": "v2.0.0",
                "manifest": manifest_raw,
                "counts": counts,
                "contentBytes": manifest["contentBytes"],
            }
        )

    manifest_receipt_by_path: Dict[str, Dict[str, Any]] = {}
    for offset in range(0, len(dataset_manifests), 4):
        batch = dataset_manifests[offset : offset + 4]
        manifest_receipt = _receipt(
            root,
            policy,
            "review-dataset-manifests-{:02d}-v2".format(
                offset // 4 + 1
            ),
            "dataset-manifests",
            batch,
            None,
        )
        active_receipts.append(manifest_receipt)
        for manifest in batch:
            manifest_receipt_by_path[manifest["path"]] = (
                manifest_receipt
            )
    for entry in dataset_entries:
        manifest = entry["manifest"]
        entry["manifest"] = _reviewed(
            manifest,
            manifest_receipt_by_path[manifest["path"]],
        )

    if world_reviewed is None:
        raise AssertionError("world fixture was not generated")
    totals = {
        "datasets": 10,
        "records": 10,
        "transcripts": 10,
        "deliberations": 10,
        "providerReasoning": 1,
        "worldPackSources": 1,
        "contentBytes": sum(
            item["contentBytes"] for item in dataset_entries
        )
        + world_reviewed["bytes"],
    }
    release = {
        "schemaVersion": "rappterverse.release-manifest/v2",
        "releaseId": release_id,
        "createdAt": CREATED_AT,
        "sequence": (
            1
            if previous is None
            else int(previous["sequence"]) + 1
        ),
        "previousReleaseId": (
            None if previous is None else previous["releaseId"]
        ),
        "previousReleasePointer": (
            None if previous is None else dict(previous["descriptor"])
        ),
        "policy": dict(policy),
        "datasets": dataset_entries,
        "worldPackSources": [world_reviewed],
        "totals": totals,
    }
    release_path = "releases/{}/manifest.json".format(release_id)
    release_raw = _write_json_at(
        root, release_path, "release-manifest", release
    )

    active_receipts = sorted(active_receipts, key=lambda item: item["path"])
    review_set = {
        "schemaVersion": "rappterverse.active-review-set/v2",
        "reviewSetId": "review-set-synthetic-fixture-v2",
        "releaseId": release_id,
        "generatedAt": CREATED_AT,
        "policy": dict(policy),
        "receipts": active_receipts,
        "heads": active_receipts,
    }
    review_set_raw = _write_json_object(
        root,
        "active-review-sets",
        "active-review-set",
        review_set,
    )
    release_receipt = _receipt(
        root,
        policy,
        "review-release-and-active-set-v2",
        "release",
        [release_raw, review_set_raw],
        None,
    )
    release_reviewed = _reviewed(release_raw, release_receipt)
    review_set_reviewed = _reviewed(review_set_raw, release_receipt)

    pointer = {
        "schemaVersion": "rappterverse.catalog-release-pointer/v2",
        "releaseId": release_id,
        "createdAt": CREATED_AT,
        "sequence": release["sequence"],
        "previousReleaseId": release["previousReleaseId"],
        "previousReleasePointerSha256": (
            None
            if previous is None
            else (
                previous_digest_override
                if previous_digest_override is not None
                else previous["descriptor"]["sha256"]
            )
        ),
        "policy": dict(policy),
        "releaseManifest": release_reviewed,
        "activeReviewSet": review_set_reviewed,
        "totals": totals,
    }
    pointer_path = "catalog/releases/{}.json".format(release_id)
    pointer_raw = _write_json_at(
        root, pointer_path, "catalog-release-pointer", pointer
    )
    pointer_receipt = _receipt(
        root,
        policy,
        "review-catalog-pointer-v2",
        "catalog-pointer",
        [pointer_raw],
        None,
    )
    latest = {
        "schemaVersion": "rappterverse.catalog-latest-pointer/v2",
        "releasePointer": _reviewed(pointer_raw, pointer_receipt),
    }
    latest_path = "catalog/latest.json"
    _write(root, latest_path, canonical_json_v2(latest, stored=True))
    return {
        "latestPath": latest_path,
        "releaseId": release_id,
        "releasePath": release_path,
        "pointerPath": pointer_path,
        "pointerDescriptor": pointer_raw,
        "reviewSetPath": review_set_raw["path"],
        "datasetManifestPaths": [
            item["path"] for item in dataset_manifests
        ],
        "activeReceiptPaths": [item["path"] for item in active_receipts],
        "releaseReceiptPath": release_receipt["path"],
        "pointerReceiptPath": pointer_receipt["path"],
        "projectionRecipePath": recipe_raw["path"],
        "worldSourcePath": world_raw["path"],
    }
