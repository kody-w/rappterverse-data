# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any, Callable, Optional


ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / ".work"
WORK.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / "scripts" / "governance"))

from policy import PolicySet  # noqa: E402
from validator import (  # noqa: E402
    Change,
    GovernanceValidator,
    artifact_set_digest,
    canonical_sha256,
)


POLICIES = PolicySet.load(ROOT / "policies")
DATASET_ID = "d01-civilization-ledger"
MANIFEST_PATH = (
    "datasets/d01-civilization-ledger/publications/publication-001/manifest.json"
)
RIGHTS_TEXT = POLICIES.rights["statements"]["synthetic-project-generated-v1"][
    "statement"
]


def quality() -> dict[str, Any]:
    return {
        "recordCount": 1,
        "metrics": {
            **{
                name: 1.0
                for name in POLICIES.quality["publicationThresholds"]["minimum"]
            },
            "duplicateRate": 0.0,
        },
    }


def provenance() -> dict[str, Any]:
    return {
        "rightsBasis": "synthetic",
        "rightsStatementId": "synthetic-project-generated-v1",
        "rightsStatement": RIGHTS_TEXT,
        "sources": [
            {
                "type": "deterministic-synthetic",
                "sourceId": "urn:rappterverse:synthetic:test-fixture",
                "generatorCommit": "a" * 40,
            }
        ],
    }


def governance(public_hash: str, candidate_hash: str = "c" * 64) -> dict[str, Any]:
    return {
        "privacy": "synthetic-nonpersonal",
        "safetyStatus": "pass",
        "safetyLabels": ["none"],
        "contamination": {"label": "deterministic-synthetic-public"},
        "publicExposure": {"label": "public-on-release"},
        "evaluationUse": "contamination-prone-not-clean-evaluation",
        "quality": quality(),
        "reviewReceipt": {
            "candidateSha256": candidate_hash,
            "disposition": "approve_public",
            "reviewer": "kody-w",
            "policyVersion": POLICIES.version,
            "reviewedAt": "2026-07-12T20:00:00Z",
            "publicArtifactSha256": public_hash,
        },
    }


class CandidateFixture(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.transcript_ref = self.write_existing_layer(
            "transcripts", b'{"events":[]}\n'
        )
        self.deliberation_ref = self.write_existing_layer(
            "deliberations",
            b'{"decision":"use synthetic fixture","uncertainty":"none"}\n',
        )
        self.provider_ref = self.write_existing_layer(
            "reasoning", b'{"providerVisible":"approved fixture"}\n'
        )

    def write_bytes(self, path: str, data: bytes) -> None:
        destination = self.root / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(data)

    def write_json(self, path: str, value: Any) -> None:
        self.write_bytes(
            path,
            (json.dumps(value, ensure_ascii=False, indent=4) + "\n").encode("utf-8"),
        )

    def write_existing_layer(self, store: str, data: bytes) -> str:
        digest = hashlib.sha256(data).hexdigest()
        self.write_bytes(
            f"objects/{store}/sha256/{digest[:2]}/{digest}.json", data
        )
        return f"sha256:{digest}"

    def object_path(self, store: str, data: bytes, extension: str) -> str:
        digest = hashlib.sha256(data).hexdigest()
        return f"objects/{store}/sha256/{digest[:2]}/{digest}.{extension}"

    def validate(
        self, changes: list[Change], *, diff_bytes: int = 0
    ):
        return GovernanceValidator(
            self.root,
            POLICIES,
            allow_historical_v1=True,
        ).validate(changes, diff_bytes=diff_bytes)

    def test_contract_negative_fixture_can_name_forbidden_fields(self) -> None:
        path = "tests/fixtures/contracts/invalid/cases.json"
        self.write_json(path, {"chainOfThought": "invalid fixture marker"})
        report = self.validate([Change("A", path)])
        self.assertTrue(report.ok, report.as_dict())

    def test_non_fixture_json_cannot_name_forbidden_fields(self) -> None:
        path = "configs/unsafe.json"
        self.write_json(path, {"chainOfThought": "must remain prohibited"})
        report = self.validate([Change("A", path)])
        self.assertFalse(report.ok)
        self.assertIn("FIELD_FORBIDDEN", {item.code for item in report.findings})

    def manifest_for(
        self,
        artifacts: list[tuple[str, str, str]],
    ) -> dict[str, Any]:
        entries = []
        for path, role, media_type in artifacts:
            data = (self.root / path).read_bytes()
            entries.append(
                {
                    "path": path,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "bytes": len(data),
                    "mediaType": media_type,
                    "role": role,
                }
            )
        public_hash = artifact_set_digest(entries)
        return {
            "schema": "rappterverse.publication/v1",
            "publicationId": "publication-d01-001",
            "datasetId": DATASET_ID,
            "policyVersion": POLICIES.version,
            "candidateSha256": "c" * 64,
            "publicArtifactSha256": public_hash,
            "licenses": {"data": "CC-BY-4.0", "code": "Apache-2.0"},
            "artifacts": entries,
            "layers": {
                "visibleTranscript": {
                    "status": "included",
                    "ref": self.transcript_ref,
                },
                "publicDeliberation": {
                    "status": "included",
                    "ref": self.deliberation_ref,
                },
                "providerExposedReasoning": {
                    "status": "not-provided",
                    "ref": None,
                    "providerFormat": None,
                    "approvalReceipt": None,
                },
            },
            "provenance": provenance(),
            "governance": governance(public_hash),
            "withdrawal": {"policy": "append-only-tombstone"},
        }

    def publish(
        self,
        *,
        artifact_path: str = (
            "datasets/d01-civilization-ledger/releases/release-001/verifier.json"
        ),
        artifact_data: bytes = b'{"verified":true}\n',
        role: str = "verifier",
        media_type: str = "application/json",
        mutate: Optional[Callable[[dict[str, Any]], None]] = None,
    ):
        self.write_bytes(artifact_path, artifact_data)
        manifest = self.manifest_for([(artifact_path, role, media_type)])
        if mutate:
            mutate(manifest)
        self.write_json(MANIFEST_PATH, manifest)
        report = self.validate(
            [Change("A", artifact_path), Change("A", MANIFEST_PATH)]
        )
        return report, manifest

    def codes(self, report) -> set[str]:
        return {item.code for item in report.findings}


class PublicationTests(CandidateFixture):
    def test_valid_publication_passes(self) -> None:
        report, _ = self.publish()
        self.assertTrue(report.ok, report.as_dict())

    def test_generator_sources_do_not_require_publication_manifest(self) -> None:
        paths = [
            "datasets/d01-civilization-ledger/config.json",
            "datasets/d01-civilization-ledger/reasoning.json",
            "worldpacks/projections/d01/recipe.json",
        ]
        for path in paths:
            self.write_json(path, {"fixture": True})
        report = self.validate([Change("M", path) for path in paths])
        self.assertTrue(report.ok, report.as_dict())

    def test_catalog_pointer_remains_a_publication_candidate(self) -> None:
        path = "catalog/latest.json"
        self.write_json(path, {"release": "release-001"})
        report = self.validate([Change("M", path)])
        self.assertIn("PUBLICATION_MANIFEST_REQUIRED", self.codes(report))

    def test_missing_manifest_fails_closed(self) -> None:
        path = "objects/verifier/sha256/aa/artifact.json"
        self.write_bytes(path, b'{"verified":true}\n')
        report = self.validate([Change("A", path)])
        self.assertIn("PUBLICATION_MANIFEST_REQUIRED", self.codes(report))

    def test_external_source_is_rejected(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            manifest["provenance"]["rightsBasis"] = "external"

        report, _ = self.publish(mutate=mutate)
        self.assertIn("SOURCE_RIGHTS_BASIS", self.codes(report))

    def test_missing_explicit_rights_statement_is_rejected(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            manifest["provenance"].pop("rightsStatement")

        report, _ = self.publish(mutate=mutate)
        self.assertIn("RIGHTS_STATEMENT_TEXT", self.codes(report))

    def test_wrong_license_metadata_is_rejected(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            manifest["licenses"]["data"] = "proprietary"

        report, _ = self.publish(mutate=mutate)
        self.assertIn("LICENSE_METADATA", self.codes(report))

    def test_visible_transcript_and_deliberation_are_required(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            manifest["layers"]["visibleTranscript"]["ref"] = None
            manifest["layers"]["publicDeliberation"]["status"] = "omitted"

        report, _ = self.publish(mutate=mutate)
        self.assertIn("REASONING_LAYER_REQUIRED", self.codes(report))

    def test_reasoning_layer_references_must_resolve(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            manifest["layers"]["visibleTranscript"]["ref"] = "sha256:" + ("9" * 64)

        report, _ = self.publish(mutate=mutate)
        self.assertIn("REASONING_LAYER_UNRESOLVED", self.codes(report))

    def test_visible_transcript_jsonl_is_not_treated_as_record_shard(self) -> None:
        data = b'{"event":"visible-output","sequence":0}\n'
        path = self.object_path("transcripts", data, "jsonl")
        reference = "sha256:" + hashlib.sha256(data).hexdigest()

        def mutate(manifest: dict[str, Any]) -> None:
            manifest["layers"]["visibleTranscript"]["ref"] = reference

        report, _ = self.publish(
            artifact_path=path,
            artifact_data=data,
            role="visible-transcript",
            media_type="application/x-ndjson",
            mutate=mutate,
        )
        self.assertTrue(report.ok, report.as_dict())

    def test_provider_reasoning_without_receipt_is_rejected(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            manifest["layers"]["providerExposedReasoning"] = {
                "status": "approved-public",
                "ref": self.provider_ref,
                "providerFormat": "provider-visible-v1",
                "approvalReceipt": None,
            }

        report, _ = self.publish(mutate=mutate)
        self.assertIn("REVIEW_RECEIPT_REQUIRED", self.codes(report))

    def test_approved_provider_reasoning_passes(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            receipt = copy.deepcopy(manifest["governance"]["reviewReceipt"])
            receipt["termsVerified"] = True
            receipt["redistributionPermitted"] = True
            manifest["layers"]["providerExposedReasoning"] = {
                "status": "approved-public",
                "ref": self.provider_ref,
                "providerFormat": "provider-visible-v1",
                "approvalReceipt": receipt,
            }

        report, _ = self.publish(mutate=mutate)
        self.assertTrue(report.ok, report.as_dict())

    def test_provider_terms_and_redistribution_must_be_verified(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            receipt = copy.deepcopy(manifest["governance"]["reviewReceipt"])
            receipt["termsVerified"] = False
            receipt["redistributionPermitted"] = False
            manifest["layers"]["providerExposedReasoning"] = {
                "status": "approved-public",
                "ref": "sha256:" + ("3" * 64),
                "providerFormat": "provider-visible-v1",
                "approvalReceipt": receipt,
            }

        report, _ = self.publish(mutate=mutate)
        self.assertTrue(
            {"PROVIDER_TERMS", "PROVIDER_REDISTRIBUTION"} <= self.codes(report)
        )

    def test_provider_reasoning_artifact_cannot_be_smuggled(self) -> None:
        data = b'{"providerVisible":"candidate"}\n'
        path = self.object_path("reasoning", data, "json")
        report, _ = self.publish(
            artifact_path=path,
            artifact_data=data,
            role="provider-reasoning",
        )
        self.assertIn("PROVIDER_REASONING_UNAPPROVED", self.codes(report))

    def test_stale_or_mismatched_receipt_is_rejected(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            receipt = manifest["governance"]["reviewReceipt"]
            receipt["policyVersion"] = "0.0.1"
            receipt["publicArtifactSha256"] = "f" * 64

        report, _ = self.publish(mutate=mutate)
        self.assertTrue(
            {"REVIEW_RECEIPT_POLICY", "REVIEW_RECEIPT_PUBLIC"}
            <= self.codes(report)
        )

    def test_superseded_receipt_is_rejected(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            manifest["governance"]["reviewReceipt"]["superseded"] = True

        report, _ = self.publish(mutate=mutate)
        self.assertIn("REVIEW_RECEIPT_SUPERSEDED", self.codes(report))

    def test_unapproved_reviewer_cannot_authorize_publication(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            manifest["governance"]["reviewReceipt"]["reviewer"] = "self-reviewer"

        report, _ = self.publish(mutate=mutate)
        self.assertIn("REVIEW_RECEIPT_REVIEWER", self.codes(report))

    def test_artifact_hash_and_coverage_are_enforced(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            manifest["artifacts"][0]["sha256"] = "e" * 64

        report, _ = self.publish(mutate=mutate)
        self.assertIn("ARTIFACT_HASH", self.codes(report))

    def test_object_path_must_match_content_hash(self) -> None:
        data = b'{"providerVisible":"candidate"}\n'
        report, _ = self.publish(
            artifact_path="objects/reasoning/sha256/00/not-content-addressed.json",
            artifact_data=data,
            role="provider-reasoning",
        )
        self.assertIn("ARTIFACT_CONTENT_ADDRESS", self.codes(report))

    def test_quality_thresholds_are_enforced(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            manifest["governance"]["quality"]["metrics"]["verifierPassRate"] = 0.99
            manifest["governance"]["quality"]["metrics"]["duplicateRate"] = 0.02

        report, _ = self.publish(mutate=mutate)
        self.assertTrue(
            {"QUALITY_MINIMUM", "QUALITY_MAXIMUM"} <= self.codes(report)
        )

    def test_contamination_and_public_exposure_labels_are_required(self) -> None:
        def mutate(manifest: dict[str, Any]) -> None:
            manifest["governance"]["contamination"]["label"] = "clean"
            manifest["governance"]["publicExposure"]["label"] = "private"

        report, _ = self.publish(mutate=mutate)
        self.assertTrue(
            {"CONTAMINATION_LABEL", "PUBLIC_EXPOSURE_LABEL"}
            <= self.codes(report)
        )

    def test_forbidden_hidden_reasoning_field_is_rejected(self) -> None:
        report, _ = self.publish(artifact_data=b'{"internalReasoning":"omitted"}\n')
        self.assertIn("FIELD_FORBIDDEN", self.codes(report))

    def test_policy_and_publication_cannot_be_mixed(self) -> None:
        artifact = "objects/verifier/sha256/aa/artifact.json"
        self.write_bytes(artifact, b'{"verified":true}\n')
        manifest = self.manifest_for([(artifact, "verifier", "application/json")])
        self.write_json(MANIFEST_PATH, manifest)
        self.write_json("policies/new-policy.json", {"policyVersion": "1.0.0"})
        report = self.validate(
            [
                Change("A", artifact),
                Change("A", MANIFEST_PATH),
                Change("A", "policies/new-policy.json"),
            ]
        )
        self.assertIn("POLICY_PUBLICATION_MIXED", self.codes(report))

    def test_more_than_five_publication_files_is_rejected(self) -> None:
        artifacts: list[tuple[str, str, str]] = []
        changes: list[Change] = []
        for index in range(5):
            path = f"objects/verifier/sha256/{index:02d}/artifact.json"
            self.write_bytes(path, b'{"verified":true}\n')
            artifacts.append((path, "verifier", "application/json"))
            changes.append(Change("A", path))
        self.write_json(MANIFEST_PATH, self.manifest_for(artifacts))
        changes.append(Change("A", MANIFEST_PATH))
        report = self.validate(changes)
        self.assertIn("PUBLICATION_FILE_LIMIT", self.codes(report))

    def test_existing_release_cannot_be_modified_or_deleted(self) -> None:
        path = "objects/records/sha256/aa/existing.json"
        self.write_bytes(path, b'{"record":"existing"}\n')
        modified = self.validate([Change("M", path)])
        deleted = self.validate([Change("D", path)])
        self.assertIn("RELEASE_IMMUTABLE", self.codes(modified))
        self.assertTrue(
            {"RELEASE_IMMUTABLE", "PUBLICATION_DELETE"} <= self.codes(deleted)
        )

    def test_byte_limits_are_enforced(self) -> None:
        path = "notes/oversized.txt"
        hard_limit = POLICIES.publication["limits"]["fileHardBytes"]
        self.write_bytes(path, b"x" * (hard_limit + 1))
        report = self.validate([Change("A", path)])
        self.assertIn("FILE_SIZE_LIMIT", self.codes(report))

    def test_jsonl_line_limit_is_enforced(self) -> None:
        path = "objects/records/sha256/aa/oversized.jsonl"
        line_limit = POLICIES.publication["limits"]["jsonlLineHardBytes"]
        self.write_bytes(path, b'"' + (b"x" * line_limit) + b'"\n')
        report = self.validate([Change("A", path)])
        self.assertIn("JSONL_LINE_LIMIT", self.codes(report))

    def test_pull_request_diff_limit_is_enforced(self) -> None:
        report = self.validate(
            [],
            diff_bytes=POLICIES.publication["limits"]["pullRequestDiffHardBytes"] + 1,
        )
        self.assertIn("PR_DIFF_LIMIT", self.codes(report))

    def test_duplicate_json_keys_and_nonfinite_numbers_are_rejected(self) -> None:
        duplicate = "notes/duplicate.json"
        nonfinite = "notes/nonfinite.json"
        self.write_bytes(duplicate, b'{"value":1,"value":2}\n')
        self.write_bytes(nonfinite, b'{"value":NaN}\n')
        report = self.validate([Change("A", duplicate), Change("A", nonfinite)])
        self.assertEqual(
            2,
            sum(item.code == "JSON_INVALID" for item in report.findings),
        )

    def test_deep_json_has_stable_diagnostic_at_cli_boundary(self) -> None:
        path = "notes/deep.json"
        self.write_bytes(
            path,
            ("[" * 141 + "0" + "]" * 141 + "\n").encode("ascii"),
        )

        process = subprocess.run(
            [
                sys.executable,
                "-B",
                str(ROOT / "scripts" / "governance" / "validate.py"),
                "--root",
                str(self.root),
                "--policy-root",
                str(ROOT / "policies"),
                "--changed-file",
                path,
                "--format",
                "json",
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        output = json.loads(process.stdout)
        codes = {item["code"] for item in output["findings"]}

        self.assertEqual(1, process.returncode, process.stderr)
        self.assertIn("JSON_DEPTH", codes)
        self.assertNotIn("VALIDATION_INTERNAL", codes)

    def test_findings_never_include_secret_value(self) -> None:
        credential = "github_" + "pat_" + ("Z" * 48)
        path = "notes/candidate.txt"
        self.write_bytes(path, credential.encode("utf-8"))
        report = self.validate([Change("A", path)])
        serialized = json.dumps(report.as_dict(), sort_keys=True)
        self.assertIn("SECRET_GITHUB_TOKEN", serialized)
        self.assertNotIn(credential, serialized)

    def test_sensitive_filename_is_rejected_and_redacted(self) -> None:
        identity = "person" + "@" + "ordinary-domain" + ".com"
        path = f"notes/{identity}.txt"
        self.write_bytes(path, b"synthetic fixture\n")
        report = self.validate([Change("A", path)])
        serialized = json.dumps(report.as_dict(), sort_keys=True)
        self.assertIn("PATH_SENSITIVE", serialized)
        self.assertIn("<redacted-path>", serialized)
        self.assertNotIn(identity, serialized)


class RecordAndCardTests(CandidateFixture):
    def valid_record(self) -> dict[str, Any]:
        payload = {"action": "move", "synthetic": True}
        return {
            "schemaVersion": "rappterverse.public-record/v1",
            "datasetId": DATASET_ID,
            "recordType": "transition",
            "recordId": "urn:rappterverse:record:sha256:" + ("d" * 64),
            "episodeId": "episode-001",
            "sequence": 0,
            "split": "train",
            "eventTime": "2026-07-12T20:00:00Z",
            "payload": payload,
            "provenance": provenance(),
            "generation": {
                "runId": "run-001",
                "threadId": "d01",
                "generatorCommit": "a" * 40,
                "seed": "seed-001",
                "model": {},
                "promptTemplate": {},
                "transcriptRef": self.transcript_ref,
                "deliberationRef": self.deliberation_ref,
                "providerReasoningRef": None,
                "tools": [],
            },
            "governance": {
                "license": "CC-BY-4.0",
                "privacy": "synthetic-nonpersonal",
                "safetyStatus": "pass",
                "safetyLabels": ["none"],
                "contamination": {"label": "deterministic-synthetic-public"},
                "publicExposure": {"label": "public-on-release"},
                "evaluationUse": "contamination-prone-not-clean-evaluation",
                "quality": {
                    "status": "pass",
                    "verifierPassed": True,
                    "score": 0.95,
                },
            },
            "integrity": {
                "payloadSha256": canonical_sha256(payload),
                "recordSha256": "d" * 64,
            },
        }

    def test_valid_public_record_passes(self) -> None:
        record = self.valid_record()
        data = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        report, _ = self.publish(
            artifact_path=self.object_path("records", data, "jsonl"),
            artifact_data=data,
            role="records",
            media_type="application/x-ndjson",
        )
        self.assertTrue(report.ok, report.as_dict())

    def test_public_record_provider_reasoning_requires_receipt(self) -> None:
        record = self.valid_record()
        record["generation"]["providerReasoningRef"] = self.provider_ref
        data = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        report, _ = self.publish(
            artifact_path=self.object_path("records", data, "jsonl"),
            artifact_data=data,
            role="records",
            media_type="application/x-ndjson",
        )
        self.assertIn("PROVIDER_REASONING_APPROVAL", self.codes(report))

    def test_payload_integrity_is_enforced(self) -> None:
        record = self.valid_record()
        record["integrity"]["payloadSha256"] = "0" * 64
        data = (json.dumps(record, separators=(",", ":")) + "\n").encode("utf-8")
        report, _ = self.publish(
            artifact_path=self.object_path("records", data, "jsonl"),
            artifact_data=data,
            role="records",
            media_type="application/x-ndjson",
        )
        self.assertIn("PAYLOAD_HASH", self.codes(report))

    def test_valid_data_card_passes(self) -> None:
        card = {
            "schema": "rappterverse.data-card/v1",
            "policyVersion": POLICIES.version,
            "datasetId": DATASET_ID,
            "title": "Synthetic test card",
            "summary": "A synthetic fixture.",
            "version": "release-001",
            "createdAt": "2026-07-12T20:00:00Z",
            "licenses": {"data": "CC-BY-4.0", "code": "Apache-2.0"},
            "sources": {
                "boundary": "synthetic-or-rappterverse-owned-only",
                "rightsBasis": "synthetic",
                "rightsStatementId": "synthetic-project-generated-v1",
                "rightsStatement": RIGHTS_TEXT,
                "lineage": provenance()["sources"],
            },
            "composition": {
                "recordCount": 1,
                "recordTypes": ["transition"],
                "splits": {"train": 1},
            },
            "reasoningLayers": {
                "visibleTranscript": "included",
                "publicDeliberation": "included",
                "providerExposedReasoning": "not-provided",
            },
            "privacyAndSafety": {
                "privacy": "synthetic-nonpersonal",
                "realPii": False,
                "secrets": False,
                "unownedContent": False,
                "safetyStatus": "pass",
                "safetyLabels": ["none"],
            },
            "contamination": {
                "label": "deterministic-synthetic-public",
                "publicExposure": "public-on-release",
                "evaluationUse": "contamination-prone-not-clean-evaluation",
            },
            "quality": quality(),
            "intendedUses": ["simulation research"],
            "outOfScopeUses": ["real-person profiling"],
            "limitations": ["synthetic data"],
            "withdrawal": {"policy": "append-only-tombstone"},
        }
        data = (json.dumps(card, indent=4) + "\n").encode("utf-8")
        report, _ = self.publish(
            artifact_path="datasets/d01-civilization-ledger/data-card.json",
            artifact_data=data,
            role="data-card",
        )
        self.assertTrue(report.ok, report.as_dict())


class WithdrawalTests(CandidateFixture):
    def valid_withdrawal(self) -> tuple[str, str]:
        target_path = "objects/records/sha256/aa/released.json"
        target_data = b'{"released":true}\n'
        self.write_bytes(target_path, target_data)
        tombstone_path = "catalog/tombstones/aa/tombstone-001.json"
        tombstone = {
            "schema": "rappterverse.withdrawal-tombstone/v1",
            "policyVersion": POLICIES.version,
            "tombstoneId": "urn:rappterverse:tombstone:sha256:" + ("a" * 64),
            "target": {
                "path": target_path,
                "sha256": hashlib.sha256(target_data).hexdigest(),
                "recordIds": [],
            },
            "status": "withdrawn",
            "reasonCode": "integrity-failure",
            "publicReason": "A verifier found an integrity mismatch.",
            "requestedAt": "2026-07-12T20:00:00Z",
            "reviewedAt": "2026-07-12T21:00:00Z",
            "reviewer": "kody-w",
            "originalRemainsAvailable": True,
            "replacement": None,
            "license": "CC-BY-4.0",
        }
        self.write_json(tombstone_path, tombstone)
        index_path = "catalog/removals.json"
        self.write_json(
            index_path,
            {
                "schema": "rappterverse.removals/v1",
                "policyVersion": POLICIES.version,
                "removals": [
                    {
                        "tombstone": tombstone_path,
                        "targetSha256": tombstone["target"]["sha256"],
                        "status": "withdrawn",
                    }
                ],
            },
        )
        return tombstone_path, index_path

    def test_valid_withdrawal_appends_tombstone(self) -> None:
        tombstone, index = self.valid_withdrawal()
        report = self.validate([Change("A", tombstone), Change("A", index)])
        self.assertTrue(report.ok, report.as_dict())

    def test_withdrawal_requires_atomic_index_update(self) -> None:
        tombstone, _ = self.valid_withdrawal()
        report = self.validate([Change("A", tombstone)])
        self.assertIn("WITHDRAWAL_ATOMIC", self.codes(report))

    def test_original_release_cannot_be_deleted_during_withdrawal(self) -> None:
        tombstone, index = self.valid_withdrawal()
        target = "objects/records/sha256/aa/released.json"
        report = self.validate(
            [Change("D", target), Change("A", tombstone), Change("A", index)]
        )
        self.assertTrue(
            {"PUBLICATION_DELETE", "RELEASE_IMMUTABLE"} <= self.codes(report)
        )

    def test_tombstone_must_preserve_original(self) -> None:
        tombstone, index = self.valid_withdrawal()
        value = json.loads((self.root / tombstone).read_text(encoding="utf-8"))
        value["originalRemainsAvailable"] = False
        self.write_json(tombstone, value)
        report = self.validate([Change("A", tombstone), Change("A", index)])
        self.assertIn("TOMBSTONE_PRESERVATION", self.codes(report))


if __name__ == "__main__":
    unittest.main()
