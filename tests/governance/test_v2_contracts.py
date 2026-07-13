# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import hashlib
import inspect
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORK = Path(os.environ.get("RV_TEST_WORKDIR", str(ROOT / ".work")))
WORK.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / "scripts" / "governance"))

from policy import PolicySet  # noqa: E402
from validator import Change, GovernanceValidator  # noqa: E402
from scripts.contracts.canonical import canonical_json_v2  # noqa: E402
from tests.fixtures.contracts.v2.release_graph import (  # noqa: E402
    build_release_graph,
)


POLICIES = PolicySet.load(ROOT / "policies")


class V2GovernanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def write(self, path: str, data: bytes) -> None:
        target = self.root / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)

    @staticmethod
    def codes(report) -> set[str]:
        return {item.code for item in report.findings}

    def build_graph(self):
        return build_release_graph(
            self.root,
            POLICIES.trust_document_bytes,
            POLICIES.rights_v2_document_bytes,
        )

    def receipt_for_dataset(self, dataset_id: str):
        for path in sorted(
            (self.root / "objects" / "review-receipts").rglob("*.json")
        ):
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("datasetId") == dataset_id:
                return path.relative_to(self.root).as_posix(), value
        self.fail("dataset receipt not found")

    def receipt_for_kind(self, artifact_kind: str):
        for path in sorted(
            (self.root / "objects" / "review-receipts").rglob("*.json")
        ):
            value = json.loads(path.read_text(encoding="utf-8"))
            if any(
                item.get("artifactKind") == artifact_kind
                for item in value.get("approvedArtifacts", [])
            ):
                return path.relative_to(self.root).as_posix(), value
        self.fail("artifact receipt not found")

    def test_prepopulated_graph_passes_one_file_activation(self) -> None:
        self.build_graph()
        changes = [Change("M", "catalog/latest.json")]

        report = GovernanceValidator(self.root, POLICIES).validate(changes)

        self.assertTrue(report.ok, report.as_dict())

    def test_trusted_base_bytes_use_resolved_git_revision(self) -> None:
        validator = GovernanceValidator(
            ROOT,
            POLICIES,
            base_revision="HEAD",
        )
        expected = subprocess.run(
            ["git", "show", "HEAD:catalog/latest.json"],
            cwd=ROOT,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        ).stdout

        self.assertEqual(
            expected,
            validator._read_base_bytes("catalog/latest.json"),
        )
        self.assertIsNone(validator._read_base_bytes("../latest.json"))
        self.assertNotIn(
            "trusted_predecessor_anchor",
            inspect.signature(GovernanceValidator).parameters,
        )

    def test_valid_five_file_leaf_batch(self) -> None:
        self.build_graph()
        receipt_path, receipt = self.receipt_for_dataset(
            "d02-counterfactual-multiverse"
        )
        changes = [
            Change("A", item["path"])
            for item in receipt["approvedArtifacts"]
        ] + [Change("A", receipt_path)]

        report = GovernanceValidator(self.root, POLICIES).validate(changes)

        self.assertEqual(5, len(changes))
        self.assertTrue(report.ok, report.as_dict())

    def test_actual_governed_luhn_digest_is_semantically_exempt(self) -> None:
        self.build_graph()
        receipt_path, receipt = self.receipt_for_dataset(
            "d09-failure-recovery"
        )
        changes = [
            Change("A", item["path"])
            for item in receipt["approvedArtifacts"]
        ] + [Change("A", receipt_path)]

        report = GovernanceValidator(self.root, POLICIES).validate(changes)

        self.assertEqual(5, len(changes))
        self.assertNotIn("PII_PAYMENT_CARD", self.codes(report))
        self.assertNotIn("PATH_SENSITIVE", self.codes(report))
        self.assertTrue(report.ok, report.as_dict())

    def test_leaf_batch_rejects_unused_claim_and_missing_closure(self) -> None:
        self.build_graph()
        receipt_path, receipt = self.receipt_for_dataset(
            "d02-counterfactual-multiverse"
        )
        changes = [
            Change("A", item["path"])
            for item in receipt["approvedArtifacts"]
            if item["artifactKind"] != "transcript-shard"
        ] + [Change("A", receipt_path)]

        report = GovernanceValidator(self.root, POLICIES).validate(changes)

        self.assertIn(
            "V2_BATCH_RECEIPT_UNUSED_CLAIM", self.codes(report)
        )
        self.assertIn("V2_TRANSCRIPT_CLOSURE", self.codes(report))

    def test_leaf_batch_rejects_duplicate_receipt_claim(self) -> None:
        self.build_graph()
        _, receipt = self.receipt_for_dataset(
            "d02-counterfactual-multiverse"
        )
        receipt["approvedArtifacts"].append(
            dict(receipt["approvedArtifacts"][0])
        )
        data = canonical_json_v2(receipt, stored=True)
        digest = hashlib.sha256(data).hexdigest()
        receipt_path = (
            "objects/review-receipts/sha256/{}/{}.json".format(
                digest[:2], digest
            )
        )
        self.write(receipt_path, data)
        changes = [
            Change("A", item["path"])
            for item in receipt["approvedArtifacts"][:-1]
        ] + [Change("A", receipt_path)]

        report = GovernanceValidator(self.root, POLICIES).validate(changes)

        self.assertIn(
            "V2_BATCH_RECEIPT_DUPLICATE_CLAIM", self.codes(report)
        )

    def test_provider_batch_requires_exact_terms_in_same_receipt(self) -> None:
        self.build_graph()
        receipt_path, receipt = self.receipt_for_kind(
            "provider-reasoning-shard"
        )
        changes = [
            Change("A", item["path"])
            for item in receipt["approvedArtifacts"]
        ] + [Change("A", receipt_path)]

        valid = GovernanceValidator(self.root, POLICIES).validate(changes)
        missing_terms = GovernanceValidator(
            self.root, POLICIES
        ).validate(
            [
                change
                for change in changes
                if not (
                    change.path.endswith(".txt")
                    and "provider-terms" in change.path
                )
            ]
        )

        self.assertTrue(valid.ok, valid.as_dict())
        self.assertIn(
            "V2_BATCH_RECEIPT_UNUSED_CLAIM",
            self.codes(missing_terms),
        )

    def test_more_than_five_files_fails_in_both_v2_modes(self) -> None:
        meta = self.build_graph()
        batch_changes = []
        for dataset_id in (
            "d02-counterfactual-multiverse",
            "d03-human-judgment",
        ):
            receipt_path, receipt = self.receipt_for_dataset(dataset_id)
            batch_changes.extend(
                Change("A", item["path"])
                for item in receipt["approvedArtifacts"]
            )
            batch_changes.append(Change("A", receipt_path))

        batch_report = GovernanceValidator(
            self.root, POLICIES
        ).validate(batch_changes)

        activation_paths = [
            "catalog/latest.json",
            meta["pointerPath"],
            meta["releasePath"],
            meta["reviewSetPath"],
            meta["releaseReceiptPath"],
            meta["pointerReceiptPath"],
        ]
        activation_report = GovernanceValidator(
            self.root, POLICIES
        ).validate([Change("A", path) for path in activation_paths])

        self.assertGreater(len(batch_changes), 5)
        self.assertIn("PUBLICATION_FILE_LIMIT", self.codes(batch_report))
        self.assertIn(
            "PUBLICATION_FILE_LIMIT", self.codes(activation_report)
        )

    def test_fixture_receipts_are_serializable_in_five_file_batches(
        self,
    ) -> None:
        self.build_graph()
        receipts = sorted(
            (self.root / "objects" / "review-receipts").rglob("*.json")
        )
        self.assertGreater(len(receipts), 10)
        for path in receipts:
            value = json.loads(path.read_text(encoding="utf-8"))
            with self.subTest(path=path):
                self.assertLessEqual(
                    len(value["approvedArtifacts"]) + 1,
                    POLICIES.publication["limits"][
                        "publicationFilesHard"
                    ],
                )

    def test_activation_rejects_unmarked_dependency_tamper(self) -> None:
        self.build_graph()
        record = next(
            (self.root / "objects" / "records").rglob("*.jsonl")
        )
        record.write_bytes(record.read_bytes().replace(b"true", b"false", 1))

        report = GovernanceValidator(self.root, POLICIES).validate(
            [Change("M", "catalog/latest.json")]
        )

        self.assertTrue(
            {"V2_DESCRIPTOR_HASH", "V2_ARTIFACT_PATH"}
            & self.codes(report)
        )

    def test_activation_rejects_payload_change(self) -> None:
        meta = self.build_graph()
        record = next(
            (self.root / "objects" / "records").rglob("*.jsonl")
        )
        record_path = record.relative_to(self.root).as_posix()

        for payload_path in (record_path, meta["releasePath"]):
            report = GovernanceValidator(self.root, POLICIES).validate(
                [
                    Change("M", "catalog/latest.json"),
                    Change("A", payload_path),
                ]
            )
            with self.subTest(payload_path=payload_path):
                self.assertIn(
                    "V2_ACTIVATION_PAYLOAD", self.codes(report)
                )

    def test_hash_mismatch_loses_digest_exemption(
        self,
    ) -> None:
        self.build_graph()
        latest_path = self.root / "catalog" / "latest.json"
        latest = json.loads(latest_path.read_text(encoding="utf-8"))
        latest["releasePointer"]["sha256"] = (
            "a" * 24 + "41111111" + "11111111" + "b" * 24
        )
        latest_path.write_bytes(canonical_json_v2(latest, stored=True))

        report = GovernanceValidator(self.root, POLICIES).validate(
            [Change("A", "catalog/latest.json")]
        )

        self.assertIn("PII_PAYMENT_CARD", self.codes(report))
        self.assertIn("V2_DESCRIPTOR_HASH", self.codes(report))

    def test_template_cannot_hide_card_in_digest_looking_text(self) -> None:
        digest = "a" * 24 + "41111111" + "11111111" + "b" * 24
        path = "templates/v2/exploit.template.json"
        self.write(
            path,
            canonical_json_v2(
                {
                    "$template": "negative regression",
                    "schemaVersion": (
                        "rappterverse.catalog-latest-pointer/v2"
                    ),
                    "sha256": digest,
                },
                stored=True,
            ),
        )

        report = GovernanceValidator(self.root, POLICIES).validate(
            [Change("A", path)]
        )

        self.assertIn("PII_PAYMENT_CARD", self.codes(report))

    def test_only_exact_negative_fixture_gets_fixture_carveout(self) -> None:
        digest = "a" * 24 + "41111111" + "11111111" + "b" * 24
        value = {"sha256": digest}
        denied_paths = (
            "tests/fixtures/contracts/v2/card.json",
            "configs/card.json",
            "docs/card.json",
        )
        for path in denied_paths:
            self.write(path, canonical_json_v2(value, stored=True))
            report = GovernanceValidator(self.root, POLICIES).validate(
                [Change("A", path)]
            )
            with self.subTest(path=path):
                self.assertIn("PII_PAYMENT_CARD", self.codes(report))

        allowed = "tests/fixtures/contracts/invalid/card.json"
        self.write(allowed, canonical_json_v2(value, stored=True))
        allowed_report = GovernanceValidator(
            self.root, POLICIES
        ).validate([Change("A", allowed)])
        self.assertTrue(allowed_report.ok, allowed_report.as_dict())

    def test_candidate_cannot_replace_the_trusted_schema_registry(self) -> None:
        fake_schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": (
                "https://data.rappterverse.dev/schemas/v2/"
                "records/public-record.schema.json"
            ),
            "type": "object",
            "additionalProperties": True,
        }
        self.write(
            "schemas/v2/records/public-record.schema.json",
            (json.dumps(fake_schema) + "\n").encode("utf-8"),
        )
        candidate = {
            "schemaVersion": "rappterverse.public-record/v2",
            "candidateAddedField": True,
        }
        self.write(
            "notes/candidate-record.json",
            canonical_json_v2(candidate, stored=True),
        )

        report = GovernanceValidator(self.root, POLICIES).validate(
            [
                Change("M", "schemas/v2/records/public-record.schema.json"),
                Change("A", "notes/candidate-record.json"),
            ]
        )

        self.assertTrue(
            {"V2_CONTRACT_ADDITIONAL_PROPERTY", "V2_CONTRACT_REQUIRED"}
            & self.codes(report)
        )

    def test_fixture_bypass_is_confined_to_exact_contract_directory(self) -> None:
        allowed = "tests/fixtures/contracts/invalid/direct-v2.json"
        allowed_release = (
            "tests/fixtures/contracts/v2/release-graph/objects/"
            "records/sha256/aa/direct-v2.json"
        )
        denied = "tests/fixtures/contracts-evil/invalid/direct-v2.json"
        value = {
            "schemaVersion": "rappterverse.public-record/v2",
            "internalReasoning": "negative fixture marker",
        }
        data = canonical_json_v2(value, stored=True)
        self.write(allowed, data)
        self.write(allowed_release, data)
        self.write(denied, data)

        allowed_report = GovernanceValidator(self.root, POLICIES).validate(
            [Change("A", allowed)]
        )
        allowed_release_report = GovernanceValidator(
            self.root, POLICIES
        ).validate([Change("A", allowed_release)])
        denied_report = GovernanceValidator(self.root, POLICIES).validate(
            [Change("A", denied)]
        )

        self.assertTrue(allowed_report.ok, allowed_report.as_dict())
        self.assertTrue(
            allowed_release_report.ok, allowed_release_report.as_dict()
        )
        self.assertFalse(denied_report.ok)
        self.assertTrue(
            {"FIELD_FORBIDDEN", "V2_CONTRACT_REQUIRED"}
            & self.codes(denied_report)
        )

    def test_new_v1_publication_is_inactive_in_production_mode(self) -> None:
        path = "objects/records/sha256/aa/historical-v1.json"
        self.write(path, b'{"schemaVersion":"rappterverse.public-record/v1"}\n')

        report = GovernanceValidator(self.root, POLICIES).validate(
            [Change("A", path)]
        )

        self.assertIn("RELEASE_CONTRACT_INACTIVE", self.codes(report))


if __name__ == "__main__":
    unittest.main()
