"""End-to-end and mutation tests for the v2 public release graph."""

from __future__ import annotations

import copy
import hashlib
import os
import tempfile
import unittest
from pathlib import Path
from typing import Optional

from scripts.contracts import (
    ReleaseTrustValidator,
    TrustedPredecessorAnchor,
    TrustedSchemaRegistry,
    canonical_json_v2,
    object_path_matches_sha256,
    parse_json_v2,
    review_supersession_diagnostics,
)
from tests.fixtures.contracts.v2.release_graph import (
    PREVIOUS_RELEASE_ID,
    build_release_graph,
)


ROOT = Path(__file__).resolve().parents[1]
WORK = Path(os.environ.get("RV_TEST_WORKDIR", str(ROOT / ".work")))
WORK.mkdir(exist_ok=True)
POLICY_BYTES = (ROOT / "policies" / "publication-trust-v2.json").read_bytes()
RIGHTS_BYTES = (ROOT / "policies" / "rights-statements-v2.json").read_bytes()
REGISTRY = TrustedSchemaRegistry.load(ROOT / "schemas" / "v2")
COMMITTED_FIXTURE = (
    ROOT / "tests" / "fixtures" / "contracts" / "v2" / "release-graph"
)


class ReleaseTrustV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.meta = build_release_graph(
            self.root, POLICY_BYTES, RIGHTS_BYTES
        )

    def validator(
        self,
        *,
        root: Optional[Path] = None,
        anchor: Optional[TrustedPredecessorAnchor] = None,
    ) -> ReleaseTrustValidator:
        return ReleaseTrustValidator(
            root or self.root,
            REGISTRY,
            POLICY_BYTES,
            RIGHTS_BYTES,
            trusted_predecessor_anchor=anchor,
        )

    @staticmethod
    def codes(diagnostics) -> set[str]:
        return {item.code for item in diagnostics}

    def read_json(self, relative: str):
        return parse_json_v2((self.root / relative).read_bytes())

    def write_json(self, relative: str, value) -> None:
        (self.root / relative).write_bytes(
            canonical_json_v2(value, stored=True)
        )

    def first_record(self):
        path = next((self.root / "objects" / "records").rglob("*.jsonl"))
        return path.relative_to(self.root).as_posix(), parse_json_v2(
            path.read_bytes()[:-1]
        )

    def fresh_root(self) -> Path:
        temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(temporary.cleanup)
        return Path(temporary.name)

    def build_anchored_second_release(
        self,
    ) -> tuple[
        Path,
        dict,
        TrustedPredecessorAnchor,
        dict,
    ]:
        root = self.fresh_root()
        previous_meta = build_release_graph(
            root,
            POLICY_BYTES,
            RIGHTS_BYTES,
            release_id=PREVIOUS_RELEASE_ID,
        )
        anchor = TrustedPredecessorAnchor.from_release_graph(
            root,
            REGISTRY,
            POLICY_BYTES,
            RIGHTS_BYTES,
        )
        previous = {
            "releaseId": previous_meta["releaseId"],
            "sequence": 1,
            "descriptor": previous_meta["pointerDescriptor"],
        }
        current_meta = build_release_graph(
            root,
            POLICY_BYTES,
            RIGHTS_BYTES,
            previous=previous,
        )
        return root, current_meta, anchor, previous

    def test_valid_ten_dataset_release_graph(self) -> None:
        validator = self.validator()

        diagnostics = validator.validate_release_graph(
            self.meta["latestPath"]
        )

        self.assertEqual(10, len(self.meta["datasetManifestPaths"]))
        self.assertEqual(0, len(diagnostics), diagnostics)
        self.assertGreaterEqual(
            sum(1 for path in self.root.rglob("*") if path.is_file()), 70
        )

    def test_committed_release_graph_matches_builder_and_validates(self) -> None:
        generated = {
            path.relative_to(self.root): path.read_bytes()
            for path in self.root.rglob("*")
            if path.is_file()
        }
        committed = {
            path.relative_to(COMMITTED_FIXTURE): path.read_bytes()
            for path in COMMITTED_FIXTURE.rglob("*")
            if path.is_file()
        }

        self.assertEqual(generated, committed)
        diagnostics = ReleaseTrustValidator(
            COMMITTED_FIXTURE, REGISTRY, POLICY_BYTES, RIGHTS_BYTES
        ).validate_release_graph()
        self.assertEqual((), diagnostics)

    def test_skeletal_record_is_rejected(self) -> None:
        validator = self.validator()
        data = canonical_json_v2(
            {"schemaVersion": "rappterverse.public-record/v2"},
            stored=True,
        )

        validator.validate_jsonl_bytes(
            "objects/records/fixture.jsonl", data, "record-shard"
        )

        self.assertIn("CONTRACT_REQUIRED", self.codes(validator.diagnostics))

    def test_missing_consent_evidence_is_rejected(self) -> None:
        validator = self.validator()
        _, record = self.first_record()
        record["provenance"] = {
            "rightsBasis": "rappterverse-owned",
            "rightsStatementId": "rights-consented-human-judgment-v2",
            "lineageComplete": True,
            "externalContentIncluded": False,
            "sources": [
                {
                    "sourceType": "consented-human-judgment",
                    "publicDataConsent": True,
                    "license": "CC-BY-4.0",
                    "consentedAt": "2026-07-12T20:00:00Z",
                }
            ],
        }

        validator.validate_jsonl_bytes(
            "objects/records/fixture.jsonl",
            canonical_json_v2(record, stored=True),
            "record-shard",
        )

        self.assertIn("CONTRACT_ONE_OF", self.codes(validator.diagnostics))

    def test_unknown_mismatched_and_revoked_rights_statements_fail(self) -> None:
        def unknown(kind, code, value):
            if kind == "record" and code == "d01":
                value["provenance"]["rightsStatementId"] = (
                    "rights-unknown-fixture-v2"
                )

        def mismatched(kind, code, value):
            if kind == "record" and code == "d01":
                value["provenance"]["rightsStatementId"] = (
                    "rights-rappterverse-repository-v2"
                )

        def revoked(kind, code, value):
            if kind == "record" and code == "d01":
                value["provenance"] = {
                    "rightsBasis": "rappterverse-owned",
                    "rightsStatementId": (
                        "rights-revoked-legacy-import-v2"
                    ),
                    "lineageComplete": True,
                    "externalContentIncluded": False,
                    "sources": [
                        {
                            "sourceType": "rappterverse-repository",
                            "repository": "kody-w/rappterverse-data",
                            "commit": "a" * 40,
                            "path": "datasets/d01/generator.py",
                            "blobSha256": "b" * 64,
                        }
                    ],
                }

        cases = (
            (unknown, "RIGHTS_STATEMENT_UNKNOWN"),
            (mismatched, "RIGHTS_BASIS_MISMATCH"),
            (revoked, "RIGHTS_STATEMENT_REVOKED"),
        )
        for mutate, expected in cases:
            root = self.fresh_root()
            build_release_graph(
                root,
                POLICY_BYTES,
                RIGHTS_BYTES,
                mutate_artifact=mutate,
            )
            diagnostics = self.validator(root=root).validate_release_graph()
            with self.subTest(expected=expected):
                self.assertIn(expected, self.codes(diagnostics))

    def test_registered_ownership_attestation_is_required(self) -> None:
        def remove_attestation(kind, code, value):
            if kind == "record" and code == "d01":
                value["provenance"] = {
                    "rightsBasis": "rappterverse-owned",
                    "rightsStatementId": (
                        "rights-system-controlled-agent-v2"
                    ),
                    "lineageComplete": True,
                    "externalContentIncluded": False,
                    "sources": [
                        {
                            "sourceType": "system-controlled-agent",
                            "agentId": "fixture-agent",
                        }
                    ],
                }

        root = self.fresh_root()
        build_release_graph(
            root,
            POLICY_BYTES,
            RIGHTS_BYTES,
            mutate_artifact=remove_attestation,
        )

        diagnostics = self.validator(root=root).validate_release_graph()

        self.assertIn("RIGHTS_ATTESTATION_MISSING", self.codes(diagnostics))

    def test_rehashed_transcript_run_and_episode_mismatch_fail(self) -> None:
        cases = (
            ("runId", "run-unrelated-fixture"),
            ("episodeId", "episode-unrelated-fixture"),
        )
        for field, replacement in cases:
            def mutate(kind, code, value, field=field, replacement=replacement):
                if kind == "transcript" and code == "d01":
                    value[field] = replacement

            root = self.fresh_root()
            build_release_graph(
                root,
                POLICY_BYTES,
                RIGHTS_BYTES,
                mutate_artifact=mutate,
            )
            diagnostics = self.validator(root=root).validate_release_graph()
            with self.subTest(field=field):
                self.assertIn("TRANSCRIPT_CLOSURE", self.codes(diagnostics))
                self.assertNotIn("DESCRIPTOR_HASH", self.codes(diagnostics))
                self.assertNotIn(
                    "RECEIPT_ARTIFACT_CLOSURE", self.codes(diagnostics)
                )

    def test_rehashed_cross_dataset_record_id_collision_fails(self) -> None:
        def collide(kind, code, value):
            if code == "d02" and kind in {
                "record",
                "transcript",
                "deliberation",
                "provider-reasoning",
            }:
                value["recordId"] = "record-d01-item-001"

        root = self.fresh_root()
        build_release_graph(
            root,
            POLICY_BYTES,
            RIGHTS_BYTES,
            mutate_artifact=collide,
        )

        diagnostics = self.validator(root=root).validate_release_graph()

        self.assertIn(
            "RECORD_ID_GLOBAL_DUPLICATE", self.codes(diagnostics)
        )
        self.assertNotIn("DESCRIPTOR_HASH", self.codes(diagnostics))
        self.assertNotIn(
            "RECEIPT_ARTIFACT_CLOSURE", self.codes(diagnostics)
        )

    def test_unknown_field_and_self_hash_attempt_are_rejected(self) -> None:
        _, record = self.first_record()
        for field in ("unexpected", "recordSha256"):
            validator = self.validator()
            mutated = copy.deepcopy(record)
            mutated[field] = "0" * 64
            validator.validate_jsonl_bytes(
                "objects/records/fixture.jsonl",
                canonical_json_v2(mutated, stored=True),
                "record-shard",
            )
            with self.subTest(field=field):
                self.assertIn(
                    "CONTRACT_ADDITIONAL_PROPERTY",
                    self.codes(validator.diagnostics),
                )

    def test_nan_is_rejected_before_contract_validation(self) -> None:
        validator = self.validator()

        validator.validate_jsonl_bytes(
            "objects/records/fixture.jsonl",
            b'{"schemaVersion":"rappterverse.public-record/v2","x":NaN}\n',
            "record-shard",
        )

        self.assertIn("V2_JSONL_INVALID", self.codes(validator.diagnostics))

    def test_deep_formal_json_has_stable_public_boundary_diagnostic(
        self,
    ) -> None:
        validator = self.validator()
        reproducer = ("[" * 141 + "0" + "]" * 141).encode("ascii")

        validator.validate_formal_json_bytes(
            "notes/deep.json",
            reproducer,
            expected_schema_version="rappterverse.data-card/v2",
        )

        self.assertIn("JSON_DEPTH", self.codes(validator.diagnostics))

    def test_duplicate_review_refs_are_rejected_semantically(self) -> None:
        review_set = self.read_json(self.meta["reviewSetPath"])
        review_set["receipts"].append(copy.deepcopy(review_set["receipts"][0]))
        review_set["heads"].append(copy.deepcopy(review_set["heads"][0]))
        self.write_json(self.meta["reviewSetPath"], review_set)

        diagnostics = self.validator().validate_release_graph()

        self.assertTrue(
            {"REVIEW_SET_DUPLICATE", "REVIEW_HEAD_ORDER"}
            & self.codes(diagnostics)
        )

    def test_manifest_count_and_size_closure_are_enforced(self) -> None:
        path = self.meta["datasetManifestPaths"][0]
        manifest = self.read_json(path)
        manifest["counts"]["records"] = 2
        manifest["contentBytes"] += 1
        self.write_json(path, manifest)

        diagnostics = self.validator().validate_release_graph()

        self.assertTrue(
            {"MANIFEST_COUNTS", "MANIFEST_BYTES"}
            <= self.codes(diagnostics)
        )

    def test_raw_hash_and_object_path_mismatch_are_enforced(self) -> None:
        latest = self.read_json(self.meta["latestPath"])
        latest["releasePointer"]["sha256"] = "0" * 64
        self.write_json(self.meta["latestPath"], latest)

        diagnostics = self.validator().validate_release_graph()

        self.assertIn("DESCRIPTOR_HASH", self.codes(diagnostics))

        object_path = next(
            (self.root / "objects" / "records").rglob("*.jsonl")
        )
        bad_path = object_path.with_name("0" * 64 + ".jsonl")
        object_path.rename(bad_path)
        self.assertFalse(
            object_path_matches_sha256(
                bad_path.relative_to(self.root).as_posix(),
                "1" * 64,
            )
        )

    def test_reviewed_world_source_cannot_use_an_arbitrary_mutable_path(
        self,
    ) -> None:
        root = self.fresh_root()
        build_release_graph(
            root,
            POLICY_BYTES,
            RIGHTS_BYTES,
            world_source_path="worldpacks/projections/reviewed-source.json",
        )

        diagnostics = ReleaseTrustValidator(
            root, REGISTRY, POLICY_BYTES, RIGHTS_BYTES
        ).validate_release_graph()

        self.assertIn("ARTIFACT_PATH", self.codes(diagnostics))

    def test_reachable_leaf_change_requires_every_enclosing_hash_update(
        self,
    ) -> None:
        recipe = self.read_json(self.meta["projectionRecipePath"])
        recipe["configuration"]["fixture"] = False
        recipe_data = canonical_json_v2(recipe, stored=True)
        recipe_digest = hashlib.sha256(recipe_data).hexdigest()
        recipe_path = (
            "objects/projection-recipes/sha256/{}/{}.json".format(
                recipe_digest[:2], recipe_digest
            )
        )
        (self.root / recipe_path).parent.mkdir(parents=True, exist_ok=True)
        (self.root / recipe_path).write_bytes(recipe_data)

        world = self.read_json(self.meta["worldSourcePath"])
        world["projectionRecipe"].update(
            {
                "path": recipe_path,
                "bytes": len(recipe_data),
                "sha256": recipe_digest,
            }
        )
        world_data = canonical_json_v2(world, stored=True)
        world_digest = hashlib.sha256(world_data).hexdigest()
        world_path = "objects/world-pack-sources/sha256/{}/{}.json".format(
            world_digest[:2], world_digest
        )
        (self.root / world_path).parent.mkdir(parents=True, exist_ok=True)
        (self.root / world_path).write_bytes(world_data)

        release = self.read_json(self.meta["releasePath"])
        release["worldPackSources"][0].update(
            {
                "path": world_path,
                "bytes": len(world_data),
                "sha256": world_digest,
            }
        )
        self.write_json(self.meta["releasePath"], release)

        diagnostics = self.validator().validate_release_graph()

        self.assertIn("DESCRIPTOR_HASH", self.codes(diagnostics))

    def test_valid_anchored_second_release_chain(self) -> None:
        root, _, anchor, _ = self.build_anchored_second_release()

        diagnostics = self.validator(
            root=root, anchor=anchor
        ).validate_release_graph()

        self.assertEqual((), diagnostics)

    def test_non_genesis_release_without_anchor_fails_closed(self) -> None:
        root, _, _, _ = self.build_anchored_second_release()

        diagnostics = self.validator(root=root).validate_release_graph()

        self.assertIn(
            "PREDECESSOR_ANCHOR_REQUIRED", self.codes(diagnostics)
        )

    def test_arbitrary_json_cannot_replace_anchored_predecessor(self) -> None:
        root, _, anchor, previous = self.build_anchored_second_release()
        data = canonical_json_v2({}, stored=True)
        (root / previous["descriptor"]["path"]).write_bytes(data)

        diagnostics = self.validator(
            root=root, anchor=anchor
        ).validate_release_graph()

        self.assertTrue(
            {
                "CONTRACT_REQUIRED",
                "PREDECESSOR_CLOSURE_TAMPER",
                "PREDECESSOR_POINTER_BYTES",
            }
            <= self.codes(diagnostics)
        )

    def test_unrelated_valid_predecessor_is_rejected_by_anchor(self) -> None:
        root, _, anchor, _ = self.build_anchored_second_release()
        unrelated = build_release_graph(
            root,
            POLICY_BYTES,
            RIGHTS_BYTES,
            release_id="release-2026-07-10-unrelated-fixture",
        )
        previous = {
            "releaseId": unrelated["releaseId"],
            "sequence": 1,
            "descriptor": unrelated["pointerDescriptor"],
        }
        build_release_graph(
            root,
            POLICY_BYTES,
            RIGHTS_BYTES,
            previous=previous,
        )

        diagnostics = self.validator(
            root=root, anchor=anchor
        ).validate_release_graph()

        self.assertTrue(
            {
                "PREDECESSOR_ANCHOR_MISMATCH",
                "PREDECESSOR_ANCHOR_ID",
            }
            <= self.codes(diagnostics)
        )

    def test_anchor_rejects_wrong_id_sequence_and_hash(self) -> None:
        mutations = (
            (
                "id",
                lambda previous: previous.update(
                    {
                        "releaseId": (
                            "release-2026-07-10-unrelated-fixture"
                        )
                    }
                ),
                "PREDECESSOR_ANCHOR_ID",
            ),
            (
                "sequence",
                lambda previous: previous.update({"sequence": 2}),
                "RELEASE_FORK",
            ),
            (
                "hash",
                lambda previous: previous["descriptor"].update(
                    {"sha256": "d" * 64}
                ),
                "PREDECESSOR_ANCHOR_MISMATCH",
            ),
        )
        for name, mutate, expected in mutations:
            root, _, anchor, trusted_previous = (
                self.build_anchored_second_release()
            )
            previous = copy.deepcopy(trusted_previous)
            mutate(previous)
            build_release_graph(
                root,
                POLICY_BYTES,
                RIGHTS_BYTES,
                previous=previous,
            )
            diagnostics = self.validator(
                root=root, anchor=anchor
            ).validate_release_graph()
            with self.subTest(name=name):
                self.assertIn(expected, self.codes(diagnostics))

    def test_anchor_rejects_fork_and_rollback(self) -> None:
        root, _, anchor, previous = self.build_anchored_second_release()
        fork = copy.deepcopy(previous)
        fork["sequence"] = anchor.sequence + 1
        build_release_graph(
            root,
            POLICY_BYTES,
            RIGHTS_BYTES,
            previous=fork,
        )
        self.assertIn(
            "RELEASE_FORK",
            self.codes(
                self.validator(
                    root=root, anchor=anchor
                ).validate_release_graph()
            ),
        )

        build_release_graph(
            root,
            POLICY_BYTES,
            RIGHTS_BYTES,
        )
        self.assertIn(
            "RELEASE_ROLLBACK",
            self.codes(
                self.validator(
                    root=root, anchor=anchor
                ).validate_release_graph()
            ),
        )

    def test_receipt_artifact_closure_rejects_extra_claim(self) -> None:
        validator = self.validator()
        original = validator._load_receipt

        def mutate_receipt(path, expected_sha256=None):
            receipt = original(path, expected_sha256)
            if receipt is not None and receipt.get("scope") == "dataset-manifests":
                receipt = copy.deepcopy(receipt)
                receipt["approvedArtifacts"].append(
                    copy.deepcopy(receipt["approvedArtifacts"][0])
                )
                validator._receipts[path] = receipt
            return receipt

        validator._load_receipt = mutate_receipt
        diagnostics = validator.validate_release_graph()

        self.assertIn("RECEIPT_ARTIFACT_CLOSURE", self.codes(diagnostics))

    def test_fake_provider_approval_is_rejected_semantically(self) -> None:
        validator = self.validator()
        original = validator._load_receipt

        def remove_provider_approval(path, expected_sha256=None):
            receipt = original(path, expected_sha256)
            if receipt is not None and any(
                item.get("artifactKind") == "provider-reasoning-shard"
                for item in receipt.get("approvedArtifacts", [])
            ):
                receipt = copy.deepcopy(receipt)
                receipt["providerRedistributionApproval"] = None
                validator._receipts[path] = receipt
            return receipt

        validator._load_receipt = remove_provider_approval
        diagnostics = validator.validate_release_graph()

        self.assertIn("PROVIDER_APPROVAL", self.codes(diagnostics))

    def test_catalog_pointer_release_equality_is_enforced(self) -> None:
        pointer = self.read_json(self.meta["pointerPath"])
        pointer["totals"]["records"] += 1
        self.write_json(self.meta["pointerPath"], pointer)

        diagnostics = self.validator().validate_release_graph()

        self.assertIn("CATALOG_RELEASE_MISMATCH", self.codes(diagnostics))

    def test_supersession_fork_cycle_stale_and_reject_are_rejected(self) -> None:
        approve = {"disposition": "approve_public", "predecessor": None}
        reject = {"disposition": "reject", "predecessor": None}

        fork = {
            "a": approve,
            "b": {
                "disposition": "approve_public",
                "predecessor": {"path": "a", "sha256": "0" * 64},
            },
            "c": {
                "disposition": "approve_public",
                "predecessor": {"path": "a", "sha256": "1" * 64},
            },
        }
        self.assertIn(
            "REVIEW_FORK",
            self.codes(
                review_supersession_diagnostics(
                    fork, {"b", "c"}, {"b", "c"}
                )
            ),
        )

        cycle = {
            "a": {
                "disposition": "approve_public",
                "predecessor": {"path": "b", "sha256": "0" * 64},
            },
            "b": {
                "disposition": "approve_public",
                "predecessor": {"path": "a", "sha256": "1" * 64},
            },
        }
        self.assertIn(
            "REVIEW_CYCLE",
            self.codes(review_supersession_diagnostics(cycle, set(), set())),
        )

        chain = {
            "a": approve,
            "b": {
                "disposition": "approve_public",
                "predecessor": {"path": "a", "sha256": "0" * 64},
            },
        }
        self.assertIn(
            "REVIEW_SET_STALE",
            self.codes(
                review_supersession_diagnostics(chain, {"b"}, {"a"})
            ),
        )
        self.assertIn(
            "REVIEW_HEAD_REJECT",
            self.codes(
                review_supersession_diagnostics(
                    {"a": reject}, {"a"}, {"a"}
                )
            ),
        )


if __name__ == "__main__":
    unittest.main()
