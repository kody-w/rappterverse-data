from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from scripts.lake.canonical import canonical_jsonl_line
from scripts.lake.manifests import ManifestError, verify_manifest
from scripts.lake.sharding import plan_shards, write_shards


SCRATCH = Path(__file__).parents[1] / ".work" / "test-manifests"


class ManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        shutil.rmtree(SCRATCH, ignore_errors=True)
        SCRATCH.mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def test_verifies_shards_fragments_ranges_and_content(self) -> None:
        records = [
            {"id": "a", "payload": "small"},
            {"id": "m", "payload": "x" * 2_000},
            {"id": "z", "payload": "last"},
        ]
        plan = write_shards(
            records,
            SCRATCH,
            target_bytes=1_100,
            hard_cap_bytes=1_500,
            line_cap_bytes=512,
        )

        result = verify_manifest(SCRATCH)

        self.assertEqual(result.records, 3)
        self.assertEqual(result.lines, plan.manifest["lines"])
        self.assertEqual(result.content_hash, plan.manifest["contentHash"])
        self.assertEqual(plan.manifest["shards"][0]["minKey"], "a")
        self.assertEqual(plan.manifest["shards"][-1]["maxKey"], "z")
        self.assertTrue(
            all(
                {"bytes", "records", "sha256", "minKey", "maxKey"} <= set(shard)
                for shard in plan.manifest["shards"]
            )
        )

    def test_content_hash_is_independent_of_layout_and_fragment_boundaries(self) -> None:
        records = [
            {"id": f"{index:02d}", "payload": "x" * (300 + index * 13)}
            for index in range(8)
        ]

        narrow = plan_shards(
            records,
            target_bytes=700,
            hard_cap_bytes=1_400,
            line_cap_bytes=512,
        )
        wide = plan_shards(
            records,
            target_bytes=1_800,
            hard_cap_bytes=2_000,
            line_cap_bytes=800,
        )

        self.assertNotEqual(
            [shard.data for shard in narrow.shards],
            [shard.data for shard in wide.shards],
        )
        self.assertEqual(
            narrow.manifest["contentHash"], wide.manifest["contentHash"]
        )
        self.assertEqual(
            narrow.manifest["canonicalBytes"], wide.manifest["canonicalBytes"]
        )

    def test_public_shard_descriptor_matches_v1_contract(self) -> None:
        shard = plan_shards([{"id": "item-1", "value": 1}]).shards[0]
        receipt = "sha256:" + "8" * 64

        descriptor = shard.descriptor(
            artifact_kind="records",
            review_receipt_ref=receipt,
        )

        self.assertEqual(
            set(descriptor),
            {
                "artifactKind",
                "byteSize",
                "contentAddressed",
                "firstItemId",
                "itemCount",
                "lastItemId",
                "maxFragmentBytes",
                "mediaType",
                "path",
                "reviewReceiptRef",
                "sha256",
            },
        )
        self.assertEqual(descriptor["byteSize"], shard.bytes)
        self.assertEqual(descriptor["itemCount"], shard.records)
        self.assertEqual(descriptor["sha256"], shard.sha256)
        self.assertTrue(descriptor["contentAddressed"])
        self.assertLessEqual(descriptor["maxFragmentBytes"], 262_144)

    def test_tampered_shard_fails_verification(self) -> None:
        write_shards(
            [{"id": "a", "value": 1}, {"id": "b", "value": 2}],
            SCRATCH,
            target_bytes=100,
            hard_cap_bytes=300,
            line_cap_bytes=200,
        )
        shard = next(SCRATCH.glob("part-*.jsonl"))
        shard.write_bytes(shard.read_bytes().replace(b'"value":1', b'"value":9'))

        with self.assertRaisesRegex(ManifestError, "SHA-256"):
            verify_manifest(SCRATCH)

    def test_tampered_manifest_range_fails_verification(self) -> None:
        write_shards(
            [{"id": "a", "value": 1}, {"id": "b", "value": 2}],
            SCRATCH,
            target_bytes=100,
            hard_cap_bytes=300,
            line_cap_bytes=200,
        )
        manifest_path = SCRATCH / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest["shards"][0]["minKey"] = "not-a"
        manifest_path.write_bytes(canonical_jsonl_line(manifest))

        with self.assertRaisesRegex(ManifestError, "minKey"):
            verify_manifest(SCRATCH)

    def test_manifest_itself_must_be_canonical(self) -> None:
        write_shards([{"id": "a"}], SCRATCH)
        manifest_path = SCRATCH / "manifest.json"
        manifest = json.loads(manifest_path.read_bytes())
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        with self.assertRaisesRegex(ManifestError, "not canonical"):
            verify_manifest(SCRATCH)


if __name__ == "__main__":
    unittest.main()
