from __future__ import annotations

import json
import shutil
import unittest
from pathlib import Path

from scripts.lake.canonical import canonical_jsonl_line, sha256_hex
from scripts.lake.sharding import (
    DEFAULT_FRAGMENT_TARGET_BYTES,
    DEFAULT_HARD_CAP_BYTES,
    DEFAULT_LINE_CAP_BYTES,
    DEFAULT_TARGET_BYTES,
    FRAGMENT_SCHEMA,
    ShardingError,
    plan_shards,
    write_shards,
)


SCRATCH = Path(__file__).parents[1] / ".work" / "test-sharding"


class ShardingTests(unittest.TestCase):
    def setUp(self) -> None:
        shutil.rmtree(SCRATCH, ignore_errors=True)
        SCRATCH.mkdir(parents=True)

    def tearDown(self) -> None:
        shutil.rmtree(SCRATCH, ignore_errors=True)

    def test_published_default_byte_limits(self) -> None:
        self.assertEqual(DEFAULT_TARGET_BYTES, 768_000)
        self.assertEqual(DEFAULT_HARD_CAP_BYTES, 1_000_000)
        self.assertEqual(DEFAULT_LINE_CAP_BYTES, 262_144)
        self.assertEqual(DEFAULT_FRAGMENT_TARGET_BYTES, 128_000)

    def test_recursive_layout_is_deterministic_and_input_order_independent(self) -> None:
        records = [
            {"id": f"record-{index:03d}", "payload": "x" * (70 + index % 11)}
            for index in range(30)
        ]
        options = {
            "target_bytes": 420,
            "hard_cap_bytes": 600,
            "line_cap_bytes": 300,
        }

        forward = plan_shards(records, **options)
        reverse = plan_shards(reversed(records), **options)

        self.assertGreater(len(forward.shards), 1)
        self.assertEqual(forward.files, reverse.files)
        self.assertTrue(
            all(shard.bytes <= options["hard_cap_bytes"] for shard in forward.shards)
        )
        self.assertTrue(
            all(
                len(line) + 1 <= options["line_cap_bytes"]
                for shard in forward.shards
                for line in shard.data[:-1].split(b"\n")
            )
        )

    def test_line_exactly_at_cap_is_not_fragmented(self) -> None:
        base = len(canonical_jsonl_line({"id": "boundary", "payload": ""}))
        payload = "x" * (DEFAULT_LINE_CAP_BYTES - base)
        record = {"id": "boundary", "payload": payload}

        plan = plan_shards([record])

        self.assertEqual(plan.manifest["canonicalBytes"], DEFAULT_LINE_CAP_BYTES)
        self.assertEqual(plan.manifest["lines"], 1)
        self.assertNotIn(FRAGMENT_SCHEMA.encode(), plan.shards[0].data)

    def test_line_one_byte_over_cap_is_hash_chained_fragments(self) -> None:
        base = len(canonical_jsonl_line({"id": "boundary", "payload": ""}))
        payload = "x" * (DEFAULT_LINE_CAP_BYTES - base + 1)
        record = {"id": "boundary", "payload": payload}

        plan = plan_shards([record])
        bodies = [
            body
            for shard in plan.shards
            for body in shard.data[:-1].split(b"\n")
        ]

        self.assertGreater(len(bodies), 1)
        self.assertEqual(plan.manifest["records"], 1)
        self.assertEqual(plan.manifest["lines"], len(bodies))
        previous = None
        for index, body in enumerate(bodies):
            self.assertLessEqual(len(body) + 1, DEFAULT_LINE_CAP_BYTES)
            fragment = json.loads(body)
            self.assertEqual(
                set(fragment),
                {
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
                },
            )
            self.assertEqual(fragment["schemaVersion"], FRAGMENT_SCHEMA)
            self.assertEqual(fragment["index"], index)
            self.assertEqual(fragment["count"], len(bodies))
            self.assertEqual(fragment["previousFragmentSha256"], previous)
            self.assertEqual(
                fragment["utf8Bytes"], len(fragment["data"].encode("utf-8"))
            )
            self.assertLessEqual(
                fragment["utf8Bytes"], DEFAULT_FRAGMENT_TARGET_BYTES
            )
            self.assertEqual(
                fragment["sha256"],
                f"sha256:{sha256_hex(fragment['data'].encode('utf-8'))}",
            )
            previous = fragment["sha256"]

    def test_singleton_may_exceed_soft_target_but_not_hard_cap(self) -> None:
        record = {"id": "singleton", "payload": "x" * 130}
        line_bytes = len(canonical_jsonl_line(record))
        self.assertGreater(line_bytes, 100)
        self.assertLessEqual(line_bytes, 220)

        plan = plan_shards(
            [record],
            target_bytes=100,
            hard_cap_bytes=220,
            line_cap_bytes=220,
        )

        self.assertEqual(len(plan.shards), 1)
        self.assertEqual(plan.shards[0].bytes, line_bytes)
        self.assertGreater(plan.shards[0].bytes, 100)

    def test_invalid_limits_and_reserved_fragment_marker_are_rejected(self) -> None:
        with self.assertRaises(ShardingError):
            plan_shards([], target_bytes=101, hard_cap_bytes=100)
        with self.assertRaises(ShardingError):
            plan_shards(
                [],
                target_bytes=1_000_001,
                hard_cap_bytes=1_000_001,
                line_cap_bytes=262_144,
            )
        with self.assertRaises(ShardingError):
            plan_shards(
                [],
                target_bytes=768_000,
                hard_cap_bytes=1_000_000,
                line_cap_bytes=262_145,
            )
        with self.assertRaises(ShardingError):
            plan_shards(
                [{"id": "x", "schemaVersion": FRAGMENT_SCHEMA}],
                target_bytes=500,
                hard_cap_bytes=600,
                line_cap_bytes=400,
            )

    def test_clean_and_resumed_writes_are_byte_equivalent(self) -> None:
        records = [
            {"id": f"{index:03d}", "payload": "data-" + "x" * (70 + index % 7)}
            for index in range(24)
        ]
        options = {
            "target_bytes": 420,
            "hard_cap_bytes": 600,
            "line_cap_bytes": 300,
        }
        clean = SCRATCH / "clean"
        resumed = SCRATCH / "resumed"
        clean_plan = write_shards(records, clean, **options)

        resumed.mkdir()
        (resumed / clean_plan.shards[0].path).write_bytes(clean_plan.shards[0].data)
        (resumed / clean_plan.shards[1].path).write_bytes(b"interrupted\n")
        (resumed / "part-99999.jsonl").write_bytes(b"stale\n")

        write_shards(records, resumed, resume=True, **options)

        clean_files = {
            path.relative_to(clean): path.read_bytes()
            for path in clean.rglob("*")
            if path.is_file()
        }
        resumed_files = {
            path.relative_to(resumed): path.read_bytes()
            for path in resumed.rglob("*")
            if path.is_file()
        }
        self.assertEqual(clean_files, resumed_files)


if __name__ == "__main__":
    unittest.main()
