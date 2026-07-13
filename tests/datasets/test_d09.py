"""Deterministic smoke coverage for D09."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "generators" / "d09" / "generate.py"
VERIFIER = ROOT / "generators" / "d09" / "verify.py"


def _run(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(str(arg) for arg in args)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


class TestD09(unittest.TestCase):
    def test_three_in_memory_fault_records_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="d09-smoke-") as temporary:
            root = Path(temporary)
            first = root / "first"
            second = root / "second.jsonl"
            _run(
                GENERATOR,
                "--output",
                first,
                "--count",
                3,
                "--seed",
                909,
            )
            _run(
                GENERATOR,
                "--output",
                second,
                "--synthetic-smoke",
                3,
                "--seed",
                909,
            )

            first_bytes = (first / "records.jsonl").read_bytes()
            self.assertEqual(first_bytes, second.read_bytes())
            records = [
                json.loads(line)
                for line in first_bytes.decode("utf-8").splitlines()
            ]
            self.assertEqual(len(records), 3)
            self.assertTrue(
                all(
                    record["schema"] == "rappterverse.d09-record/v1"
                    and len(record["exposed_reasoning_refs"]) == 3
                    for record in records
                )
            )
            self.assertEqual(
                [record["fault_trace"]["fault_type"] for record in records],
                ["duplicate_delivery", "reordered_delivery", "dropped_ack"],
            )
            self.assertTrue(
                all(
                    record["fault_trace"]["simulation_scope"] == "in-memory-only"
                    and record["oracle"]["recovered"]
                    for record in records
                )
            )
            _run(VERIFIER, "--input", first / "records.jsonl")
            _run(VERIFIER, "--input", second)

            checkpoint = first / "checkpoint.json"
            checkpoint_state = json.loads(checkpoint.read_text())
            checkpoint_state["next_index"] = 2
            checkpoint.write_text(
                json.dumps(checkpoint_state, indent=4, sort_keys=True) + "\n"
            )
            (first / "records.jsonl").write_bytes(
                b"".join(first_bytes.splitlines(keepends=True)[:2])
            )
            _run(
                GENERATOR,
                "--output",
                first,
                "--checkpoint",
                checkpoint,
                "--resume",
            )
            self.assertEqual(first_bytes, (first / "records.jsonl").read_bytes())

            recipe = json.loads(
                (ROOT / "worldpacks" / "projections" / "d09" / "recipe.json").read_text()
            )
            self.assertFalse(recipe["safety"]["real_fault_injection"])
            self.assertEqual(recipe["dataset_id"], "d09")


if __name__ == "__main__":
    unittest.main()
