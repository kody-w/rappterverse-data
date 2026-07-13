"""Deterministic smoke coverage for D10."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "generators" / "d10" / "generate.py"
VERIFIER = ROOT / "generators" / "d10" / "verify.py"


def _run(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(str(arg) for arg in args)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


class TestD10(unittest.TestCase):
    def test_three_software_lineages_are_deterministic_and_acyclic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="d10-smoke-") as temporary:
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
                1010,
            )
            _run(
                GENERATOR,
                "--output",
                second,
                "--synthetic-smoke",
                3,
                "--seed",
                1010,
            )

            first_bytes = (first / "records.jsonl").read_bytes()
            self.assertEqual(first_bytes, second.read_bytes())
            records = [
                json.loads(line)
                for line in first_bytes.decode("utf-8").splitlines()
            ]
            self.assertEqual(len(records), 3)
            for record in records:
                self.assertEqual(record["schema"], "rappterverse.d10-record/v1")
                self.assertEqual(len(record["exposed_reasoning_refs"]), 3)
                self.assertTrue(record["transcript"])
                order = record["oracle"]["topological_order"]
                positions = {agent_id: index for index, agent_id in enumerate(order)}
                self.assertTrue(record["oracle"]["acyclic"])
                self.assertTrue(
                    all(node["software_only"] for node in record["lineage"]["nodes"])
                )
                for edge in record["lineage"]["edges"]:
                    self.assertLess(
                        positions[edge["parent"]],
                        positions[edge["child"]],
                    )
            _run(VERIFIER, "--input", first)
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
                (ROOT / "worldpacks" / "projections" / "d10" / "recipe.json").read_text()
            )
            self.assertTrue(recipe["safety"]["fictional_software_only"])
            self.assertEqual(recipe["dataset_id"], "d10")


if __name__ == "__main__":
    unittest.main()
