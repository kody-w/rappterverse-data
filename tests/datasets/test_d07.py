"""Deterministic smoke coverage for D07."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GENERATOR = ROOT / "generators" / "d07" / "generate.py"
VERIFIER = ROOT / "generators" / "d07" / "verify.py"


def _run(*args: object) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, *(str(arg) for arg in args)],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )


class TestD07(unittest.TestCase):
    def test_three_conservative_tapes_are_deterministic(self) -> None:
        with tempfile.TemporaryDirectory(prefix="d07-smoke-") as temporary:
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
                707,
            )
            _run(
                GENERATOR,
                "--output",
                second,
                "--synthetic-smoke",
                3,
                "--seed",
                707,
            )

            first_bytes = (first / "records.jsonl").read_bytes()
            self.assertEqual(first_bytes, second.read_bytes())
            records = [
                json.loads(line)
                for line in first_bytes.decode("utf-8").splitlines()
            ]
            self.assertEqual(len(records), 3)
            for record in records:
                self.assertEqual(record["schema"], "rappterverse.d07-record/v1")
                self.assertEqual(len(record["exposed_reasoning_refs"]), 3)
                self.assertTrue(record["deliberation"]["decision"])
                self.assertEqual(
                    [event["sequence"] for event in record["tape"]],
                    list(range(len(record["tape"]))),
                )
                self.assertTrue(record["oracle"]["conserved"])
                self.assertEqual(
                    record["oracle"]["initial_total"],
                    record["oracle"]["final_total"],
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
                (ROOT / "worldpacks" / "projections" / "d07" / "recipe.json").read_text()
            )
            self.assertEqual(recipe["dataset_id"], "d07")
            self.assertTrue(recipe["win_condition"]["all"])


if __name__ == "__main__":
    unittest.main()
