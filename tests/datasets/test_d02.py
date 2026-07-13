#!/usr/bin/env python3

import shutil
import unittest
from pathlib import Path

from generators.d02 import generate, verify


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "tests" / "datasets" / ".test-output" / "d02"


class TestD02CounterfactualMultiverse(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(OUTPUT, ignore_errors=True)
        OUTPUT.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(OUTPUT, ignore_errors=True)

    def test_three_pairs_are_deterministic_replayable_and_isolated(self):
        first = OUTPUT / "first.jsonl"
        second = OUTPUT / "second.jsonl"
        sources = generate.synthetic_sources(3)
        records = generate.generate(sources, first)
        generate.generate(sources, second)

        self.assertEqual(3, len(records))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual([], verify.verify(records))
        for record in records:
            pair = record["counterfactual_pair"]
            self.assertTrue(pair["isolated_intervention"])
            self.assertFalse(pair["control"]["intervention_applied"])
            self.assertTrue(pair["treatment"]["intervention_applied"])
            self.assertEqual(
                pair["control"]["initial_state_sha256"],
                pair["treatment"]["initial_state_sha256"],
            )
            self.assertTrue(pair["causal_contrast"])

    def test_completed_checkpoint_resumes_exact_output(self):
        output = OUTPUT / "records.jsonl"
        checkpoint = OUTPUT / "checkpoint.json"
        sources = generate.synthetic_sources(3)
        generate.generate(sources, output, checkpoint=checkpoint)
        before = output.read_bytes()

        records = generate.generate(
            sources, output, checkpoint=checkpoint, resume=True
        )

        self.assertEqual(3, len(records))
        self.assertEqual(before, output.read_bytes())

    def test_cli_smoke_mode_and_verifier(self):
        output = OUTPUT / "cli.jsonl"
        self.assertEqual(
            0,
            generate.main(["--synthetic-smoke", "3", "--output", str(output)]),
        )
        self.assertEqual(0, verify.main(["--input", str(output)]))


if __name__ == "__main__":
    unittest.main()
