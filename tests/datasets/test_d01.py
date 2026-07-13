#!/usr/bin/env python3

import shutil
import unittest
from pathlib import Path

from generators.d01 import generate, verify


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "tests" / "datasets" / ".test-output" / "d01"


class TestD01CivilizationLedger(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(OUTPUT, ignore_errors=True)
        OUTPUT.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(OUTPUT, ignore_errors=True)

    def test_three_smoke_records_are_deterministic_and_valid(self):
        first = OUTPUT / "first.jsonl"
        second = OUTPUT / "second.jsonl"
        sources = generate.synthetic_sources(3)
        records = generate.generate(sources, first)
        generate.generate(sources, second)

        self.assertEqual(3, len(records))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual([], verify.verify(records))
        self.assertTrue(all(record["transcript"] for record in records))
        self.assertTrue(all("deliberation" in record for record in records))
        self.assertTrue(
            all(
                record["source"]["source_type"] in generate.ALLOWED_SOURCE_TYPES
                for record in records
            )
        )
        self.assertIn("exposed_reasoning_refs", records[0])

    def test_completed_checkpoint_can_resume_without_rewriting(self):
        output = OUTPUT / "records.jsonl"
        checkpoint = OUTPUT / "checkpoint.json"
        sources = generate.synthetic_sources(3)
        generate.generate(sources, output, checkpoint=checkpoint)
        before = output.read_bytes()

        resumed = generate.generate(
            sources, output, checkpoint=checkpoint, resume=True
        )

        self.assertEqual(3, len(resumed))
        self.assertEqual(before, output.read_bytes())

    def test_cli_smoke_mode_generates_test_only_fixture(self):
        output = OUTPUT / "cli.jsonl"
        self.assertEqual(
            0,
            generate.main(["--synthetic-smoke", "3", "--output", str(output)]),
        )
        self.assertEqual(0, verify.main(["--input", str(output)]))


if __name__ == "__main__":
    unittest.main()
