#!/usr/bin/env python3

import shutil
import unittest
from pathlib import Path

from generators.d05 import generate, verify


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "tests" / "datasets" / ".test-output" / "d05"


class TestD05CompleteAgentLifetimes(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(OUTPUT, ignore_errors=True)
        OUTPUT.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(OUTPUT, ignore_errors=True)

    def test_three_complete_lifetimes_are_deterministic_and_valid(self):
        first = OUTPUT / "first.jsonl"
        second = OUTPUT / "second.jsonl"
        sources = generate.synthetic_sources(3)
        records = generate.generate(sources, first)
        generate.generate(sources, second)

        self.assertEqual(3, len(records))
        self.assertEqual(first.read_bytes(), second.read_bytes())
        self.assertEqual([], verify.verify(records))
        for record in records:
            lifetime = record["agent_lifetime"]
            self.assertTrue(lifetime["complete"])
            self.assertEqual([0, 1, 2], [tick["sequence"] for tick in lifetime["ticks"]])
            self.assertEqual(
                {"decision", "idle"}, {tick["kind"] for tick in lifetime["ticks"]}
            )
            self.assertTrue(lifetime["memories"])
            self.assertTrue(lifetime["goals"])
            self.assertTrue(lifetime["relationships"])
            self.assertEqual(
                lifetime["ticks"][-1]["state_after"],
                lifetime["terminal_event"]["final_state"],
            )

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
