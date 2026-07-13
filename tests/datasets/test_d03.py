#!/usr/bin/env python3

import shutil
import unittest
from pathlib import Path

from generators.d03 import generate, verify


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "tests" / "datasets" / ".test-output" / "d03"


class TestD03HumanJudgmentGoldSet(unittest.TestCase):
    def setUp(self):
        shutil.rmtree(OUTPUT, ignore_errors=True)
        OUTPUT.mkdir(parents=True)

    def tearDown(self):
        shutil.rmtree(OUTPUT, ignore_errors=True)

    def test_candidates_are_blinded_and_labels_are_separate(self):
        first_candidates = OUTPUT / "first-candidates.jsonl"
        first_labels = OUTPUT / "first-labels.jsonl"
        second_candidates = OUTPUT / "second-candidates.jsonl"
        second_labels = OUTPUT / "second-labels.jsonl"
        sources = generate.synthetic_sources(3)

        candidates, labels = generate.generate(
            sources, first_candidates, first_labels
        )
        generate.generate(sources, second_candidates, second_labels)

        self.assertEqual(3, len(candidates))
        self.assertEqual(2, len(labels))
        self.assertEqual(first_candidates.read_bytes(), second_candidates.read_bytes())
        self.assertEqual(first_labels.read_bytes(), second_labels.read_bytes())
        self.assertEqual([], verify.verify(candidates, labels))
        self.assertTrue(
            all(candidate["actors"] == ["blinded-candidate"] for candidate in candidates)
        )
        self.assertTrue(all(not verify._private_paths(item) for item in candidates))
        self.assertTrue(all("agreement" in item for item in labels))
        self.assertEqual(
            {"unanimous", "consented_adjudication"},
            {item["adjudication"]["method"] for item in labels},
        )

    def test_completed_checkpoint_resumes_both_outputs(self):
        candidates_output = OUTPUT / "candidates.jsonl"
        labels_output = OUTPUT / "labels.jsonl"
        checkpoint = OUTPUT / "checkpoint.json"
        sources = generate.synthetic_sources(3)
        generate.generate(
            sources,
            candidates_output,
            labels_output,
            checkpoint=checkpoint,
        )
        before = (candidates_output.read_bytes(), labels_output.read_bytes())

        candidates, labels = generate.generate(
            sources,
            candidates_output,
            labels_output,
            checkpoint=checkpoint,
            resume=True,
        )

        self.assertEqual((3, 2), (len(candidates), len(labels)))
        self.assertEqual(
            before, (candidates_output.read_bytes(), labels_output.read_bytes())
        )

    def test_cli_smoke_mode_and_verifier(self):
        candidates = OUTPUT / "cli-candidates.jsonl"
        labels = OUTPUT / "cli-labels.jsonl"
        self.assertEqual(
            0,
            generate.main([
                "--synthetic-smoke",
                "3",
                "--candidates-output",
                str(candidates),
                "--labels-output",
                str(labels),
            ]),
        )
        self.assertEqual(
            0,
            verify.main([
                "--candidates",
                str(candidates),
                "--labels",
                str(labels),
            ]),
        )


if __name__ == "__main__":
    unittest.main()
