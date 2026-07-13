# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


class RepositoryControlTests(unittest.TestCase):
    def test_workflow_is_read_only_and_uses_base_validator(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "validate-pr.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("pull_request:", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertNotIn("pull-requests: write", workflow)
        self.assertIn("contents: read", workflow)
        self.assertEqual(2, workflow.count("persist-credentials: false"))
        self.assertIn("$TRUSTED_ROOT/scripts/governance/validate.py", workflow)
        self.assertIn("github.event.pull_request.base.sha", workflow)

    def test_ruleset_requires_review_and_governance(self) -> None:
        value = json.loads(
            (ROOT / ".github" / "rulesets" / "main.desired.json").read_text(
                encoding="utf-8"
            )
        )
        rules = value["ruleset"]["rules"]
        types = {item["type"] for item in rules}
        self.assertTrue(
            {"deletion", "non_fast_forward", "pull_request", "required_status_checks"}
            <= types
        )
        pull_request = next(item for item in rules if item["type"] == "pull_request")
        self.assertTrue(pull_request["parameters"]["require_code_owner_review"])
        status = next(item for item in rules if item["type"] == "required_status_checks")
        self.assertEqual(
            "governance / validate",
            status["parameters"]["required_status_checks"][0]["context"],
        )
        self.assertEqual([], value["ruleset"]["bypass_actors"])

    def test_codeowners_covers_publication_paths(self) -> None:
        owners = (ROOT / ".github" / "CODEOWNERS").read_text(encoding="utf-8")
        for path in ("/catalog/", "/datasets/", "/objects/", "/releases/", "/worldpacks/"):
            self.assertIn(f"{path} @kody-w", owners)

    def test_json_templates_are_well_formed(self) -> None:
        templates = sorted((ROOT / "templates").rglob("*.json"))
        self.assertGreaterEqual(len(templates), 4)
        for path in templates:
            with self.subTest(path=path):
                self.assertIsInstance(
                    json.loads(path.read_text(encoding="utf-8")), dict
                )


if __name__ == "__main__":
    unittest.main()
