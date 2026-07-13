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
        self.assertIn(
            "$TRUSTED_ROOT/scripts/governance/validate_candidate_trust.py",
            workflow,
        )
        self.assertIn("tests.test_contracts_v2", workflow)
        self.assertIn("tests.test_release_trust_v2", workflow)
        self.assertIn("github.event.pull_request.base.sha", workflow)
        self.assertIn("ref: ${{ github.event.pull_request.head.sha }}", workflow)
        self.assertIn("TRUSTED_ROOT=$BASE_ROOT", workflow)
        self.assertNotIn("TRUSTED_ROOT=$CANDIDATE_ROOT", workflow)

    def test_v2_bootstrap_is_conditional_and_cannot_self_validate(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "validate-pr.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("TRUSTED_BASE_HAS_V2=true", workflow)
        self.assertIn("TRUSTED_BASE_HAS_V2=false", workflow)
        self.assertIn(
            "if: env.TRUSTED_BASE_HAS_V2 == 'true'", workflow
        )
        self.assertIn(
            "if: env.TRUSTED_BASE_HAS_V2 == 'false'", workflow
        )
        self.assertIn(
            "- name: Validate migration surface with trusted base policy",
            workflow,
        )
        self.assertIn(
            "The one-time v2 migration may not delete files", workflow
        )
        self.assertIn("scripts/contracts/*", workflow)
        self.assertIn("schemas/v2/*", workflow)
        validation_start = workflow.index(
            "- name: Validate candidate with trusted base policy"
        )
        bootstrap_start = workflow.index(
            "- name: Bootstrap v2 tests from candidate without credentials"
        )
        validation_step = workflow[validation_start:bootstrap_start]
        self.assertLess(validation_start, bootstrap_start)
        self.assertIn(
            '--policy-root "$TRUSTED_ROOT/policies"', validation_step
        )
        self.assertIn(
            "if: env.TRUSTED_BASE_HAS_V2 == 'true'", validation_step
        )
        self.assertIn(
            "if: env.TRUSTED_BASE_HAS_V2 == 'false'", validation_step
        )
        self.assertNotIn("$CANDIDATE_ROOT/policies", validation_step)
        self.assertNotIn("$CANDIDATE_ROOT/schemas", validation_step)
        self.assertIn('GITHUB_TOKEN: ""', workflow[bootstrap_start:])
        self.assertIn('GH_TOKEN: ""', workflow[bootstrap_start:])

        validator = (
            ROOT / "scripts" / "governance" / "validator.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            'else policies.root.parent / "schemas" / "v2"', validator
        )

    def test_candidate_trust_changes_get_trusted_and_sandboxed_tests(
        self,
    ) -> None:
        workflow = (ROOT / ".github" / "workflows" / "validate-pr.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn(
            "- name: Exercise candidate trust data with trusted harness",
            workflow,
        )
        self.assertIn(
            "--candidate-root \"$CANDIDATE_ROOT\"", workflow
        )
        self.assertIn(
            "--trusted-root \"$TRUSTED_ROOT\"", workflow
        )
        self.assertNotIn(
            "$CANDIDATE_ROOT/scripts/governance/validate_candidate_trust.py",
            workflow,
        )
        self.assertIn(
            "- name: Test candidate v2 code without credentials in read-only checkout",
            workflow,
        )
        self.assertGreaterEqual(workflow.count('GITHUB_TOKEN: ""'), 2)
        self.assertGreaterEqual(workflow.count('GH_TOKEN: ""'), 2)
        self.assertEqual(
            1, workflow.count('chmod -R a-w "$CANDIDATE_ROOT"')
        )
        self.assertIn('-p "test_*v2.py"', workflow)
        self.assertIn('-p "test_*v2*.py"', workflow)
        self.assertIn("policies/rights-statements-v2.json", workflow)

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
        for path in (
            "/catalog/",
            "/datasets/",
            "/objects/",
            "/releases/",
            "/worldpacks/",
            "/scripts/contracts/",
            "/schemas/v2/",
        ):
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
