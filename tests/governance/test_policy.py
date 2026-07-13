# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORK = ROOT / ".work"
WORK.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / "scripts" / "governance"))

from policy import PolicyConfigurationError, PolicySet  # noqa: E402


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        shutil.copytree(ROOT / "policies", self.root / "policies")

    def load(self) -> PolicySet:
        return PolicySet.load(self.root / "policies")

    def rewrite(self, filename: str, mutate) -> None:
        path = self.root / "policies" / filename
        value = json.loads(path.read_text(encoding="utf-8"))
        mutate(value)
        path.write_text(json.dumps(value), encoding="utf-8")

    def test_repository_policy_bundle_loads(self) -> None:
        policy = self.load()
        self.assertEqual("1.0.0", policy.version)
        self.assertEqual("CC-BY-4.0", policy.publication["licenses"]["data"])

    def test_missing_policy_fails_closed(self) -> None:
        (self.root / "policies" / "reasoning-policy.json").unlink()
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_missing_v2_trust_policy_fails_closed(self) -> None:
        (self.root / "policies" / "publication-trust-v2.json").unlink()
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_missing_v2_rights_registry_fails_closed(self) -> None:
        (self.root / "policies" / "rights-statements-v2.json").unlink()
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_v2_rights_registry_pin_cannot_be_replaced(self) -> None:
        path = self.root / "policies" / "rights-statements-v2.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["statements"][0]["status"] = "revoked"
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_v2_policy_cannot_claim_signed_approvals_are_enabled(self) -> None:
        path = self.root / "policies" / "publication-trust-v2.json"
        value = json.loads(path.read_text(encoding="utf-8"))
        value["approvalMechanisms"]["signedApprovals"] = "enabled"
        path.write_text(
            json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_file_limit_cannot_be_weakened(self) -> None:
        self.rewrite(
            "publication-policy.json",
            lambda value: value["limits"].update({"fileHardBytes": 1_000_001}),
        )
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_external_rights_basis_cannot_be_added(self) -> None:
        self.rewrite(
            "source-allowlist.json",
            lambda value: value["allowedRightsBases"].update(
                {"external": {"sourceTypes": ["external-dataset"]}}
            ),
        )
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_external_repository_cannot_be_allowlisted(self) -> None:
        self.rewrite(
            "source-allowlist.json",
            lambda value: value["allowedRepositories"].append("third-party/corpus"),
        )
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_immutable_publication_surface_cannot_be_removed(self) -> None:
        self.rewrite(
            "publication-policy.json",
            lambda value: value["immutablePathPrefixes"].remove("objects/"),
        )
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_source_exemptions_cannot_be_broadened(self) -> None:
        self.rewrite(
            "publication-policy.json",
            lambda value: value["sourcePathPrefixes"].append("objects/"),
        )
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_finalized_dataset_globs_cannot_be_removed(self) -> None:
        self.rewrite(
            "publication-policy.json",
            lambda value: value["publicationPathGlobs"].remove(
                "datasets/*/publications/**"
            ),
        )
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_untrusted_reviewer_cannot_be_allowlisted(self) -> None:
        self.rewrite(
            "publication-policy.json",
            lambda value: value["approvedReviewerIds"].append("self-reviewer"),
        )
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_quality_pass_rates_cannot_be_lowered(self) -> None:
        self.rewrite(
            "quality-policy.json",
            lambda value: value["publicationThresholds"]["minimum"].update(
                {"schemaPassRate": 0.99}
            ),
        )
        with self.assertRaises(PolicyConfigurationError):
            self.load()

    def test_redaction_policy_cannot_be_disabled(self) -> None:
        self.rewrite(
            "safety-policy.json",
            lambda value: value["findingOutput"].update({"redacted": False}),
        )
        with self.assertRaises(PolicyConfigurationError):
            self.load()

if __name__ == "__main__":
    unittest.main()
    unittest.main()
