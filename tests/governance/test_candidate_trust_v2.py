# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
WORK = Path(os.environ.get("RV_TEST_WORKDIR", str(ROOT / ".work")))
WORK.mkdir(exist_ok=True)
sys.path.insert(0, str(ROOT / "scripts" / "governance"))

from validate_candidate_trust import (  # noqa: E402
    _required_relative_files,
    validate_candidate_tree,
)


def _copytree_for_mutable_fixture(source: Path, target: Path) -> None:
    """Copy trusted data into a scratch fixture without inheriting read-only bits."""
    shutil.copytree(source, target)
    for path in (target, *target.rglob("*")):
        if path.is_dir():
            path.chmod(path.stat().st_mode | 0o700)
        elif path.is_file():
            path.chmod(path.stat().st_mode | 0o600)


class CandidateTrustHarnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(dir=WORK)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        for directory in ("schemas", "policies", "templates"):
            _copytree_for_mutable_fixture(
                ROOT / directory,
                self.root / directory,
            )
        for relative in _required_relative_files(ROOT):
            source = ROOT / relative
            target = self.root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            target.chmod(target.stat().st_mode | 0o600)

    def errors(self):
        return validate_candidate_tree(self.root, ROOT)

    def test_repository_candidate_tree_passes_trusted_vectors(self) -> None:
        self.assertEqual((), self.errors())

    def test_mutable_fixture_does_not_inherit_read_only_candidate_mode(self) -> None:
        readme = self.root / "templates" / "v2" / "README.md"
        readme.write_bytes(readme.read_bytes())

    def test_deleted_schema_or_registry_fails_closed(self) -> None:
        cases = (
            "schemas/v2/records/public-record.schema.json",
            "policies/rights-statements-v2.json",
        )
        for relative in cases:
            with self.subTest(relative=relative):
                backup = (self.root / relative).read_bytes()
                (self.root / relative).unlink()
                self.assertTrue(self.errors())
                (self.root / relative).parent.mkdir(
                    parents=True, exist_ok=True
                )
                (self.root / relative).write_bytes(backup)

    def test_schema_weakening_that_accepts_negative_vector_fails(self) -> None:
        path = (
            self.root
            / "schemas"
            / "v2"
            / "records"
            / "public-record.schema.json"
        )
        value = json.loads(path.read_text(encoding="utf-8"))
        value["additionalProperties"] = True
        path.write_text(
            json.dumps(value, indent=4) + "\n",
            encoding="utf-8",
        )

        errors = self.errors()

        self.assertTrue(
            any("accepts trusted negative vector" in item for item in errors),
            errors,
        )

    def test_required_candidate_runtime_and_tests_cannot_be_deleted(
        self,
    ) -> None:
        for relative in (
            "scripts/contracts/release_trust.py",
            "tests/test_release_trust_v2.py",
        ):
            with self.subTest(relative=relative):
                path = self.root / relative
                backup = path.read_bytes()
                path.unlink()
                self.assertTrue(self.errors())
                path.write_bytes(backup)


if __name__ == "__main__":
    unittest.main()
