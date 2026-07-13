"""Stdlib-only checks for the public JSON Schema contracts and fixtures."""

from __future__ import annotations

import json
import unittest
from pathlib import Path
from typing import Any, Iterable

from scripts.contracts.validator import ContractValidator


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas" / "v1"
FIXTURE_ROOT = ROOT / "tests" / "fixtures" / "contracts"
DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"


def load_json(path: Path) -> Any:
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


class SchemaContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.schema_paths = sorted(SCHEMA_ROOT.rglob("*.schema.json"))
        cls.schemas_by_path = {path.relative_to(ROOT).as_posix(): load_json(path) for path in cls.schema_paths}
        cls.schemas_by_id: dict[str, dict[str, Any]] = {}
        for schema in cls.schemas_by_path.values():
            schema_id = schema.get("$id")
            if schema_id in cls.schemas_by_id:
                raise AssertionError(f"duplicate $id: {schema_id}")
            cls.schemas_by_id[schema_id] = schema
        cls.validator = ContractValidator(cls.schemas_by_id)
        cls.valid_cases = load_json(FIXTURE_ROOT / "valid" / "cases.json")
        cls.invalid_cases = load_json(FIXTURE_ROOT / "invalid" / "cases.json")

    def test_all_schemas_declare_draft_and_unique_id(self) -> None:
        self.assertGreaterEqual(len(self.schema_paths), 20)
        for path, schema in self.schemas_by_path.items():
            with self.subTest(schema=path):
                self.assertEqual(schema.get("$schema"), DRAFT_2020_12)
                self.assertRegex(
                    schema.get("$id", ""),
                    r"^https://data\.rappterverse\.dev/schemas/v1/",
                )
                self.assertLessEqual(path and (ROOT / path).stat().st_size, 512000)

    def test_every_reference_resolves(self) -> None:
        for path, root_schema in self.schemas_by_path.items():
            for reference in self._references(root_schema):
                with self.subTest(schema=path, reference=reference):
                    self.validator.resolve(reference, root_schema)

    def test_object_contracts_are_closed(self) -> None:
        for path, root_schema in self.schemas_by_path.items():
            for location, node in self._nodes(root_schema):
                if node.get("type") != "object":
                    continue
                with self.subTest(schema=path, location=location):
                    self.assertIn("additionalProperties", node)
                    if path != "schemas/v1/common/json-value.schema.json":
                        self.assertFalse(node["additionalProperties"])

    def test_valid_fixtures_conform(self) -> None:
        for case in self.valid_cases:
            schema = self.schemas_by_path[case["schema"]]
            errors = self.validator.errors(case["instance"], schema)
            with self.subTest(case=case["name"]):
                self.assertEqual(errors, [], "\n".join(errors[:20]))

    def test_invalid_fixtures_are_rejected(self) -> None:
        for case in self.invalid_cases:
            schema = self.schemas_by_path[case["schema"]]
            errors = self.validator.errors(case["instance"], schema)
            with self.subTest(case=case["name"]):
                self.assertTrue(errors, "invalid fixture unexpectedly passed")

    def test_hard_limits_are_frozen(self) -> None:
        limits = load_json(ROOT / "configs" / "publication-limits-v1.json")
        self.assertEqual(limits["canonicalJsonlShard"]["hardBytes"], 1000000)
        self.assertEqual(limits["recordFragment"]["hardBytes"], 262144)
        self.assertEqual(limits["manifest"]["hardBytes"], 512000)

        fragment = self.schemas_by_path[
            "schemas/v1/common/record-fragment.schema.json"
        ]
        self.assertEqual(fragment["properties"]["utf8Bytes"]["maximum"], 262144)
        shard = self.schemas_by_path[
            "schemas/v1/manifests/shard-descriptor.schema.json"
        ]
        self.assertEqual(shard["properties"]["byteSize"]["maximum"], 1000000)
        for name in ("dataset-manifest", "release-manifest"):
            schema = self.schemas_by_path[
                f"schemas/v1/manifests/{name}.schema.json"
            ]
            self.assertEqual(schema["properties"]["manifestBytes"]["maximum"], 512000)

    def test_visible_transcript_fixture_is_complete_and_chained(self) -> None:
        transcript = self._valid_instance("visible-transcript")
        expected_kinds = {
            "system-prompt",
            "user-prompt",
            "assistant-output",
            "tool-call",
            "tool-result",
            "verifier-result",
            "final-outcome",
        }
        events = transcript["events"]
        self.assertEqual({event["kind"] for event in events}, expected_kinds)
        self.assertEqual([event["sequence"] for event in events], list(range(len(events))))
        self.assertEqual(transcript["integrity"]["eventCount"], len(events))
        self.assertEqual(
            transcript["integrity"]["firstEventSha256"], events[0]["eventSha256"]
        )
        self.assertEqual(
            transcript["integrity"]["lastEventSha256"], events[-1]["eventSha256"]
        )
        for index, event in enumerate(events):
            expected_previous = None if index == 0 else events[index - 1]["eventSha256"]
            self.assertEqual(event["previousEventSha256"], expected_previous)
            content = event.get("content") or event.get("arguments") or event.get("result")
            for fragment in content["fragments"]:
                self.assertEqual(
                    fragment["utf8Bytes"], len(fragment["data"].encode("utf-8"))
                )

    def test_release_contains_each_dataset_once(self) -> None:
        release = self._valid_instance("release-manifest")
        actual = [item["datasetId"] for item in release["datasets"]]
        expected = self.schemas_by_id[
            "https://data.rappterverse.dev/schemas/v1/common/identifiers.schema.json"
        ]["$defs"]["DatasetId"]["enum"]
        self.assertEqual(len(actual), len(set(actual)))
        self.assertEqual(set(actual), set(expected))

    def test_provider_reasoning_is_optional_and_review_gated(self) -> None:
        record = self._valid_instance("public-record")
        self.assertIsNone(record["generation"]["providerReasoningRef"])
        self.assertIsNone(record["generation"]["providerReasoningReviewRef"])

        reasoning = self._valid_instance("provider-reasoning")
        self.assertEqual(reasoning["availability"], "provider-exposed")
        self.assertEqual(reasoning["reviewGate"]["disposition"], "approve_public")
        self.assertTrue(reasoning["source"]["redistributionPermitted"])
        self.assertFalse(reasoning["integrity"]["internalReasoningRequested"])

    def test_public_prompts_define_capture_boundary(self) -> None:
        generation = (ROOT / "prompts" / "v1" / "public-generation-system.txt").read_text(
            encoding="utf-8"
        )
        deliberation = (ROOT / "prompts" / "v1" / "explicit-deliberation.txt").read_text(
            encoding="utf-8"
        )
        reasoning = (
            ROOT / "prompts" / "v1" / "provider-reasoning-handling.txt"
        ).read_text(encoding="utf-8")
        generation = " ".join(generation.split())
        for phrase in (
            "system and user prompts",
            "tool calls and arguments",
            "tool results",
            "final outcome",
        ):
            self.assertIn(phrase, generation)
        for field in (
            "evidence",
            "assumptions",
            "alternatives",
            "uncertainty",
            "critiques",
            "rejectedOptions",
            "decision",
            "expectedOutcome",
        ):
            self.assertIn(field, deliberation)
        self.assertIn("optional", reasoning)
        self.assertIn("approve_public", reasoning)
        self.assertIn("Never solicit hidden reasoning", reasoning)

    def _valid_instance(self, name: str) -> dict[str, Any]:
        return next(case["instance"] for case in self.valid_cases if case["name"] == name)

    @classmethod
    def _references(cls, node: Any) -> Iterable[str]:
        if isinstance(node, dict):
            if "$ref" in node:
                yield node["$ref"]
            for value in node.values():
                yield from cls._references(value)
        elif isinstance(node, list):
            for value in node:
                yield from cls._references(value)

    @classmethod
    def _nodes(
        cls, node: Any, location: str = "$"
    ) -> Iterable[tuple[str, dict[str, Any]]]:
        if isinstance(node, dict):
            yield location, node
            for key, value in node.items():
                yield from cls._nodes(value, f"{location}/{key}")
        elif isinstance(node, list):
            for index, value in enumerate(node):
                yield from cls._nodes(value, f"{location}/{index}")


if __name__ == "__main__":
    unittest.main()
