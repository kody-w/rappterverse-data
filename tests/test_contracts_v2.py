"""Production contract-registry and canonical JSON v2 tests."""

from __future__ import annotations

import copy
import hashlib
import json
import unittest
from pathlib import Path

from scripts.contracts import (
    ARTIFACT_KIND_TO_SCHEMA_VERSION,
    MAX_JSON_NESTING_DEPTH,
    CanonicalJSONV2Error,
    CanonicalJSONV2DepthError,
    ContractValidator,
    SCHEMA_VERSION_TO_PATH,
    TrustedSchemaRegistry,
    canonical_json_v2,
    parse_json_v2,
)
from scripts.contracts.registry import JSONL_ARTIFACT_KIND_TO_SCHEMA_VERSION
from scripts.contracts.validator import ContractSchemaError


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_ROOT = ROOT / "schemas" / "v2"
FIXTURES = ROOT / "tests" / "fixtures" / "contracts" / "v2"


class ContractV2Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.registry = TrustedSchemaRegistry.load(SCHEMA_ROOT)
        cls.validator = ContractValidator(cls.registry.schemas_by_id)

    def test_registry_is_closed_and_complete(self) -> None:
        self.assertEqual(20, len(self.registry.schemas_by_id))
        self.assertEqual(
            set(SCHEMA_VERSION_TO_PATH),
            set(self.registry.schemas_by_version),
        )
        self.assertEqual(
            set(ARTIFACT_KIND_TO_SCHEMA_VERSION.values()),
            set(SCHEMA_VERSION_TO_PATH),
        )
        self.assertEqual(
            {
                "rappterverse.public-record/v2",
                "rappterverse.visible-transcript/v2",
                "rappterverse.public-deliberation/v2",
                "rappterverse.provider-reasoning/v2",
            },
            set(JSONL_ARTIFACT_KIND_TO_SCHEMA_VERSION.values()),
        )

    def test_trusted_schemas_reject_unknown_keywords_and_refs(self) -> None:
        schema = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://data.rappterverse.dev/schemas/v2/test.schema.json",
            "type": "object",
            "additionalProperties": False,
            "mysteryKeyword": True,
        }
        with self.assertRaises(ContractSchemaError):
            ContractValidator({schema["$id"]: schema}).check_trusted_schemas()

        schema.pop("mysteryKeyword")
        schema["$ref"] = "missing.schema.json"
        with self.assertRaises(ContractSchemaError):
            ContractValidator({schema["$id"]: schema}).check_trusted_schemas()

    def test_every_object_contract_is_closed(self) -> None:
        for schema_id, schema in self.registry.schemas_by_id.items():
            for location, node in self._nodes(schema):
                if node.get("type") != "object":
                    continue
                if (
                    schema_id.endswith("/common/json-value.schema.json")
                    and location.endswith("/JsonObject")
                ):
                    self.assertIsInstance(node["additionalProperties"], dict)
                else:
                    self.assertIs(
                        node.get("additionalProperties"),
                        False,
                        "{} {}".format(schema_id, location),
                    )

    def test_leaf_contracts_have_no_self_hash_or_receipt(self) -> None:
        versions = (
            "rappterverse.public-record/v2",
            "rappterverse.visible-transcript/v2",
            "rappterverse.public-deliberation/v2",
            "rappterverse.provider-reasoning/v2",
            "rappterverse.data-card/v2",
            "rappterverse.public-review-receipt/v2",
            "rappterverse.active-review-set/v2",
            "rappterverse.publication-trust-policy/v2",
            "rappterverse.rights-statements/v2",
            "rappterverse.world-pack-source/v2",
            "rappterverse.projection-recipe/v2",
            "rappterverse.dataset-manifest/v2",
            "rappterverse.release-manifest/v2",
            "rappterverse.catalog-release-pointer/v2",
            "rappterverse.catalog-latest-pointer/v2",
        )
        forbidden = {
            "sha256",
            "recordSha256",
            "transcriptSha256",
            "deliberationSha256",
            "reasoningSha256",
            "cardSha256",
            "manifestSha256",
            "sourceSha256",
            "receiptSha256",
        }
        for version in versions:
            properties = self.registry.schema_for_version(version)["properties"]
            with self.subTest(version=version):
                self.assertFalse(forbidden & set(properties))

    def test_policy_bundle_is_canonical_and_contract_valid(self) -> None:
        data = (ROOT / "policies" / "publication-trust-v2.json").read_bytes()
        value = parse_json_v2(data)
        self.assertEqual(data, canonical_json_v2(value, stored=True))
        self.assertEqual(
            [],
            self.validator.errors(
                value,
                self.registry.schema_for_version(value["schemaVersion"]),
            ),
        )
        self.assertEqual(
            ["kody-w"],
            [
                item["reviewerId"]
                for item in value["reviewerRoster"]["reviewers"]
            ],
        )
        self.assertEqual("not-enabled", value["approvalMechanisms"]["signedApprovals"])
        self.assertEqual(5, value["limits"]["publicationFilesHard"])
        self.assertEqual(
            900000, value["limits"]["pullRequestDiffHardBytes"]
        )
        rights_data = (
            ROOT / "policies" / "rights-statements-v2.json"
        ).read_bytes()
        self.assertEqual(
            value["rightsRegistry"]["sha256"],
            hashlib.sha256(rights_data).hexdigest(),
        )
        keys = {
            key.lower()
            for _, node in self._nodes(value)
            for key in node
        }
        self.assertFalse(
            {"privatekey", "publickey", "token", "credential"} & keys
        )

    def test_receipt_contract_allows_only_a_future_approval_reference(self) -> None:
        schema = self.registry.schema_for_version(
            "rappterverse.public-review-receipt/v2"
        )
        branches = schema["properties"]["approvalReference"]["anyOf"]

        self.assertEqual({"type": "null"}, branches[0])
        self.assertEqual(
            "#/$defs/FutureApprovalReference", branches[1]["$ref"]
        )

    def test_golden_canonical_vectors(self) -> None:
        vectors = json.loads(
            (FIXTURES / "canonical-golden.json").read_text(encoding="utf-8")
        )
        for vector in vectors:
            with self.subTest(vector=vector["name"]):
                self.assertEqual(
                    vector["canonical"].encode("utf-8"),
                    canonical_json_v2(vector["value"]),
                )
                self.assertEqual(
                    vector["stored"].encode("utf-8"),
                    canonical_json_v2(vector["value"], stored=True),
                )

    def test_canonical_parser_rejects_duplicates_floats_and_collisions(self) -> None:
        invalid = (
            b'{"a":1,"a":2}',
            b'{"a":NaN}',
            b'{"a":Infinity}',
            b'{"a":1.5}',
            '{"é":1,"e\u0301":2}',
        )
        for value in invalid:
            with self.subTest(value=value):
                with self.assertRaises(CanonicalJSONV2Error):
                    parse_json_v2(value)
        with self.assertRaises(CanonicalJSONV2Error):
            canonical_json_v2({"nested": [1.0]})

        schema = self.registry.schema_for_version(
            "rappterverse.publication-trust-policy/v2"
        )
        for value in (b'{"a":1,"a":2}', b'{"a":NaN}', b'{"a":Infinity}'):
            with self.subTest(contract_bytes=value):
                self.assertEqual(
                    "JSON_PARSE",
                    self.validator.validate_bytes(value, schema)[0].code,
                )

    def test_json_nesting_limit_is_deterministic_and_schema_recursion_works(
        self,
    ) -> None:
        def nested(depth):
            value = 0
            for _ in range(depth):
                value = [value]
            return value

        at_limit = nested(MAX_JSON_NESTING_DEPTH)
        encoded = canonical_json_v2(at_limit)
        self.assertEqual(at_limit, parse_json_v2(encoded))
        json_value_schema = self.registry.schemas_by_id[
            "https://data.rappterverse.dev/schemas/v2/common/json-value.schema.json"
        ]
        self.assertEqual((), self.validator.validate(at_limit, json_value_schema))

        over_limit = nested(MAX_JSON_NESTING_DEPTH + 1)
        with self.assertRaises(CanonicalJSONV2DepthError):
            canonical_json_v2(over_limit)
        self.assertEqual(
            "JSON_DEPTH",
            self.validator.validate(over_limit, json_value_schema)[0].code,
        )

        reproducer = ("[" * 141 + "0" + "]" * 141).encode("ascii")
        with self.assertRaises(CanonicalJSONV2DepthError):
            parse_json_v2(reproducer)
        self.assertEqual(
            "JSON_DEPTH",
            self.validator.validate_bytes(
                reproducer, json_value_schema
            )[0].code,
        )

    def test_integer_timestamp_path_and_unknown_field_fail_closed(self) -> None:
        policy = parse_json_v2(
            (ROOT / "policies" / "publication-trust-v2.json").read_bytes()
        )
        schema = self.registry.schema_for_version(policy["schemaVersion"])

        boolean_integer = copy.deepcopy(policy)
        boolean_integer["reviewerRoster"]["minimumApprovals"] = True
        self.assertTrue(self.validator.errors(boolean_integer, schema))

        bad_time = copy.deepcopy(policy)
        bad_time["effectiveAt"] = "2026-02-30T00:00:00Z"
        self.assertTrue(self.validator.errors(bad_time, schema))

        receipt_schema = self.registry.schema_for_version(
            "rappterverse.public-review-receipt/v2"
        )
        path_schema = self.registry.schemas_by_id[
            "https://data.rappterverse.dev/schemas/v2/common/identifiers.schema.json"
        ]["$defs"]["SafePath"]
        self.assertTrue(self.validator.errors("../escape.json", path_schema))

        unknown = copy.deepcopy(policy)
        unknown["policySha256"] = "0" * 64
        errors = self.validator.errors(unknown, schema)
        self.assertTrue(any("additional property" in item for item in errors))
        self.assertIsInstance(receipt_schema, dict)

    def test_diagnostics_are_bounded_and_deterministic(self) -> None:
        policy = parse_json_v2(
            (ROOT / "policies" / "publication-trust-v2.json").read_bytes()
        )
        for index in range(100):
            policy["unknown{:03d}".format(index)] = index
        schema = self.registry.schema_for_version(policy["schemaVersion"])

        first = self.validator.validate(policy, schema)
        second = self.validator.validate(policy, schema)

        self.assertEqual(50, len(first))
        self.assertEqual(first, second)

    @classmethod
    def _nodes(cls, node, location="$"):
        if isinstance(node, dict):
            yield location, node
            for key, value in node.items():
                yield from cls._nodes(value, "{}/{}".format(location, key))
        elif isinstance(node, list):
            for index, value in enumerate(node):
                yield from cls._nodes(
                    value, "{}/{}".format(location, index)
                )


if __name__ == "__main__":
    unittest.main()
