from __future__ import annotations

import gzip
import hashlib
import json
import unittest
from pathlib import Path

from scripts.lake.canonical import (
    CanonicalJSONError,
    canonical_json_bytes,
    canonical_jsonl_bytes,
    canonical_loads,
    content_hash,
    content_id,
    deterministic_gzip,
)


FIXTURES = Path(__file__).parent / "fixtures" / "sharding"


class CanonicalJSONTests(unittest.TestCase):
    def test_golden_jsonl_is_compact_sorted_utf8_nfc(self) -> None:
        records = json.loads(
            (FIXTURES / "canonical-input.json").read_text(encoding="utf-8")
        )

        actual = canonical_jsonl_bytes(records)

        self.assertEqual(
            actual, (FIXTURES / "canonical-output.jsonl").read_bytes()
        )
        self.assertIn("Café".encode(), actual)
        self.assertNotIn(b"\\u", actual)

    def test_normalizes_nested_keys_and_values(self) -> None:
        decomposed = "e\u0301"
        value = {"z": [{decomposed: decomposed}], "a": 1}

        self.assertEqual(
            canonical_json_bytes(value),
            '{"a":1,"z":[{"é":"é"}]}'.encode(),
        )

    def test_rejects_non_finite_numbers_at_any_depth(self) -> None:
        for value in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(value=value):
                with self.assertRaises(CanonicalJSONError):
                    canonical_json_bytes({"nested": [value]})

    def test_rejects_keys_that_collide_after_nfc(self) -> None:
        with self.assertRaisesRegex(CanonicalJSONError, "normalize"):
            canonical_json_bytes({"é": 1, "e\u0301": 2})

    def test_loads_rejects_duplicates_and_non_json_constants(self) -> None:
        with self.assertRaisesRegex(CanonicalJSONError, "duplicate"):
            canonical_loads('{"a":1,"a":2}')
        with self.assertRaisesRegex(CanonicalJSONError, "non-finite"):
            canonical_loads('{"a":NaN}')

    def test_content_ids_and_hashes_use_canonical_bytes(self) -> None:
        first = {"name": "Cafe\u0301", "id": 7}
        equivalent = {"id": 7, "name": "Café"}
        expected_body = '{"id":7,"name":"Café"}'.encode()
        expected_stream_hash = hashlib.sha256(expected_body + b"\n").hexdigest()

        self.assertEqual(content_id(first), content_id(equivalent))
        self.assertEqual(
            content_id(first),
            "urn:rappterverse:record:"
            f"sha256:{hashlib.sha256(expected_body).hexdigest()}",
        )
        self.assertEqual(
            content_hash([first]),
            f"sha256:{expected_stream_hash}",
        )

    def test_deterministic_gzip_has_zero_mtime(self) -> None:
        payload = b"canonical raw jsonl remains the source of truth\n"

        first = deterministic_gzip(payload)
        second = deterministic_gzip(payload)

        self.assertEqual(first, second)
        self.assertEqual(first[4:8], b"\x00\x00\x00\x00")
        self.assertEqual(gzip.decompress(first), payload)


if __name__ == "__main__":
    unittest.main()
