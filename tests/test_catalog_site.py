#!/usr/bin/env python3

import importlib.util
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("build_site", ROOT / "scripts" / "build_site.py")
BUILD_SITE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD_SITE)


class TestCatalogSite(unittest.TestCase):
    def test_build_is_deterministic(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first_result = BUILD_SITE.build(Path(first))
            second_result = BUILD_SITE.build(Path(second))
            self.assertEqual(first_result, second_result)
            self.assertEqual(
                (Path(first) / "index.html").read_bytes(),
                (Path(second) / "index.html").read_bytes(),
            )

    def test_remote_values_are_escaped(self):
        output = BUILD_SITE.render(
            {
                "datasets": [{
                    "id": '"><script>alert(1)</script>',
                    "title": "<img src=x onerror=alert(1)>",
                }]
            },
            {"release": "<script>", "manifestSha256": '"bad"'},
        )
        self.assertNotIn("<script>alert(1)</script>", output)
        self.assertNotIn("<img src=x", output)
        self.assertIn("&lt;script&gt;", output)


if __name__ == "__main__":
    unittest.main()
