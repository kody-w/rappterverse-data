# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "governance"))

from scanners import scan_text  # noqa: E402


class ScannerTests(unittest.TestCase):
    def test_reserved_examples_are_allowed(self) -> None:
        text = "agent@example.invalid 192.0.2.12 198.51.100.8 203.0.113.4"
        self.assertEqual([], scan_text(text))

    def test_real_email_is_rejected_without_retaining_value(self) -> None:
        value = "person" + "@" + "ordinary-domain" + ".com"
        hits = scan_text(f"contact={value}")
        self.assertIn("PII_EMAIL", {item.code for item in hits})
        self.assertNotIn(value, repr(hits))

    def test_phone_and_government_identifier_are_rejected(self) -> None:
        phone = "212" + "-555-" + "0199"
        government_id = "123" + "-45-" + "6789"
        codes = {item.code for item in scan_text(phone + " " + government_id)}
        self.assertIn("PII_PHONE", codes)
        self.assertIn("PII_GOVERNMENT_ID", codes)

    def test_non_documentation_network_address_is_rejected(self) -> None:
        address = "8" + ".8.8.8"
        hits = scan_text(address)
        self.assertEqual(["PII_NETWORK_ADDRESS"], [item.code for item in hits])

    def test_payment_card_is_rejected(self) -> None:
        card = "4111" + " 1111" + " 1111" + " 1111"
        self.assertIn("PII_PAYMENT_CARD", {item.code for item in scan_text(card)})

    def test_secret_patterns_are_redacted(self) -> None:
        credential = "ghp_" + ("A" * 36)
        hits = scan_text(f"token={credential}")
        self.assertIn("SECRET_GITHUB_TOKEN", {item.code for item in hits})
        self.assertNotIn(credential, repr(hits))

    def test_private_key_header_is_rejected(self) -> None:
        marker = ("-" * 5) + "BEGIN PRIVATE KEY" + ("-" * 5)
        self.assertIn("SECRET_PRIVATE_KEY", {item.code for item in scan_text(marker)})

if __name__ == "__main__":
    unittest.main()
    unittest.main()
