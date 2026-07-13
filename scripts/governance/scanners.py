# SPDX-License-Identifier: Apache-2.0

"""Conservative secret and personal-data scanning with redacted results."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass


@dataclass(frozen=True, order=True)
class ScanHit:
    code: str
    line: int
    column: int
    message: str


_EMAIL = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"[A-Za-z0-9._%+-]+@(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}"
)
_SSN = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
_PHONE = re.compile(
    r"(?<!\d)(?:\+?1[\s.-]?)?(?:\(\d{3}\)|\d{3})"
    r"[\s.-]\d{3}[\s.-]\d{4}(?!\d)"
)
_IPV4 = re.compile(
    r"(?<![\d.])(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?![\d.])"
)
_CARD = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")

_SECRET_PATTERNS = (
    (
        "SECRET_PRIVATE_KEY",
        re.compile(r"-{5}BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-{5}"),
        "private-key material is prohibited",
    ),
    (
        "SECRET_GITHUB_TOKEN",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{40,255})\b"),
        "credential-like material is prohibited",
    ),
    (
        "SECRET_AWS_ACCESS_KEY",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
        "credential-like material is prohibited",
    ),
    (
        "SECRET_SLACK_TOKEN",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
        "credential-like material is prohibited",
    ),
    (
        "SECRET_BEARER_TOKEN",
        re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{24,}\b"),
        "credential-like material is prohibited",
    ),
    (
        "SECRET_ASSIGNED_VALUE",
        re.compile(
            r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)"
            r"\s*[:=]\s*[\"']?[A-Za-z0-9._~+/=-]{16,}"
        ),
        "credential-like material is prohibited",
    ),
)

_RESERVED_EMAIL_DOMAINS = (
    ".example",
    ".invalid",
    ".test",
    "example.com",
    "example.net",
    "example.org",
)
_DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


def _location(text: str, index: int) -> tuple[int, int]:
    line = text.count("\n", 0, index) + 1
    previous_newline = text.rfind("\n", 0, index)
    return line, index - previous_newline


def _hit(text: str, match: re.Match[str], code: str, message: str) -> ScanHit:
    line, column = _location(text, match.start())
    return ScanHit(code, line, column, message)


def _is_reserved_email(value: str) -> bool:
    domain = value.rsplit("@", 1)[-1].lower()
    return any(domain == item or domain.endswith(item) for item in _RESERVED_EMAIL_DOMAINS)


def _is_documentation_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    return any(address in network for network in _DOCUMENTATION_NETWORKS)


def _passes_luhn(value: str) -> bool:
    digits = [int(character) for character in value if character.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    total = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def scan_text(text: str) -> list[ScanHit]:
    """Return redacted findings; matched values are never retained."""

    findings: list[ScanHit] = []
    for match in _EMAIL.finditer(text):
        if not _is_reserved_email(match.group(0)):
            findings.append(
                _hit(text, match, "PII_EMAIL", "possible real email address is prohibited")
            )
    for match in _SSN.finditer(text):
        findings.append(
            _hit(text, match, "PII_GOVERNMENT_ID", "government identifier is prohibited")
        )
    for match in _PHONE.finditer(text):
        findings.append(
            _hit(text, match, "PII_PHONE", "possible real telephone number is prohibited")
        )
    for match in _IPV4.finditer(text):
        if not _is_documentation_ip(match.group(0)):
            findings.append(
                _hit(text, match, "PII_NETWORK_ADDRESS", "network address is prohibited")
            )
    for match in _CARD.finditer(text):
        if _passes_luhn(match.group(0)):
            findings.append(
                _hit(text, match, "PII_PAYMENT_CARD", "payment-card number is prohibited")
            )
    for code, pattern, message in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(_hit(text, match, code, message))
    return sorted(set(findings))
