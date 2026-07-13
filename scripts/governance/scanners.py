# SPDX-License-Identifier: Apache-2.0

"""Conservative secret and personal-data scanning with redacted results."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Optional, Set, Tuple, Union


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
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_CONTENT_PATH = re.compile(
    r"^objects/[a-z0-9-]+/sha256/([0-9a-f]{2})/"
    r"([0-9a-f]{64})\.(?:json|jsonl|txt)$"
)
_FORMAL_DIGEST_CONTEXT = re.compile(
    r"^rappterverse\.[a-z0-9-]+/v2$"
)
_DESCRIPTOR_PATHS = {
    "rappterverse.dataset-manifest/v2": {
        ("dataCard",),
        ("shards", "*"),
        ("supportingArtifacts", "*"),
    },
    "rappterverse.release-manifest/v2": {
        ("previousReleasePointer",),
        ("datasets", "*", "manifest"),
        ("worldPackSources", "*"),
    },
    "rappterverse.catalog-release-pointer/v2": {
        ("activeReviewSet",),
        ("releaseManifest",),
    },
    "rappterverse.catalog-latest-pointer/v2": {("releasePointer",)},
    "rappterverse.public-review-receipt/v2": {
        ("approvalReference",),
        ("approvedArtifacts", "*"),
        ("providerRedistributionApproval", "termsReference"),
    },
    "rappterverse.provider-reasoning/v2": {
        ("source", "redistributionTermsRef"),
    },
    "rappterverse.world-pack-source/v2": {("projectionRecipe",)},
}
_RECEIPT_REF_PATHS = {
    "rappterverse.active-review-set/v2": {
        ("heads", "*"),
        ("receipts", "*"),
    },
    "rappterverse.public-review-receipt/v2": {
        ("approvalReference",),
        ("predecessor",),
    },
}
_EVIDENCE_REF_PATHS = {
    "rappterverse.public-review-receipt/v2": {
        ("checks", "*", "evidence", "*"),
    },
    "rappterverse.public-record/v2": {
        ("provenance", "sources", "*", "consentEvidence"),
        ("provenance", "sources", "*", "ownershipEvidence"),
    },
}
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


def _scan_text(text: str, *, exempt_payment_card: bool) -> list[ScanHit]:
    """Scan one string, optionally after a structural digest exemption."""

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
        if _passes_luhn(match.group(0)) and not exempt_payment_card:
            findings.append(
                _hit(text, match, "PII_PAYMENT_CARD", "payment-card number is prohibited")
            )
    for code, pattern, message in _SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(_hit(text, match, code, message))
    return sorted(set(findings))


def scan_text(text: str) -> list[ScanHit]:
    """Scan raw text without interpreting digest-looking surroundings."""

    return _scan_text(text, exempt_payment_card=False)


def scan_path(
    path: str, *, verified_content_address: bool = False
) -> list[ScanHit]:
    """Scan a path; only a verified content address may be exempt."""

    return _scan_text(
        path,
        exempt_payment_card=(
            verified_content_address
            and _content_path_digest(path) is not None
        ),
    )


def _content_path_digest(value: Any) -> Optional[str]:
    if not isinstance(value, str):
        return None
    match = _CONTENT_PATH.fullmatch(value)
    if match is None or match.group(1) != match.group(2)[:2]:
        return None
    return match.group(2)


def _is_descriptor(parent: Mapping[str, Any]) -> bool:
    return {
        "path",
        "artifactKind",
        "mediaType",
        "bytes",
        "sha256",
    } <= set(parent)


def _path_is_allowed(
    path: Tuple[Union[str, int], ...],
    patterns: Set[Tuple[str, ...]],
) -> bool:
    return any(
        len(path) == len(pattern)
        and all(
            expected == "*" or expected == actual
            for actual, expected in zip(path, pattern)
        )
        for pattern in patterns
    )


def _digest_value_is_exempt(
    key: Optional[str],
    value: str,
    parent: Optional[Mapping[str, Any]],
    root_version: Optional[str],
    path: Tuple[Union[str, int], ...],
) -> bool:
    if (
        key is None
        or parent is None
        or root_version is None
        or _FORMAL_DIGEST_CONTEXT.fullmatch(root_version) is None
    ):
        return False
    parent_path = path[:-1]
    descriptor_path = _path_is_allowed(
        parent_path, _DESCRIPTOR_PATHS.get(root_version, set())
    )
    receipt_ref_path = _path_is_allowed(
        parent_path, _RECEIPT_REF_PATHS.get(root_version, set())
    )
    evidence_ref_path = _path_is_allowed(
        parent_path, _EVIDENCE_REF_PATHS.get(root_version, set())
    )

    if key == "sha256" and _HEX_64.fullmatch(value):
        if descriptor_path and _is_descriptor(parent):
            return True
        if (
            parent_path == ("policy",)
            and
            parent.get("policyId") == "rappterverse-publication-trust"
            and parent.get("path") == "policies/publication-trust-v2.json"
        ):
            return True
        path_digest = _content_path_digest(parent.get("path"))
        if receipt_ref_path and path_digest == value:
            return True

    if key == "path" and descriptor_path and _is_descriptor(parent):
        return (
            _content_path_digest(value) == parent.get("sha256")
            and _HEX_64.fullmatch(str(parent.get("sha256"))) is not None
        )
    if key == "path" and receipt_ref_path:
        return _content_path_digest(value) == parent.get("sha256")
    if key == "reviewReceiptRef" and descriptor_path:
        return _content_path_digest(value) is not None and value.startswith(
            "objects/review-receipts/"
        )
    if (
        key == "artifactSha256"
        and evidence_ref_path
        and _HEX_64.fullmatch(value)
    ):
        return (
            isinstance(parent.get("artifactPath"), str)
            and isinstance(parent.get("summary"), str)
        )
    if key == "artifactPath" and evidence_ref_path:
        return _content_path_digest(value) == parent.get("artifactSha256")
    if (
        key == "previousReleasePointerSha256"
        and root_version == "rappterverse.catalog-release-pointer/v2"
        and path == ("previousReleasePointerSha256",)
        and _HEX_64.fullmatch(value)
    ):
        return True
    return False


JsonPath = Tuple[Union[str, int], ...]


def governed_digest_paths(value: Any) -> Set[JsonPath]:
    """Identify v2 digest locations after a semantic validator proves them."""

    if not isinstance(value, Mapping):
        return set()
    candidate = value.get("schemaVersion")
    root_version = candidate if isinstance(candidate, str) else None
    if (
        root_version is None
        or _FORMAL_DIGEST_CONTEXT.fullmatch(root_version) is None
    ):
        return set()

    verified: Set[JsonPath] = set()
    stack = [(value, (), None)]
    while stack:
        item, path, parent = stack.pop()
        key = path[-1] if path and isinstance(path[-1], str) else None
        if isinstance(item, str):
            if _digest_value_is_exempt(
                key, item, parent, root_version, path
            ):
                verified.add(path)
        elif isinstance(item, Mapping):
            stack.extend(
                (child, path + (child_key,), item)
                for child_key, child in item.items()
            )
        elif isinstance(item, (list, tuple)):
            stack.extend(
                (child, path + (index,), None)
                for index, child in enumerate(item)
            )
    return verified


def scan_json(
    value: Any,
    *,
    verified_digest_paths: Optional[Set[JsonPath]] = None,
) -> list[ScanHit]:
    """Scan parsed JSON, defaulting to no digest exemption."""

    verified = (
        set()
        if verified_digest_paths is None
        else set(verified_digest_paths)
    )
    findings: list[ScanHit] = []
    stack = [(value, ())]
    while stack:
        item, path = stack.pop()
        if isinstance(item, str):
            findings.extend(
                _scan_text(
                    item,
                    exempt_payment_card=path in verified,
                )
            )
        elif isinstance(item, Mapping):
            for child_key, child in item.items():
                if isinstance(child_key, str):
                    findings.extend(scan_text(child_key))
                stack.append((child, path + (child_key,)))
        elif isinstance(item, (list, tuple)):
            stack.extend(
                (child, path + (index,))
                for index, child in enumerate(item)
            )
    return sorted(set(findings))
