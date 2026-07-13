#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0

"""Exercise a candidate v2 trust tree with this trusted-base harness."""

from __future__ import annotations

import argparse
import copy
import sys
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

SCRIPTS_ROOT = Path(__file__).resolve().parents[1]
if str(SCRIPTS_ROOT) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_ROOT))

from contracts.canonical import (  # noqa: E402
    CanonicalJSONV2Error,
    parse_json_v2,
)
from contracts.registry import (  # noqa: E402
    SchemaRegistryError,
    TrustedSchemaRegistry,
)
from contracts.validator import ContractValidator  # noqa: E402

try:
    from .policy import PolicyConfigurationError, PolicySet
    from .scanners import scan_json
except ImportError:
    from policy import PolicyConfigurationError, PolicySet
    from scanners import scan_json


class CandidateTrustError(ValueError):
    """Raised when candidate trust data fails a trusted contract vector."""


def _regular_file(path: Path) -> bool:
    return path.is_file() and not path.is_symlink()


def _required_relative_files(
    trusted_root: Path,
) -> Tuple[str, ...]:
    patterns = (
        "scripts/contracts/*.py",
        "templates/v2/*.json",
        "templates/v2/README.md",
        "tests/fixtures/contracts/v2/release_graph.py",
        "tests/test_*v2.py",
        "tests/governance/test_*v2*.py",
    )
    paths = {
        path.relative_to(trusted_root).as_posix()
        for pattern in patterns
        for path in trusted_root.glob(pattern)
        if path.is_file()
    }
    return tuple(sorted(paths))


def _load_golden_instances(
    trusted_root: Path,
) -> Dict[str, Dict[str, Any]]:
    fixture = (
        trusted_root
        / "tests"
        / "fixtures"
        / "contracts"
        / "v2"
        / "release-graph"
    )
    instances: Dict[str, Dict[str, Any]] = {}
    for path in sorted(fixture.rglob("*.json")):
        value = parse_json_v2(path.read_bytes())
        if isinstance(value, dict) and isinstance(
            value.get("schemaVersion"), str
        ):
            instances.setdefault(value["schemaVersion"], value)
    for path in sorted(fixture.rglob("*.jsonl")):
        data = path.read_bytes()
        if not data.endswith(b"\n"):
            raise CandidateTrustError(
                "trusted golden JSONL is not terminal-LF delimited"
            )
        for line in data[:-1].split(b"\n"):
            value = parse_json_v2(line)
            if isinstance(value, dict) and isinstance(
                value.get("schemaVersion"), str
            ):
                instances.setdefault(value["schemaVersion"], value)
    for filename in (
        "publication-trust-v2.json",
        "rights-statements-v2.json",
    ):
        value = parse_json_v2(
            (trusted_root / "policies" / filename).read_bytes()
        )
        if not isinstance(value, dict) or not isinstance(
            value.get("schemaVersion"), str
        ):
            raise CandidateTrustError(
                "trusted policy golden instance is malformed"
            )
        instances[value["schemaVersion"]] = value
    return instances


def _negative_vectors(
    value: Mapping[str, Any],
    schema: Mapping[str, Any],
    trusted_validator: ContractValidator,
) -> Iterable[Dict[str, Any]]:
    unknown = copy.deepcopy(dict(value))
    unknown["trustedHarnessUnexpectedField"] = True
    if trusted_validator.validate(unknown, dict(schema)):
        yield unknown

    for key in sorted(value):
        if key == "schemaVersion":
            continue
        missing = copy.deepcopy(dict(value))
        del missing[key]
        if trusted_validator.validate(missing, dict(schema)):
            yield missing

    wrong_version = copy.deepcopy(dict(value))
    wrong_version["schemaVersion"] = "rappterverse.invalid/v2"
    if trusted_validator.validate(wrong_version, dict(schema)):
        yield wrong_version


def validate_candidate_tree(
    candidate_root: Path,
    trusted_root: Path,
) -> Tuple[str, ...]:
    """Return deterministic, redacted errors for candidate trust data."""

    candidate = Path(candidate_root).resolve()
    trusted = Path(trusted_root).resolve()
    errors: List[str] = []
    for relative in _required_relative_files(trusted):
        if not _regular_file(candidate / relative):
            errors.append(
                "required candidate trust file is unavailable: {}".format(
                    relative
                )
            )

    try:
        candidate_registry = TrustedSchemaRegistry.load(
            candidate / "schemas" / "v2"
        )
    except (OSError, ValueError, SchemaRegistryError):
        errors.append("candidate v2 schema registry is unavailable or unsafe")
        return tuple(sorted(set(errors)))
    try:
        candidate_policies = PolicySet.load(candidate / "policies")
    except (OSError, ValueError, PolicyConfigurationError):
        errors.append("candidate v2 policy tree is unavailable or unsafe")
        return tuple(sorted(set(errors)))

    candidate_validator = ContractValidator(
        candidate_registry.schemas_by_id
    )
    trusted_registry = TrustedSchemaRegistry.load(
        trusted / "schemas" / "v2"
    )
    trusted_validator = ContractValidator(
        trusted_registry.schemas_by_id
    )
    golden = _load_golden_instances(trusted)
    if set(golden) != set(trusted_registry.schemas_by_version):
        errors.append("trusted golden vector set is incomplete")
        return tuple(sorted(set(errors)))

    for version in sorted(golden):
        value = golden[version]
        candidate_schema = candidate_registry.schema_for_version(version)
        trusted_schema = trusted_registry.schema_for_version(version)
        if candidate_validator.validate(value, candidate_schema):
            errors.append(
                "candidate schema rejects trusted golden vector: {}".format(
                    version
                )
            )
        for negative in _negative_vectors(
            value, trusted_schema, trusted_validator
        ):
            if not candidate_validator.validate(
                negative, candidate_schema
            ):
                errors.append(
                    "candidate schema accepts trusted negative vector: {}".format(
                        version
                    )
                )
                break

    for value in (
        candidate_policies.trust_document,
        candidate_policies.rights_v2_document,
    ):
        version = value.get("schemaVersion")
        try:
            schema = candidate_registry.schema_for_version(str(version))
        except (KeyError, ValueError):
            errors.append("candidate policy uses an unknown v2 schema")
            continue
        if candidate_validator.validate(value, schema):
            errors.append("candidate v2 policy violates candidate schema")

    trusted_templates = trusted / "templates" / "v2"
    candidate_templates = candidate / "templates" / "v2"
    required_templates = {
        path.relative_to(trusted_templates).as_posix()
        for path in trusted_templates.glob("*.json")
    }
    available_templates = (
        {
            path.relative_to(candidate_templates).as_posix()
            for path in candidate_templates.glob("*.json")
            if _regular_file(path)
        }
        if candidate_templates.is_dir()
        else set()
    )
    if not required_templates <= available_templates:
        errors.append("candidate v2 template set is incomplete")
    for relative in sorted(available_templates):
        path = candidate_templates / relative
        try:
            value = parse_json_v2(path.read_bytes())
        except (OSError, CanonicalJSONV2Error):
            errors.append("candidate v2 template is not strict JSON")
            continue
        if not isinstance(value, dict):
            errors.append("candidate v2 template root is not an object")
        elif scan_json(value):
            errors.append("candidate v2 template contains prohibited data")
    return tuple(sorted(set(errors)))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Validate candidate v2 schemas, policies, templates, runtime "
            "surface, and tests with trusted-base vectors."
        )
    )
    parser.add_argument("--candidate-root", required=True)
    parser.add_argument(
        "--trusted-root",
        default=str(Path(__file__).resolve().parents[2]),
    )
    return parser


def main(argv: Sequence[str] = ()) -> int:
    args = _parser().parse_args(list(argv) if argv else None)
    errors = validate_candidate_tree(
        Path(args.candidate_root),
        Path(args.trusted_root),
    )
    if errors:
        for error in errors:
            print("ERROR CANDIDATE_TRUST {}: {}".format(".", error))
        print(
            "candidate trust harness: FAIL ({} findings)".format(
                len(errors)
            )
        )
        return 1
    print("candidate trust harness: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
