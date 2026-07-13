# SPDX-License-Identifier: Apache-2.0

"""Closed trusted registry for the public-release v2 contracts."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from .canonical import CanonicalJSONV2Error, parse_json_v2

SCHEMA_BASE = "https://data.rappterverse.dev/schemas/v2/"

SCHEMA_VERSION_TO_PATH = {
    "rappterverse.public-record/v2": "records/public-record.schema.json",
    "rappterverse.visible-transcript/v2": (
        "transcripts/visible-transcript.schema.json"
    ),
    "rappterverse.public-deliberation/v2": (
        "deliberations/public-deliberation.schema.json"
    ),
    "rappterverse.provider-reasoning/v2": (
        "deliberations/provider-reasoning.schema.json"
    ),
    "rappterverse.data-card/v2": "governance/data-card.schema.json",
    "rappterverse.public-review-receipt/v2": (
        "governance/public-review-receipt.schema.json"
    ),
    "rappterverse.active-review-set/v2": (
        "governance/active-review-set.schema.json"
    ),
    "rappterverse.publication-trust-policy/v2": (
        "governance/publication-trust-policy.schema.json"
    ),
    "rappterverse.rights-statements/v2": (
        "governance/rights-statements.schema.json"
    ),
    "rappterverse.dataset-manifest/v2": (
        "manifests/dataset-manifest.schema.json"
    ),
    "rappterverse.release-manifest/v2": (
        "manifests/release-manifest.schema.json"
    ),
    "rappterverse.world-pack-source/v2": (
        "worldpacks/world-pack-source.schema.json"
    ),
    "rappterverse.projection-recipe/v2": (
        "worldpacks/projection-recipe.schema.json"
    ),
    "rappterverse.catalog-release-pointer/v2": (
        "catalog/release-pointer.schema.json"
    ),
    "rappterverse.catalog-latest-pointer/v2": (
        "catalog/latest-pointer.schema.json"
    ),
}

TRUSTED_SCHEMA_PATHS = frozenset(
    set(SCHEMA_VERSION_TO_PATH.values())
    | {
        "common/artifact-descriptor.schema.json",
        "common/digest.schema.json",
        "common/identifiers.schema.json",
        "common/json-value.schema.json",
        "manifests/shard-descriptor.schema.json",
    }
)

ARTIFACT_KIND_TO_SCHEMA_VERSION = {
    "public-record": "rappterverse.public-record/v2",
    "visible-transcript": "rappterverse.visible-transcript/v2",
    "public-deliberation": "rappterverse.public-deliberation/v2",
    "provider-reasoning": "rappterverse.provider-reasoning/v2",
    "data-card": "rappterverse.data-card/v2",
    "public-review-receipt": "rappterverse.public-review-receipt/v2",
    "active-review-set": "rappterverse.active-review-set/v2",
    "publication-trust-policy": "rappterverse.publication-trust-policy/v2",
    "rights-statements": "rappterverse.rights-statements/v2",
    "dataset-manifest": "rappterverse.dataset-manifest/v2",
    "release-manifest": "rappterverse.release-manifest/v2",
    "world-pack-source": "rappterverse.world-pack-source/v2",
    "projection-recipe": "rappterverse.projection-recipe/v2",
    "catalog-release-pointer": "rappterverse.catalog-release-pointer/v2",
    "catalog-latest-pointer": "rappterverse.catalog-latest-pointer/v2",
}

JSONL_ARTIFACT_KIND_TO_SCHEMA_VERSION = {
    "record-shard": "rappterverse.public-record/v2",
    "transcript-shard": "rappterverse.visible-transcript/v2",
    "deliberation-shard": "rappterverse.public-deliberation/v2",
    "provider-reasoning-shard": "rappterverse.provider-reasoning/v2",
}


class SchemaRegistryError(ValueError):
    """Raised when the trusted registry is missing, malformed, or incomplete."""


class TrustedSchemaRegistry:
    """Schemas loaded only from a caller-selected trusted repository tree."""

    def __init__(
        self,
        root: Path,
        schemas_by_id: Dict[str, Dict[str, Any]],
        schemas_by_version: Dict[str, Dict[str, Any]],
    ) -> None:
        self.root = root
        self.schemas_by_id = schemas_by_id
        self.schemas_by_version = schemas_by_version

    @classmethod
    def load(cls, root: Path) -> "TrustedSchemaRegistry":
        schema_root = Path(root).resolve()
        if not schema_root.is_dir() or schema_root.is_symlink():
            raise SchemaRegistryError("trusted v2 schema directory is unavailable")

        schemas_by_id: Dict[str, Dict[str, Any]] = {}
        paths: Dict[str, Path] = {}
        discovered = sorted(schema_root.rglob("*.schema.json"))
        relative_paths = {
            path.relative_to(schema_root).as_posix() for path in discovered
        }
        if relative_paths != TRUSTED_SCHEMA_PATHS:
            raise SchemaRegistryError(
                "trusted v2 schema file set does not match the closed registry"
            )
        for path in discovered:
            if path.is_symlink() or not path.is_file():
                raise SchemaRegistryError("trusted schemas must be regular files")
            try:
                value = parse_json_v2(path.read_bytes())
            except (OSError, UnicodeError, CanonicalJSONV2Error) as exc:
                raise SchemaRegistryError(
                    "trusted schema is not strict JSON: {}".format(
                        path.relative_to(schema_root).as_posix()
                    )
                ) from exc
            if not isinstance(value, dict):
                raise SchemaRegistryError("trusted schema root must be an object")
            schema_id = value.get("$id")
            if (
                not isinstance(schema_id, str)
                or not schema_id.startswith(SCHEMA_BASE)
            ):
                raise SchemaRegistryError("trusted schema has an invalid $id")
            if schema_id in schemas_by_id:
                raise SchemaRegistryError("trusted schema $id is duplicated")
            schemas_by_id[schema_id] = value
            paths[schema_id] = path

        schemas_by_version: Dict[str, Dict[str, Any]] = {}
        for schema_version, relative in sorted(SCHEMA_VERSION_TO_PATH.items()):
            expected_path = (schema_root / relative).resolve()
            try:
                expected_path.relative_to(schema_root)
            except ValueError as exc:
                raise SchemaRegistryError("schema map escapes the trusted root") from exc
            expected_id = SCHEMA_BASE + relative
            schema = schemas_by_id.get(expected_id)
            if schema is None or paths.get(expected_id) != expected_path:
                raise SchemaRegistryError(
                    "trusted schema map entry is unavailable: {}".format(
                        schema_version
                    )
                )
            const = schema.get("properties", {}).get("schemaVersion", {}).get(
                "const"
            )
            if const != schema_version:
                raise SchemaRegistryError(
                    "schemaVersion const does not match the trusted map"
                )
            schemas_by_version[schema_version] = schema

        from .validator import ContractValidator

        ContractValidator(schemas_by_id).check_trusted_schemas()
        return cls(schema_root, schemas_by_id, schemas_by_version)

    def schema_for_version(self, schema_version: str) -> Dict[str, Any]:
        try:
            return self.schemas_by_version[schema_version]
        except KeyError as exc:
            raise SchemaRegistryError(
                "schemaVersion is not in the trusted v2 registry"
            ) from exc
