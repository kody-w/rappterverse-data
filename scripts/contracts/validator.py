# SPDX-License-Identifier: Apache-2.0

"""Fail-closed stdlib JSON Schema subset for trusted v2 contracts."""

from __future__ import annotations

import math
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import PurePosixPath
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple
from urllib.parse import urldefrag, urljoin

from .canonical import (
    MAX_JSON_NESTING_DEPTH,
    CanonicalJSONV2Error,
    CanonicalJSONV2DepthError,
    canonical_json_v2,
    ensure_json_depth,
    parse_json_v2,
)

_UTC_Z = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$"
)
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")

_SUPPORTED_KEYWORDS = {
    "$defs",
    "$id",
    "$ref",
    "$schema",
    "additionalProperties",
    "allOf",
    "anyOf",
    "const",
    "description",
    "else",
    "enum",
    "format",
    "if",
    "items",
    "maxItems",
    "maxLength",
    "maxProperties",
    "maximum",
    "minItems",
    "minLength",
    "minProperties",
    "minimum",
    "not",
    "oneOf",
    "pattern",
    "properties",
    "required",
    "then",
    "title",
    "type",
    "uniqueItems",
}
_SCHEMA_MAP_KEYWORDS = {"$defs", "properties"}
_SCHEMA_LIST_KEYWORDS = {"allOf", "anyOf", "oneOf"}
_SCHEMA_SINGLE_KEYWORDS = {
    "additionalProperties",
    "else",
    "if",
    "items",
    "not",
    "then",
}
_SUPPORTED_FORMATS = {"date-time", "safe-relative-path"}
_SUPPORTED_TYPES = {
    "array",
    "boolean",
    "integer",
    "null",
    "number",
    "object",
    "string",
}


class ContractSchemaError(ValueError):
    """Raised when a trusted schema uses unsupported or unsafe constructs."""


@dataclass(frozen=True, order=True)
class ContractDiagnostic:
    """One deterministic, bounded, value-free contract diagnostic."""

    path: str
    code: str
    message: str


def _safe_relative_path(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or "\\" in value
        or _CONTROL.search(value)
        or unicodedata.normalize("NFC", value) != value
    ):
        return False
    candidate = PurePosixPath(value)
    return (
        not candidate.is_absolute()
        and str(candidate) == value
        and all(part not in {"", ".", ".."} for part in candidate.parts)
    )


def _utc_z_timestamp(value: Any) -> bool:
    if not isinstance(value, str) or _UTC_Z.fullmatch(value) is None:
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timezone.utc.utcoffset(
        parsed
    )


class ContractValidator:
    """Validate instances against the exact keyword subset used by v2."""

    def __init__(
        self, schemas: Dict[str, Dict[str, Any]], *, max_diagnostics: int = 50
    ) -> None:
        if (
            isinstance(max_diagnostics, bool)
            or not isinstance(max_diagnostics, int)
            or max_diagnostics < 1
            or max_diagnostics > 1000
        ):
            raise ValueError("max_diagnostics must be an integer from 1 to 1000")
        self.schemas = dict(schemas)
        self.max_diagnostics = max_diagnostics

    def check_trusted_schemas(self) -> None:
        """Reject unsupported keywords, malformed nodes, and unresolved refs."""

        try:
            for schema_id in sorted(self.schemas):
                schema = self.schemas[schema_id]
                if schema.get("$id") != schema_id:
                    raise ContractSchemaError("trusted schema registry key mismatch")
                ensure_json_depth(schema)
                self._check_schema_node(schema, schema, "$")
        except (CanonicalJSONV2DepthError, RecursionError) as exc:
            raise ContractSchemaError(
                "trusted schema exceeds maximum JSON nesting depth {}".format(
                    MAX_JSON_NESTING_DEPTH
                )
            ) from exc

    def _check_schema_node(
        self, node: Any, root_schema: Dict[str, Any], location: str
    ) -> None:
        if isinstance(node, bool):
            return
        if not isinstance(node, dict):
            raise ContractSchemaError(
                "{}: schema node must be an object or boolean".format(location)
            )
        unknown = set(node) - _SUPPORTED_KEYWORDS
        if unknown:
            raise ContractSchemaError(
                "{}: unsupported schema keyword {}".format(
                    location, sorted(unknown)[0]
                )
            )
        if "$ref" in node:
            if not isinstance(node["$ref"], str):
                raise ContractSchemaError("{}: $ref must be a string".format(location))
            self.resolve(node["$ref"], root_schema)
        if "type" in node:
            declared = node["type"]
            types = declared if isinstance(declared, list) else [declared]
            if (
                not types
                or any(
                    not isinstance(item, str) or item not in _SUPPORTED_TYPES
                    for item in types
                )
            ):
                raise ContractSchemaError(
                    "{}: schema type is unsupported".format(location)
                )
        if "format" in node and node["format"] not in _SUPPORTED_FORMATS:
            raise ContractSchemaError(
                "{}: schema format is unsupported".format(location)
            )
        if "pattern" in node:
            try:
                re.compile(node["pattern"])
            except (TypeError, re.error) as exc:
                raise ContractSchemaError(
                    "{}: schema pattern is invalid".format(location)
                ) from exc
        for keyword in _SCHEMA_MAP_KEYWORDS:
            if keyword not in node:
                continue
            children = node[keyword]
            if not isinstance(children, dict):
                raise ContractSchemaError(
                    "{}: {} must be an object".format(location, keyword)
                )
            for name in sorted(children):
                self._check_schema_node(
                    children[name],
                    root_schema,
                    "{}/{}/{}".format(location, keyword, name),
                )
        for keyword in _SCHEMA_LIST_KEYWORDS:
            if keyword not in node:
                continue
            children = node[keyword]
            if not isinstance(children, list) or not children:
                raise ContractSchemaError(
                    "{}: {} must be a non-empty array".format(location, keyword)
                )
            for index, child in enumerate(children):
                self._check_schema_node(
                    child,
                    root_schema,
                    "{}/{}[{}]".format(location, keyword, index),
                )
        for keyword in _SCHEMA_SINGLE_KEYWORDS:
            if keyword in node:
                self._check_schema_node(
                    node[keyword],
                    root_schema,
                    "{}/{}".format(location, keyword),
                )

    def resolve(
        self, reference: str, root_schema: Dict[str, Any]
    ) -> Tuple[Any, Dict[str, Any]]:
        base = root_schema.get("$id")
        if not isinstance(base, str):
            raise ContractSchemaError("trusted schema is missing $id")
        uri, fragment = urldefrag(urljoin(base, reference))
        document = self.schemas.get(uri)
        if document is None:
            raise ContractSchemaError("trusted schema reference is unresolved")
        target: Any = document
        if fragment:
            if not fragment.startswith("/"):
                raise ContractSchemaError("only JSON Pointer fragments are supported")
            try:
                for raw_part in fragment[1:].split("/"):
                    part = raw_part.replace("~1", "/").replace("~0", "~")
                    if isinstance(target, dict):
                        target = target[part]
                    elif isinstance(target, list):
                        target = target[int(part)]
                    else:
                        raise KeyError(part)
            except (KeyError, IndexError, ValueError) as exc:
                raise ContractSchemaError(
                    "trusted schema JSON Pointer is unresolved"
                ) from exc
        return target, document

    def validate(
        self, instance: Any, schema: Dict[str, Any]
    ) -> Tuple[ContractDiagnostic, ...]:
        diagnostics: List[ContractDiagnostic] = []
        try:
            ensure_json_depth(instance)
            self._validate(instance, schema, schema, "$", diagnostics)
        except (CanonicalJSONV2DepthError, RecursionError):
            return (
                ContractDiagnostic(
                    "$",
                    "JSON_DEPTH",
                    "JSON nesting exceeds maximum depth {}".format(
                        MAX_JSON_NESTING_DEPTH
                    ),
                ),
            )
        return tuple(sorted(set(diagnostics))[: self.max_diagnostics])

    def validate_bytes(
        self,
        data: bytes,
        schema: Dict[str, Any],
        *,
        stored: bool = False,
    ) -> Tuple[ContractDiagnostic, ...]:
        """Parse and validate strict JSON bytes without losing parser errors."""

        try:
            instance = parse_json_v2(data)
        except CanonicalJSONV2DepthError:
            return (
                ContractDiagnostic(
                    "$",
                    "JSON_DEPTH",
                    "JSON nesting exceeds maximum depth {}".format(
                        MAX_JSON_NESTING_DEPTH
                    ),
                ),
            )
        except CanonicalJSONV2Error:
            return (
                ContractDiagnostic(
                    "$",
                    "JSON_PARSE",
                    "input is not strict canonical-domain JSON",
                ),
            )
        diagnostics = list(self.validate(instance, schema))
        if stored and canonical_json_v2(instance, stored=True) != data:
            diagnostics.append(
                ContractDiagnostic(
                    "$",
                    "CANONICAL",
                    "stored JSON is not project canonical v2 with terminal LF",
                )
            )
        return tuple(sorted(set(diagnostics))[: self.max_diagnostics])

    def errors(self, instance: Any, schema: Dict[str, Any]) -> List[str]:
        """Compatibility adapter for the original test-only validator API."""

        return [
            "{}: {}".format(item.path, item.message)
            for item in self.validate(instance, schema)
        ]

    def _add(
        self,
        output: List[ContractDiagnostic],
        path: str,
        code: str,
        message: str,
    ) -> None:
        if len(output) < self.max_diagnostics:
            output.append(ContractDiagnostic(path, code, message))

    def _branch_valid(
        self,
        instance: Any,
        schema: Any,
        root_schema: Dict[str, Any],
        path: str,
    ) -> bool:
        temporary: List[ContractDiagnostic] = []
        self._validate(instance, schema, root_schema, path, temporary)
        return not temporary

    def _validate(
        self,
        instance: Any,
        schema: Any,
        root_schema: Dict[str, Any],
        path: str,
        output: List[ContractDiagnostic],
    ) -> None:
        if len(output) >= self.max_diagnostics:
            return
        if schema is True:
            return
        if schema is False:
            self._add(output, path, "FALSE_SCHEMA", "value is rejected")
            return
        if not isinstance(schema, dict):
            raise ContractSchemaError("trusted schema node is malformed")

        if "$ref" in schema:
            target, target_root = self.resolve(schema["$ref"], root_schema)
            self._validate(instance, target, target_root, path, output)

        for child in schema.get("allOf", []):
            self._validate(instance, child, root_schema, path, output)

        if "anyOf" in schema and not any(
            self._branch_valid(instance, child, root_schema, path)
            for child in schema["anyOf"]
        ):
            self._add(output, path, "ANY_OF", "value does not match any branch")

        if "oneOf" in schema:
            matches = sum(
                self._branch_valid(instance, child, root_schema, path)
                for child in schema["oneOf"]
            )
            if matches != 1:
                self._add(
                    output,
                    path,
                    "ONE_OF",
                    "value must match exactly one branch",
                )

        if "not" in schema and self._branch_valid(
            instance, schema["not"], root_schema, path
        ):
            self._add(output, path, "NOT", "value matches a forbidden branch")

        if "if" in schema:
            condition = self._branch_valid(
                instance, schema["if"], root_schema, path
            )
            branch = schema.get("then") if condition else schema.get("else")
            if branch is not None:
                self._validate(instance, branch, root_schema, path, output)

        if "const" in schema and not self._json_equal(instance, schema["const"]):
            self._add(output, path, "CONST", "value does not match the constant")
        if "enum" in schema and not any(
            self._json_equal(instance, choice) for choice in schema["enum"]
        ):
            self._add(output, path, "ENUM", "value is not in the allowed set")

        expected_type = schema.get("type")
        if expected_type is not None:
            types = (
                expected_type if isinstance(expected_type, list) else [expected_type]
            )
            if not any(self._has_type(instance, item) for item in types):
                self._add(output, path, "TYPE", "value has the wrong JSON type")
                return

        if isinstance(instance, dict):
            for name in sorted(schema.get("required", [])):
                if name not in instance:
                    self._add(
                        output,
                        path,
                        "REQUIRED",
                        "required property {!r} is missing".format(name),
                    )
            properties = schema.get("properties", {})
            for name in sorted(set(instance) & set(properties)):
                self._validate(
                    instance[name],
                    properties[name],
                    root_schema,
                    "{}.{}".format(path, name),
                    output,
                )
            extras = sorted(set(instance) - set(properties))
            additional = schema.get("additionalProperties", True)
            if additional is False:
                for name in extras:
                    self._add(
                        output,
                        path,
                        "ADDITIONAL_PROPERTY",
                        "additional property {!r} is not allowed".format(name),
                    )
            elif isinstance(additional, (dict, bool)):
                for name in extras:
                    self._validate(
                        instance[name],
                        additional,
                        root_schema,
                        "{}.{}".format(path, name),
                        output,
                    )
            if len(instance) < schema.get("minProperties", 0):
                self._add(output, path, "MIN_PROPERTIES", "object is too small")
            if len(instance) > schema.get("maxProperties", math.inf):
                self._add(output, path, "MAX_PROPERTIES", "object is too large")

        if isinstance(instance, list):
            if len(instance) < schema.get("minItems", 0):
                self._add(output, path, "MIN_ITEMS", "array is too short")
            if len(instance) > schema.get("maxItems", math.inf):
                self._add(output, path, "MAX_ITEMS", "array is too long")
            if schema.get("uniqueItems"):
                encoded: List[bytes] = []
                try:
                    encoded = [canonical_json_v2(item) for item in instance]
                except CanonicalJSONV2Error:
                    self._add(
                        output,
                        path,
                        "UNIQUE_ITEMS",
                        "array contains a non-canonical value",
                    )
                if encoded and len(encoded) != len(set(encoded)):
                    self._add(
                        output, path, "UNIQUE_ITEMS", "array contains duplicates"
                    )
            if "items" in schema:
                for index, item in enumerate(instance):
                    self._validate(
                        item,
                        schema["items"],
                        root_schema,
                        "{}[{}]".format(path, index),
                        output,
                    )

        if isinstance(instance, str):
            if len(instance) < schema.get("minLength", 0):
                self._add(output, path, "MIN_LENGTH", "string is too short")
            if len(instance) > schema.get("maxLength", math.inf):
                self._add(output, path, "MAX_LENGTH", "string is too long")
            if "pattern" in schema and re.search(schema["pattern"], instance) is None:
                self._add(output, path, "PATTERN", "string has an invalid form")
            if schema.get("format") == "date-time" and not _utc_z_timestamp(
                instance
            ):
                self._add(
                    output,
                    path,
                    "TIMESTAMP",
                    "timestamp must be a real UTC date-time ending in Z",
                )
            if schema.get("format") == "safe-relative-path" and not _safe_relative_path(
                instance
            ):
                self._add(
                    output,
                    path,
                    "PATH",
                    "path must be a canonical safe relative POSIX path",
                )

        if self._is_number(instance):
            if instance < schema.get("minimum", -math.inf):
                self._add(output, path, "MINIMUM", "number is below the minimum")
            if instance > schema.get("maximum", math.inf):
                self._add(output, path, "MAXIMUM", "number is above the maximum")

    @staticmethod
    def _is_number(value: Any) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    @classmethod
    def _has_type(cls, value: Any, expected: str) -> bool:
        checks = {
            "null": value is None,
            "boolean": isinstance(value, bool),
            "integer": isinstance(value, int) and not isinstance(value, bool),
            "number": cls._is_number(value),
            "string": isinstance(value, str),
            "array": isinstance(value, list),
            "object": isinstance(value, dict),
        }
        return checks[expected]

    @staticmethod
    def _json_equal(left: Any, right: Any) -> bool:
        if isinstance(left, bool) or isinstance(right, bool):
            return type(left) is type(right) and left == right
        return left == right
