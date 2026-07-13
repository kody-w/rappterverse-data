# SPDX-License-Identifier: Apache-2.0

"""Trusted v2 public-release contracts and semantic validation."""

from .canonical import (
    CANONICALIZATION_V2,
    MAX_JSON_NESTING_DEPTH,
    CanonicalJSONV2Error,
    CanonicalJSONV2DepthError,
    canonical_json_v2,
    ensure_json_depth,
    parse_json_v2,
)
from .registry import (
    ARTIFACT_KIND_TO_SCHEMA_VERSION,
    SCHEMA_VERSION_TO_PATH,
    TrustedSchemaRegistry,
)
from .release_trust import (
    ReleaseTrustValidator,
    TrustedPredecessorAnchor,
    TrustDiagnostic,
    object_path_matches_sha256,
    review_supersession_diagnostics,
    validate_release_graph,
)
from .validator import ContractDiagnostic, ContractValidator

__all__ = [
    "ARTIFACT_KIND_TO_SCHEMA_VERSION",
    "CANONICALIZATION_V2",
    "MAX_JSON_NESTING_DEPTH",
    "CanonicalJSONV2Error",
    "CanonicalJSONV2DepthError",
    "ContractDiagnostic",
    "ContractValidator",
    "ReleaseTrustValidator",
    "SCHEMA_VERSION_TO_PATH",
    "TrustedSchemaRegistry",
    "TrustedPredecessorAnchor",
    "TrustDiagnostic",
    "canonical_json_v2",
    "ensure_json_depth",
    "object_path_matches_sha256",
    "parse_json_v2",
    "review_supersession_diagnostics",
    "validate_release_graph",
]
