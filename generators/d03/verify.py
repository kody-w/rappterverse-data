#!/usr/bin/env python3
"""Verify D03 candidate blinding, consent, agreement, and adjudication."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

try:
    from ._fallback import DatasetError, common_errors, read_jsonl, timestamp
    from .generate import PRIVATE_KEYS, agreement_metrics
except ImportError:
    from _fallback import DatasetError, common_errors, read_jsonl, timestamp  # type: ignore
    from generate import PRIVATE_KEYS, agreement_metrics  # type: ignore

DATASET_ID = "d03"


def _private_paths(value: object, path: str = "") -> list[str]:
    paths = []
    if isinstance(value, dict):
        for key, child in value.items():
            child_path = f"{path}.{key}" if path else key
            if key in PRIVATE_KEYS:
                paths.append(child_path)
            elif key != "exposed_reasoning_refs":
                paths.extend(_private_paths(child, child_path))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            paths.extend(_private_paths(child, f"{path}[{index}]"))
    return paths


def _consent_errors(value: object) -> list[str]:
    if not isinstance(value, dict):
        return ["consent must be an object"]
    errors = []
    if value.get("status") != "granted":
        errors.append("consent must be granted")
    scopes = value.get("scopes")
    if not isinstance(scopes, list) or "public_dataset_label" not in scopes:
        errors.append("consent lacks public_dataset_label scope")
    if not value.get("evidence_ref"):
        errors.append("consent requires evidence_ref")
    try:
        timestamp(value.get("granted_at"))
    except DatasetError as exc:
        errors.append(str(exc))
    return errors


def candidate_errors(record: object) -> list[str]:
    errors = common_errors(record, DATASET_ID)
    if not isinstance(record, dict):
        return errors
    leaked = _private_paths(record)
    if leaked:
        errors.append(f"candidate leaks review data: {', '.join(sorted(leaked))}")
    if record.get("label_status") != "unlabeled_candidate":
        errors.append("label_status must be unlabeled_candidate")
    if record.get("actors") != ["blinded-candidate"]:
        errors.append("candidate actors are not blinded")
    if record.get("deliberation", {}).get("status") != "explicit":
        errors.append("candidate requires explicit deliberation")
    if not isinstance(record.get("context"), dict):
        errors.append("candidate context must be an object")
    return errors


def label_errors(label: object, candidate_ids: set[str]) -> list[str]:
    if not isinstance(label, dict):
        return ["label must be an object"]
    errors = []
    if label.get("schema") != "rappterverse.d03-consented-label/v1":
        errors.append("invalid consented-label schema")
    if label.get("dataset_id") != DATASET_ID:
        errors.append("invalid dataset_id")
    if label.get("record_id") not in candidate_ids:
        errors.append("label does not join to a candidate")
    if label.get("publication") != {
        "candidate_blinded": True,
        "consent_verified": True,
        "review_safe": True,
    }:
        errors.append("label is not marked review-safe")
    judgments = label.get("judgments")
    if not isinstance(judgments, list) or len(judgments) < 2:
        return errors + ["at least two consented judgments are required"]
    judgment_labels = []
    reviewer_refs = set()
    for judgment in judgments:
        if not isinstance(judgment, dict):
            errors.append("judgment must be an object")
            continue
        judgment_labels.append(judgment.get("label"))
        reviewer_ref = judgment.get("reviewer_ref")
        if (
            not isinstance(reviewer_ref, str)
            or not reviewer_ref.startswith("reviewer-")
            or reviewer_ref in reviewer_refs
        ):
            errors.append("reviewer_ref must be unique and pseudonymous")
        reviewer_refs.add(reviewer_ref)
        errors.extend(_consent_errors(judgment.get("consent")))
    if not all(isinstance(value, str) and value for value in judgment_labels):
        errors.append("judgment labels must be non-empty strings")
        return errors
    expected_metrics = agreement_metrics(judgment_labels)
    if label.get("agreement") != expected_metrics:
        errors.append("agreement metrics do not recompute")
    adjudication = label.get("adjudication")
    if not isinstance(adjudication, dict):
        return errors + ["adjudication must be an object"]
    selected = adjudication.get("selected_label")
    if selected not in Counter(judgment_labels):
        errors.append("adjudication selected_label lacks a supporting judgment")
    if label.get("gold_label") != selected:
        errors.append("gold_label does not match adjudication")
    if expected_metrics["unanimous"]:
        if adjudication.get("method") != "unanimous":
            errors.append("unanimous judgments require unanimous adjudication")
    else:
        if adjudication.get("method") != "consented_adjudication":
            errors.append("disagreement requires consented adjudication")
        errors.extend(_consent_errors(adjudication.get("consent")))
        if not adjudication.get("reviewer_ref") or not adjudication.get("rationale"):
            errors.append("adjudication requires reviewer_ref and rationale")
    return errors


def verify(candidates: list[dict], labels: list[dict]) -> list[str]:
    errors = []
    candidate_ids = set()
    previous = None
    for index, candidate in enumerate(candidates, 1):
        errors.extend(
            f"candidate {index}: {error}" for error in candidate_errors(candidate)
        )
        record_id = candidate.get("record_id")
        if record_id in candidate_ids:
            errors.append(f"candidate {index}: duplicate record_id")
        candidate_ids.add(record_id)
        order = (candidate.get("observed_at", ""), str(record_id))
        if previous is not None and order < previous:
            errors.append(f"candidate {index}: candidates are not ordered")
        previous = order
    label_ids = set()
    for index, label in enumerate(labels, 1):
        errors.extend(
            f"label {index}: {error}" for error in label_errors(label, candidate_ids)
        )
        record_id = label.get("record_id")
        if record_id in label_ids:
            errors.append(f"label {index}: duplicate record_id")
        label_ids.add(record_id)
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidates", type=Path, required=True)
    parser.add_argument("--labels", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        candidates = read_jsonl(args.candidates)
        labels = read_jsonl(args.labels)
    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    errors = verify(candidates, labels)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"verified {len(candidates)} d03 candidates and {len(labels)} gold labels")
    return 0


if __name__ == "__main__":
    sys.exit(main())
