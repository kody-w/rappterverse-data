#!/usr/bin/env python3
"""Verify D04 visible captures, patches, verifier evidence, and outcomes."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path, PurePosixPath

try:
    from ._fallback import DatasetError, common_errors, read_jsonl, sha256, timestamp
    from .generate import CAPTURE
except ImportError:
    from _fallback import (  # type: ignore
        DatasetError,
        common_errors,
        read_jsonl,
        sha256,
        timestamp,
    )
    from generate import CAPTURE  # type: ignore

DATASET_ID = "d04"


def errors_for(record: object) -> list[str]:
    errors = common_errors(record, DATASET_ID)
    if not isinstance(record, dict):
        return errors
    trajectory = record.get("work_trajectory")
    if not isinstance(trajectory, dict):
        return errors + ["work_trajectory must be an object"]
    if trajectory.get("capture") != CAPTURE:
        errors.append("capture is not complete and public-safe")
    if record.get("deliberation", {}).get("status") != "explicit":
        errors.append("work trajectory requires explicit deliberation")
    task = trajectory.get("task")
    if (
        not isinstance(task, dict)
        or not task.get("task_id")
        or not task.get("instruction")
    ):
        errors.append("task identity and instruction are required")
    try:
        started_at = timestamp(trajectory.get("started_at"))
        completed_at = timestamp(trajectory.get("completed_at"))
        if completed_at < started_at:
            errors.append("trajectory completed_at precedes started_at")
    except DatasetError as exc:
        errors.append(str(exc))

    calls = trajectory.get("tool_calls")
    if not isinstance(calls, list) or not calls:
        errors.append("tool_calls must be non-empty")
    else:
        for sequence, call in enumerate(calls):
            if (
                not isinstance(call, dict)
                or call.get("sequence") != sequence
                or not call.get("call_id")
                or not call.get("tool_name")
                or "arguments" not in call
                or "result" not in call
            ):
                errors.append("tool call is incomplete or out of order")
                continue
            try:
                started_at = timestamp(call.get("started_at"))
                completed_at = timestamp(call.get("completed_at"))
                if completed_at < started_at:
                    errors.append("tool call completed_at precedes started_at")
            except DatasetError as exc:
                errors.append(str(exc))
            if call.get("status") not in {"succeeded", "failed"}:
                errors.append("tool call status is invalid")

    patches = trajectory.get("patches")
    if not isinstance(patches, list) or not patches:
        errors.append("patches must be non-empty")
    else:
        for sequence, patch in enumerate(patches):
            if not isinstance(patch, dict):
                errors.append("patch must be an object")
                continue
            path = patch.get("path")
            if (
                not isinstance(path, str)
                or PurePosixPath(path).is_absolute()
                or ".." in PurePosixPath(path).parts
            ):
                errors.append("patch path is unsafe")
            if patch.get("sequence") != sequence:
                errors.append("patch sequence is invalid")
            if not isinstance(patch.get("before_content"), str) or not isinstance(
                patch.get("after_content"), str
            ):
                errors.append("patch before/after content must be strings")
            if patch.get("before_sha256") != sha256(patch.get("before_content")):
                errors.append("patch before_sha256 does not match")
            if patch.get("after_sha256") != sha256(patch.get("after_content")):
                errors.append("patch after_sha256 does not match")
            if not isinstance(patch.get("unified_diff"), str) or not patch.get(
                "unified_diff"
            ):
                errors.append("patch unified_diff is missing")
            if not isinstance(patch.get("applied"), bool):
                errors.append("patch applied flag must be boolean")

    evidence = trajectory.get("verifier_evidence")
    if not isinstance(evidence, list) or not evidence:
        errors.append("verifier_evidence must be non-empty")
    else:
        for sequence, result in enumerate(evidence):
            if not isinstance(result, dict):
                errors.append("verifier result must be an object")
                continue
            if result.get("sequence") != sequence:
                errors.append("verifier sequence is invalid")
            if result.get("output_sha256") != sha256(result.get("output")):
                errors.append("verifier output_sha256 does not match")
            if result.get("passed") != (result.get("exit_code") == 0):
                errors.append("verifier passed flag disagrees with exit_code")

    outcome = trajectory.get("outcome")
    if (
        not isinstance(outcome, dict)
        or outcome.get("status") not in {"succeeded", "failed", "partial"}
        or not outcome.get("summary")
        or not isinstance(outcome.get("artifact_refs"), list)
    ):
        errors.append("terminal outcome is incomplete")
    elif outcome["status"] == "succeeded" and isinstance(evidence, list) and any(
        isinstance(result, dict) and result.get("passed") is not True
        for result in evidence
    ):
        errors.append("succeeded outcome has failing verifier evidence")
    return errors


def verify(records: list[dict]) -> list[str]:
    errors = []
    seen = set()
    previous = None
    for index, record in enumerate(records, 1):
        errors.extend(f"record {index}: {error}" for error in errors_for(record))
        record_id = record.get("record_id")
        if record_id in seen:
            errors.append(f"record {index}: duplicate record_id")
        seen.add(record_id)
        order = (record.get("observed_at", ""), str(record_id))
        if previous is not None and order < previous:
            errors.append(f"record {index}: records are not ordered")
        previous = order
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        records = read_jsonl(args.input)
    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    errors = verify(records)
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"verified {len(records)} d04 work trajectories")
    return 0


if __name__ == "__main__":
    sys.exit(main())
