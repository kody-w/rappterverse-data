#!/usr/bin/env python3
"""Verify D02 paired branches, replay hashes, and causal contrasts."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from ._fallback import (
        DatasetError,
        causal_contrast,
        common_errors,
        read_jsonl,
        replay_branch,
        sha256,
    )
except ImportError:
    from _fallback import (  # type: ignore
        DatasetError,
        causal_contrast,
        common_errors,
        read_jsonl,
        replay_branch,
        sha256,
    )

DATASET_ID = "d02"


def errors_for(record: object) -> list[str]:
    errors = common_errors(record, DATASET_ID)
    if not isinstance(record, dict):
        return errors
    pair = record.get("counterfactual_pair")
    if not isinstance(pair, dict):
        return errors + ["counterfactual_pair must be an object"]
    base = pair.get("base_state")
    intervention = pair.get("intervention")
    steps = pair.get("shared_replay_steps")
    if (
        not isinstance(base, dict)
        or not isinstance(intervention, dict)
        or not isinstance(steps, list)
        or not all(isinstance(step, dict) for step in steps)
    ):
        return errors + ["pair inputs are malformed"]
    if pair.get("base_state_sha256") != sha256(base):
        errors.append("base_state_sha256 does not match")
    if pair.get("isolated_intervention") is not True:
        errors.append("isolated_intervention must be true")
    if record.get("deliberation", {}).get("status") != "explicit":
        errors.append("counterfactual pair requires explicit deliberation")
    try:
        control = replay_branch(base, intervention=None, shared_steps=steps)
        treatment = replay_branch(
            base, intervention=intervention, shared_steps=steps
        )
    except DatasetError as exc:
        return errors + [str(exc)]
    if pair.get("control") != control:
        errors.append("control branch does not replay exactly")
    if pair.get("treatment") != treatment:
        errors.append("treatment branch does not replay exactly")
    expected_contrast = causal_contrast(
        control["final_state"], treatment["final_state"]
    )
    if pair.get("causal_contrast") != expected_contrast:
        errors.append("causal_contrast does not match final states")
    if control["post_intervention_state_sha256"] != control["initial_state_sha256"]:
        errors.append("control changed during intervention phase")
    if (
        treatment["post_intervention_state_sha256"]
        == treatment["initial_state_sha256"]
    ):
        errors.append("treatment intervention had no state effect")
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
    print(f"verified {len(records)} d02 branch pairs")
    return 0


if __name__ == "__main__":
    sys.exit(main())
