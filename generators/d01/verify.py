#!/usr/bin/env python3
"""Verify D01 Civilization Ledger JSONL records."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

try:
    from ._fallback import DatasetError, common_errors, read_jsonl
except ImportError:
    from _fallback import DatasetError, common_errors, read_jsonl  # type: ignore

DATASET_ID = "d01"
ALLOWED_SOURCE_TYPES = {
    "legacy_action_export",
    "owned_synthetic_event",
    "rappterverse_owned_event",
    "synthetic_smoke",
}


def errors_for(record: object) -> list[str]:
    errors = common_errors(record, DATASET_ID)
    if not isinstance(record, dict):
        return errors
    event = record.get("event")
    if not isinstance(event, dict):
        errors.append("event must be an object")
    else:
        if not event.get("event_type"):
            errors.append("event.event_type is required")
        if not event.get("source_event_id"):
            errors.append("event.source_event_id is required")
        if not isinstance(event.get("outcome"), dict):
            errors.append("event.outcome must be an object")
    if not isinstance(record.get("world"), str):
        errors.append("world must be a string")
    source = record.get("source")
    if isinstance(source, dict) and source.get("source_type") not in ALLOWED_SOURCE_TYPES:
        errors.append("source type is not RAPPterverse-owned or synthetic")
    return errors


def verify(records: list[dict]) -> list[str]:
    errors = []
    seen = set()
    previous = None
    for index, record in enumerate(records, 1):
        for error in errors_for(record):
            errors.append(f"record {index}: {error}")
        record_id = record.get("record_id")
        if record_id in seen:
            errors.append(f"record {index}: duplicate record_id")
        seen.add(record_id)
        order = (record.get("observed_at", ""), str(record_id))
        if previous is not None and order < previous:
            errors.append(f"record {index}: records are not deterministically ordered")
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
    print(f"verified {len(records)} d01 records")
    return 0


if __name__ == "__main__":
    sys.exit(main())
