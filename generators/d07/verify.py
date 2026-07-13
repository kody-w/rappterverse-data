#!/usr/bin/env python3
"""Verify D07 conservation and ordering tape JSONL records."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

try:
    from ._fallback import common_envelope_errors
except ImportError:
    from _fallback import common_envelope_errors

DATASET_ID = "d07"


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _validate_reasoning(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    reasoning = record.get("reasoning")
    if not isinstance(reasoning, dict):
        return ["reasoning must be an object"]
    required = {
        "observation": ("references", "facts"),
        "inference": ("references", "rule"),
        "decision": ("references", "label"),
    }
    if set(reasoning) != set(required):
        errors.append("reasoning must contain exactly observation, inference, and decision")
        return errors
    for layer, fields in required.items():
        value = reasoning[layer]
        if not isinstance(value, dict):
            errors.append(f"reasoning.{layer} must be an object")
            continue
        for field in fields:
            if field not in value:
                errors.append(f"reasoning.{layer}.{field} is required")
        references = value.get("references")
        if not isinstance(references, list) or not references:
            errors.append(f"reasoning.{layer}.references must be non-empty")
        elif not all(isinstance(ref, str) and ref.startswith("/") for ref in references):
            errors.append(f"reasoning.{layer}.references must be JSON Pointers")
    return errors


def validate_record(record: dict[str, Any]) -> list[str]:
    errors = common_envelope_errors(record, DATASET_ID)
    errors.extend(_validate_reasoning(record))
    if record.get("dataset_id") != DATASET_ID:
        errors.append(f"dataset_id must be {DATASET_ID}")
    initial_state = record.get("initial_state")
    tape = record.get("tape")
    oracle = record.get("oracle")
    if not isinstance(initial_state, dict) or not initial_state:
        return errors + ["initial_state must be a non-empty object"]
    if not all(isinstance(value, int) and value >= 0 for value in initial_state.values()):
        errors.append("initial balances must be non-negative integers")
    if not isinstance(tape, list) or not tape:
        return errors + ["tape must be non-empty"]
    if not isinstance(oracle, dict):
        return errors + ["oracle must be an object"]

    balances = dict(initial_state)
    previous_hash = "GENESIS"
    for expected_sequence, event in enumerate(tape):
        if not isinstance(event, dict):
            errors.append(f"tape[{expected_sequence}] must be an object")
            continue
        if event.get("sequence") != expected_sequence:
            errors.append(f"tape[{expected_sequence}] sequence mismatch")
        if event.get("previous_event_hash") != previous_hash:
            errors.append(f"tape[{expected_sequence}] previous hash mismatch")
        core = {key: value for key, value in event.items() if key != "event_hash"}
        event_hash = hashlib.sha256(_canonical(core).encode()).hexdigest()
        if event.get("event_hash") != event_hash:
            errors.append(f"tape[{expected_sequence}] event hash mismatch")
        source = event.get("from")
        destination = event.get("to")
        amount = event.get("amount")
        if source not in balances or destination not in balances or source == destination:
            errors.append(f"tape[{expected_sequence}] account reference is invalid")
        elif not isinstance(amount, int) or amount <= 0:
            errors.append(f"tape[{expected_sequence}] amount must be positive")
        elif balances[source] < amount:
            errors.append(f"tape[{expected_sequence}] overdrafts the source")
        else:
            balances[source] -= amount
            balances[destination] += amount
        previous_hash = event_hash

    initial_total = sum(initial_state.values())
    final_total = sum(balances.values())
    expected = {
        "conserved": initial_total == final_total,
        "final_state": balances,
        "final_total": final_total,
        "initial_total": initial_total,
        "ordered": True,
        "terminal_event_hash": previous_hash,
    }
    if oracle != expected:
        errors.append("oracle does not match independent ordered replay")
    return errors


def _records_path(path: Path) -> Path:
    return path / "records.jsonl" if path.is_dir() else path


def verify(path: Path) -> tuple[int, list[str]]:
    records_path = _records_path(path)
    errors: list[str] = []
    seen: set[str] = set()
    count = 0
    previous_order: tuple[str, str] | None = None
    try:
        lines = records_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return 0, [str(exc)]
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        count += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number}: invalid JSON: {exc.msg}")
            continue
        if not isinstance(record, dict):
            errors.append(f"line {line_number}: record must be a JSON object")
            continue
        record_id = record.get("record_id")
        if not isinstance(record_id, str) or not record_id:
            errors.append(f"line {line_number}: record_id is required")
        elif record_id in seen:
            errors.append(f"line {line_number}: duplicate record_id {record_id}")
        else:
            seen.add(record_id)
        order = (str(record.get("observed_at", "")), str(record_id))
        if previous_order is not None and order < previous_order:
            errors.append(f"line {line_number}: records are not deterministically ordered")
        previous_order = order
        errors.extend(
            f"line {line_number}: {error}" for error in validate_record(record)
        )
    if count == 0:
        errors.append("no records found")

    manifest_path = records_path.parent / "manifest.json"
    if not manifest_path.exists():
        manifest_path = records_path.with_suffix(".manifest.json")
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("dataset_id") != DATASET_ID:
                errors.append("manifest dataset_id mismatch")
            if manifest.get("count") != count:
                errors.append("manifest count mismatch")
            digest = hashlib.sha256(records_path.read_bytes()).hexdigest()
            if manifest.get("records_sha256") != digest:
                errors.append("manifest records_sha256 mismatch")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"invalid manifest: {exc}")
    return count, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    count, errors = verify(args.input)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"verified {count} {DATASET_ID} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
