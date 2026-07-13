#!/usr/bin/env python3
"""Verify D09 safe in-memory fault and recovery JSONL records."""

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

DATASET_ID = "d09"
FAULT_TYPES = {
    "duplicate_delivery",
    "reordered_delivery",
    "dropped_ack",
    "transient_read_error",
}


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


def _apply(state: dict[str, Any], operation: dict[str, Any]) -> None:
    if operation["kind"] == "put":
        state[operation["key"]] = operation["value"]
    elif operation["kind"] == "increment":
        current = state.get(operation["key"], 0)
        if not isinstance(current, int):
            raise ValueError("increment target is not an integer")
        state[operation["key"]] = current + operation["delta"]
    else:
        raise ValueError("unsupported operation")


def validate_record(record: dict[str, Any]) -> list[str]:
    errors = common_envelope_errors(record, DATASET_ID)
    errors.extend(_validate_reasoning(record))
    if record.get("dataset_id") != DATASET_ID:
        errors.append(f"dataset_id must be {DATASET_ID}")
    initial_state = record.get("initial_state")
    operations = record.get("operations")
    fault_trace = record.get("fault_trace")
    recovery = record.get("recovery")
    oracle = record.get("oracle")
    if not isinstance(initial_state, dict):
        return errors + ["initial_state must be an object"]
    if not isinstance(operations, list) or len(operations) < 3:
        return errors + ["operations must contain at least three entries"]
    if not isinstance(fault_trace, dict) or not isinstance(recovery, dict):
        return errors + ["fault_trace and recovery must be objects"]
    if not isinstance(oracle, dict):
        return errors + ["oracle must be an object"]
    if fault_trace.get("simulation_scope") != "in-memory-only":
        errors.append("fault simulation must be in-memory-only")
    fault_type = fault_trace.get("fault_type")
    if fault_type not in FAULT_TYPES:
        errors.append("fault_type is not allowed")

    operation_ids: list[str] = []
    for expected_sequence, operation in enumerate(operations):
        if not isinstance(operation, dict):
            errors.append(f"operations[{expected_sequence}] must be an object")
            continue
        if operation.get("sequence") != expected_sequence:
            errors.append(f"operations[{expected_sequence}] sequence mismatch")
        op_id = operation.get("op_id")
        if not isinstance(op_id, str) or op_id in operation_ids:
            errors.append(f"operations[{expected_sequence}] op_id is invalid")
        else:
            operation_ids.append(op_id)
        if operation.get("kind") not in {"put", "increment"}:
            errors.append(f"operations[{expected_sequence}] kind is unsafe or unsupported")
        if not isinstance(operation.get("key"), str):
            errors.append(f"operations[{expected_sequence}] key must be a string")
        if operation.get("kind") == "increment" and not isinstance(
            operation.get("delta"), int
        ):
            errors.append(f"operations[{expected_sequence}] delta must be an integer")

    delivery_order = fault_trace.get("delivery_order")
    attempts = fault_trace.get("attempts")
    if not isinstance(delivery_order, list) or not all(
        op_id in operation_ids for op_id in delivery_order
    ):
        errors.append("delivery_order must reference only canonical operations")
    if not isinstance(attempts, list):
        errors.append("fault_trace.attempts must be a list")
    if recovery.get("applied_order") != operation_ids:
        errors.append("recovery must apply canonical operations exactly once and in order")
    actions = recovery.get("actions")
    required_actions = {
        "buffer-by-sequence",
        "deduplicate-by-op-id",
        "retry-transient-observations",
        "apply-canonical-order-once",
    }
    if not isinstance(actions, list) or not required_actions.issubset(actions):
        errors.append("recovery actions are incomplete")

    if isinstance(delivery_order, list) and fault_type == "duplicate_delivery":
        if len(delivery_order) == len(set(delivery_order)):
            errors.append("duplicate_delivery trace has no duplicate")
    if isinstance(delivery_order, list) and fault_type == "reordered_delivery":
        if delivery_order == operation_ids:
            errors.append("reordered_delivery trace is still canonical")
    if isinstance(attempts, list) and fault_type == "dropped_ack":
        if not any(attempt.get("result") == "delivered_ack_lost" for attempt in attempts):
            errors.append("dropped_ack trace has no lost acknowledgement")
    if isinstance(attempts, list) and fault_type == "transient_read_error":
        if not any(attempt.get("result") == "transient_read_error" for attempt in attempts):
            errors.append("transient_read_error trace has no transient error")

    final_state = dict(initial_state)
    if not errors:
        try:
            for operation in operations:
                _apply(final_state, operation)
        except (KeyError, ValueError) as exc:
            errors.append(str(exc))
    expected_oracle = {
        "exactly_once": True,
        "final_state": final_state,
        "recovered": True,
        "safe_simulation": True,
    }
    if oracle != expected_oracle:
        errors.append("oracle does not match canonical in-memory replay")
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
