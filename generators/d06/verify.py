#!/usr/bin/env python3
"""Verify D06 paired-world social causality JSONL records."""

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

DATASET_ID = "d06"


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
    pair = record.get("pair")
    oracle = record.get("oracle")
    if not isinstance(pair, dict) or not isinstance(oracle, dict):
        return errors + ["pair and oracle must be objects"]
    noise = pair.get("common_noise")
    worlds = pair.get("worlds")
    if not isinstance(noise, list) or not noise:
        errors.append("pair.common_noise must be non-empty")
    if not isinstance(worlds, list) or len(worlds) != 2:
        return errors + ["pair.worlds must contain exactly two worlds"]
    digest = hashlib.sha256(_canonical(noise).encode()).hexdigest()
    if pair.get("common_noise_digest") != digest:
        errors.append("pair.common_noise_digest does not match the tape")
    arms = {world.get("arm") for world in worlds if isinstance(world, dict)}
    if arms != {"control", "treatment"}:
        errors.append("worlds must contain one control and one treatment arm")
        return errors
    assignment = pair.get("assignment")
    expected_assignment = {
        world.get("world_id"): world.get("arm") for world in worlds
    }
    if assignment != expected_assignment:
        errors.append("pair.assignment does not match the worlds")
    outcomes: dict[str, int] = {}
    for world in worlds:
        if world.get("common_noise_ref") != "/pair/common_noise":
            errors.append("each world must reference /pair/common_noise")
        if world.get("common_noise_digest") != digest:
            errors.append("world common-noise digest mismatch")
        score = world.get("outcome", {}).get("cooperation_score")
        if not isinstance(score, int) or not 0 <= score <= 100:
            errors.append("cooperation_score must be an integer in [0, 100]")
        else:
            outcomes[world["arm"]] = score
    if set(outcomes) == {"control", "treatment"}:
        paired_effect = outcomes["treatment"] - outcomes["control"]
        if oracle.get("control_outcome") != outcomes["control"]:
            errors.append("oracle control_outcome mismatch")
        if oracle.get("treatment_outcome") != outcomes["treatment"]:
            errors.append("oracle treatment_outcome mismatch")
        if oracle.get("paired_effect") != paired_effect:
            errors.append("oracle paired_effect mismatch")
    if oracle.get("common_noise_shared") is not True:
        errors.append("oracle must mark common noise as shared")
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
