#!/usr/bin/env python3
"""Verify D08 fictional governance rule-oracle JSONL records."""

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

DATASET_ID = "d08"


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


def _evaluate(
    rules: dict[str, Any],
    members: list[dict[str, str]],
    ballots: list[dict[str, str]],
) -> dict[str, Any]:
    member_roles = {member["member_id"]: member["role"] for member in members}
    eligible = len(members)
    turnout = len(ballots)
    yes = sum(ballot["vote"] == "yes" for ballot in ballots)
    no = sum(ballot["vote"] == "no" for ballot in ballots)
    abstain = sum(ballot["vote"] == "abstain" for ballot in ballots)
    decisive = yes + no
    quorum_met = turnout * 100 >= rules["quorum_percent"] * eligible
    threshold_met = (
        decisive > 0 and yes * 100 >= rules["approval_percent"] * decisive
    )
    veto_triggered = rules["guardian_veto"] and any(
        ballot["vote"] == "no"
        and member_roles[ballot["member_id"]] == rules["veto_role"]
        for ballot in ballots
    )
    return {
        "approved": quorum_met and threshold_met and not veto_triggered,
        "counts": {
            "abstain": abstain,
            "decisive": decisive,
            "eligible": eligible,
            "no": no,
            "turnout": turnout,
            "yes": yes,
        },
        "quorum_met": quorum_met,
        "threshold_met": threshold_met,
        "veto_triggered": veto_triggered,
    }


def validate_record(record: dict[str, Any]) -> list[str]:
    errors = common_envelope_errors(record, DATASET_ID)
    errors.extend(_validate_reasoning(record))
    if record.get("dataset_id") != DATASET_ID:
        errors.append(f"dataset_id must be {DATASET_ID}")
    rules = record.get("rules")
    members = record.get("members")
    ballots = record.get("ballots")
    oracle = record.get("oracle")
    proposal = record.get("proposal")
    if not isinstance(rules, dict):
        return errors + ["rules must be an object"]
    if not isinstance(members, list) or len(members) < 4:
        return errors + ["members must contain at least four fictional members"]
    if not isinstance(ballots, list):
        return errors + ["ballots must be a list"]
    if not isinstance(oracle, dict):
        return errors + ["oracle must be an object"]
    if not isinstance(proposal, dict) or proposal.get("synthetic") is not True:
        errors.append("proposal must be marked synthetic")

    for key in ("quorum_percent", "approval_percent"):
        if not isinstance(rules.get(key), int) or not 1 <= rules[key] <= 100:
            errors.append(f"rules.{key} must be an integer in [1, 100]")
    if rules.get("guardian_veto") is not True:
        errors.append("guardian_veto must be an explicit boolean true")
    if not isinstance(rules.get("veto_role"), str):
        errors.append("veto_role must be a string")

    member_ids: set[str] = set()
    member_roles: set[str] = set()
    for member in members:
        if not isinstance(member, dict):
            errors.append("each member must be an object")
            continue
        member_id = member.get("member_id")
        role = member.get("role")
        if not isinstance(member_id, str) or not member_id:
            errors.append("member_id must be a non-empty string")
        elif member_id in member_ids:
            errors.append(f"duplicate member_id {member_id}")
        else:
            member_ids.add(member_id)
        if isinstance(role, str):
            member_roles.add(role)
    if rules.get("veto_role") not in member_roles:
        errors.append("veto_role is not represented by a member")

    voters: set[str] = set()
    for ballot in ballots:
        if not isinstance(ballot, dict):
            errors.append("each ballot must be an object")
            continue
        member_id = ballot.get("member_id")
        if member_id not in member_ids:
            errors.append("ballot references an ineligible member")
        elif member_id in voters:
            errors.append(f"member {member_id} cast multiple ballots")
        else:
            voters.add(member_id)
        if ballot.get("vote") not in {"yes", "no", "abstain"}:
            errors.append("ballot vote must be yes, no, or abstain")

    if not errors:
        expected = _evaluate(rules, members, ballots)
        if oracle != expected:
            errors.append("oracle does not match independent rule evaluation")
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
