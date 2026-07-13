#!/usr/bin/env python3
"""Verify D05 tick completeness, state continuity, and lifecycle aggregates."""

from __future__ import annotations

import argparse
import sys
from collections import Counter
from datetime import datetime
from pathlib import Path

try:
    from ._fallback import DatasetError, common_errors, read_jsonl, sha256, timestamp
except ImportError:
    from _fallback import (  # type: ignore
        DatasetError,
        common_errors,
        read_jsonl,
        sha256,
        timestamp,
    )

DATASET_ID = "d05"


def _seconds_between(start: str, end: str) -> int:
    first = datetime.fromisoformat(start.replace("Z", "+00:00"))
    last = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return int((last - first).total_seconds())


def errors_for(record: object) -> list[str]:
    errors = common_errors(record, DATASET_ID)
    if not isinstance(record, dict):
        return errors
    lifetime = record.get("agent_lifetime")
    if not isinstance(lifetime, dict):
        return errors + ["agent_lifetime must be an object"]
    if lifetime.get("complete") is not True:
        errors.append("lifetime must be complete")
    if record.get("deliberation", {}).get("status") != "explicit":
        errors.append("complete lifetime requires explicit deliberation")
    birth = lifetime.get("birth_event")
    terminal = lifetime.get("terminal_event")
    ticks = lifetime.get("ticks")
    if not isinstance(birth, dict) or not isinstance(terminal, dict):
        return errors + ["birth_event and terminal_event are required"]
    if not isinstance(ticks, list) or not ticks:
        return errors + ["ticks must be non-empty"]
    try:
        birth_at = timestamp(birth.get("observed_at"))
        terminal_at = timestamp(terminal.get("observed_at"))
    except DatasetError as exc:
        return errors + [str(exc)]
    initial_state = birth.get("initial_state")
    if not isinstance(initial_state, dict):
        return errors + ["birth initial_state must be an object"]
    if birth.get("initial_state_sha256") != sha256(initial_state):
        errors.append("birth state hash does not match")
    if "world" in initial_state and birth.get("world") != str(initial_state["world"]):
        errors.append("birth world does not match initial state")

    previous_state = initial_state
    previous_at = birth_at
    kinds = set()
    memories = []
    goals = []
    relationships = []
    action_counts = Counter()
    worlds = [birth.get("world")]
    for sequence, tick in enumerate(ticks):
        if not isinstance(tick, dict):
            errors.append("tick must be an object")
            continue
        if tick.get("sequence") != sequence:
            errors.append("tick sequence has a gap")
        try:
            observed_at = timestamp(tick.get("observed_at"))
            if observed_at <= previous_at:
                errors.append("tick timestamps are not strictly increasing")
            previous_at = observed_at
        except DatasetError as exc:
            errors.append(str(exc))
        kind = tick.get("kind")
        kinds.add(kind)
        if kind not in {"decision", "idle"}:
            errors.append("invalid tick kind")
        if kind == "decision" and not tick.get("action"):
            errors.append("decision tick lacks action")
        if kind == "idle" and not tick.get("idle_reason"):
            errors.append("idle tick lacks idle_reason")
        tick_deliberation = tick.get("deliberation")
        if (
            not isinstance(tick_deliberation, dict)
            or tick_deliberation.get("status") != "explicit"
        ):
            errors.append("tick lacks explicit deliberation")
        before = tick.get("state_before")
        after = tick.get("state_after")
        if not isinstance(before, dict) or not isinstance(after, dict):
            errors.append("tick states must be objects")
        if before != previous_state:
            errors.append("tick state continuity is broken")
        if tick.get("state_before_sha256") != sha256(before):
            errors.append("state_before_sha256 does not match")
        if tick.get("state_after_sha256") != sha256(after):
            errors.append("state_after_sha256 does not match")
        if isinstance(after, dict) and "world" in after and tick.get("world") != str(
            after["world"]
        ):
            errors.append("tick world does not match state_after")
        previous_state = after
        for key, target in (
            ("memory_updates", memories),
            ("goal_updates", goals),
            ("relationship_updates", relationships),
        ):
            updates = tick.get(key)
            if not isinstance(updates, list) or not all(
                isinstance(item, dict) for item in updates
            ):
                errors.append(f"{key} must contain objects")
            else:
                target.extend(updates)
        action_counts[tick.get("action") if kind == "decision" else "idle"] += 1
        worlds.append(tick.get("world"))

    if kinds != {"decision", "idle"}:
        errors.append("lifetime must include decision and idle ticks")
    if terminal_at <= previous_at:
        errors.append("terminal event does not follow all ticks")
    if terminal.get("final_state") != previous_state:
        errors.append("terminal final_state does not join final tick")
    if terminal.get("final_state_sha256") != sha256(terminal.get("final_state")):
        errors.append("terminal final_state_sha256 does not match")
    if not terminal.get("event_type") or not isinstance(terminal.get("outcome"), dict):
        errors.append("terminal event is incomplete")
    if lifetime.get("duration_seconds") != _seconds_between(birth_at, terminal_at):
        errors.append("duration_seconds does not match")
    if lifetime.get("memories") != memories:
        errors.append("memory aggregate does not match ticks")
    if lifetime.get("goals") != goals:
        errors.append("goal aggregate does not match ticks")
    if lifetime.get("relationships") != relationships:
        errors.append("relationship aggregate does not match ticks")
    if lifetime.get("action_counts") != dict(sorted(action_counts.items())):
        errors.append("action_counts do not match ticks")
    expected_worlds = list(dict.fromkeys(worlds))
    if lifetime.get("worlds_visited") != expected_worlds:
        errors.append("worlds_visited do not match ticks")
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
    print(f"verified {len(records)} d05 complete lifetimes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
