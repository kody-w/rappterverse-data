#!/usr/bin/env python3
"""Generate deterministic D05 Complete Agent Lifetime records."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from copy import deepcopy
from datetime import datetime
from pathlib import Path

try:
    from ._fallback import (
        DatasetError,
        deliberation,
        load_checkpoint,
        public_reasoning_refs,
        read_jsonl,
        save_checkpoint,
        sha256,
        stable_id,
        timestamp,
        transcript,
        write_jsonl,
    )
except ImportError:
    from _fallback import (  # type: ignore
        DatasetError,
        deliberation,
        load_checkpoint,
        public_reasoning_refs,
        read_jsonl,
        save_checkpoint,
        sha256,
        stable_id,
        timestamp,
        transcript,
        write_jsonl,
    )

DATASET_ID = "d05"
ALLOWED_SOURCE_TYPES = {"owned_accelerated_simulation", "synthetic_smoke"}


def _seconds_between(start: str, end: str) -> int:
    first = datetime.fromisoformat(start.replace("Z", "+00:00"))
    last = datetime.fromisoformat(end.replace("Z", "+00:00"))
    return int((last - first).total_seconds())


def _updates(tick: dict, key: str) -> list[dict]:
    value = tick.get(key, [])
    if not isinstance(value, list) or not all(isinstance(item, dict) for item in value):
        raise DatasetError(f"{key} must contain objects")
    return value


def _ticks(value: object, birth_at: str, initial_state: dict) -> list[dict]:
    if not isinstance(value, list) or not value:
        raise DatasetError("complete lifetime requires ticks")
    ticks = []
    previous_at = birth_at
    previous_state = initial_state
    for sequence, raw in enumerate(value):
        if not isinstance(raw, dict):
            raise DatasetError("tick must be an object")
        if raw.get("sequence") != sequence:
            raise DatasetError("tick sequences must start at zero without gaps")
        observed_at = timestamp(raw.get("observed_at"))
        if observed_at <= previous_at:
            raise DatasetError("tick timestamps must be strictly increasing")
        kind = raw.get("kind")
        if kind not in {"decision", "idle"}:
            raise DatasetError("tick kind must be decision or idle")
        state_before = raw.get("state_before")
        state_after = raw.get("state_after")
        if not isinstance(state_before, dict) or not isinstance(state_after, dict):
            raise DatasetError("tick states must be objects")
        if state_before != previous_state:
            raise DatasetError("tick state_before breaks lifetime continuity")
        action = raw.get("action")
        idle_reason = raw.get("idle_reason")
        if kind == "decision" and (not isinstance(action, str) or not action):
            raise DatasetError("decision tick requires action")
        if kind == "idle" and (not isinstance(idle_reason, str) or not idle_reason):
            raise DatasetError("idle tick requires idle_reason")
        tick_deliberation = deliberation(
            raw.get("explicit_deliberation"),
            default_decision=action if kind == "decision" else "idle",
        )
        if tick_deliberation["status"] != "explicit":
            raise DatasetError("every lifetime tick requires explicit deliberation")
        world = str(raw.get("world", state_after.get("world", "unknown")))
        if "world" in state_after and world != str(state_after["world"]):
            raise DatasetError("tick world must match state_after world")
        normalized = {
            "action": action if kind == "decision" else None,
            "deliberation": tick_deliberation,
            "goal_updates": _updates(raw, "goal_updates"),
            "idle_reason": idle_reason if kind == "idle" else None,
            "kind": kind,
            "memory_updates": _updates(raw, "memory_updates"),
            "observed_at": observed_at,
            "relationship_updates": _updates(raw, "relationship_updates"),
            "sequence": sequence,
            "state_after": state_after,
            "state_after_sha256": sha256(state_after),
            "state_before": state_before,
            "state_before_sha256": sha256(state_before),
            "world": world,
        }
        ticks.append(normalized)
        previous_at = observed_at
        previous_state = state_after
    if not any(tick["kind"] == "decision" for tick in ticks):
        raise DatasetError("lifetime requires at least one decision tick")
    if not any(tick["kind"] == "idle" for tick in ticks):
        raise DatasetError("lifetime requires at least one idle tick")
    return ticks


def normalize(source: dict) -> dict:
    source_id = str(source.get("source_id", source.get("id", "")))
    agent_id = str(source.get("agent_id", ""))
    source_type = str(source.get("source_type", ""))
    if not source_id or not agent_id:
        raise DatasetError("lifetime requires source id and agent_id")
    if source_type not in ALLOWED_SOURCE_TYPES:
        raise DatasetError("lifetime source must be owned accelerated simulation")
    birth = source.get("birth_event")
    terminal = source.get("terminal_event")
    if not isinstance(birth, dict) or not isinstance(terminal, dict):
        raise DatasetError("complete lifetime requires birth_event and terminal_event")
    birth_at = timestamp(birth.get("observed_at"))
    initial_state = birth.get("initial_state")
    if not isinstance(initial_state, dict):
        raise DatasetError("birth initial_state must be an object")
    birth_world = str(birth.get("world", initial_state.get("world", "unknown")))
    if "world" in initial_state and birth_world != str(initial_state["world"]):
        raise DatasetError("birth world must match initial_state world")
    ticks = _ticks(source.get("ticks"), birth_at, initial_state)
    terminal_at = timestamp(terminal.get("observed_at"))
    if terminal_at <= ticks[-1]["observed_at"]:
        raise DatasetError("terminal event must follow every tick")
    final_state = terminal.get("final_state")
    if final_state != ticks[-1]["state_after"]:
        raise DatasetError("terminal final_state must equal final tick state")
    event_type = terminal.get("event_type")
    if not isinstance(event_type, str) or not event_type:
        raise DatasetError("terminal event_type is required")
    outcome = terminal.get("outcome")
    if not isinstance(outcome, dict):
        raise DatasetError("terminal outcome must be an object")

    memories = [
        update for tick in ticks for update in tick["memory_updates"]
    ]
    goals = [update for tick in ticks for update in tick["goal_updates"]]
    relationships = [
        update for tick in ticks for update in tick["relationship_updates"]
    ]
    action_counts = Counter(
        tick["action"] if tick["kind"] == "decision" else "idle" for tick in ticks
    )
    worlds_visited = list(dict.fromkeys(
        [birth_world]
        + [tick["world"] for tick in ticks]
    ))
    lineage = str(source.get("lineage", "owned-synthetic"))
    content_sha256 = sha256(source)
    public_deliberation = deliberation(
        source.get("explicit_deliberation"),
        default_decision=event_type,
    )
    if public_deliberation["status"] != "explicit":
        raise DatasetError("complete lifetime requires explicit deliberation")
    record = {
        "actors": [agent_id],
        "agent_lifetime": {
            "action_counts": dict(sorted(action_counts.items())),
            "agent_id": agent_id,
            "birth_event": {
                "initial_state": initial_state,
                "initial_state_sha256": sha256(initial_state),
                "observed_at": birth_at,
                "world": birth_world,
            },
            "complete": True,
            "duration_seconds": _seconds_between(birth_at, terminal_at),
            "goals": goals,
            "memories": memories,
            "relationships": relationships,
            "terminal_event": {
                "event_type": event_type,
                "final_state": final_state,
                "final_state_sha256": sha256(final_state),
                "observed_at": terminal_at,
                "outcome": outcome,
            },
            "ticks": ticks,
            "worlds_visited": worlds_visited,
        },
        "dataset_id": DATASET_ID,
        "deliberation": public_deliberation,
        "observed_at": birth_at,
        "record_id": stable_id(DATASET_ID, lineage, source_id, content_sha256),
        "schema": "rappterverse.d05-record/v1",
        "source": {
            "content_sha256": content_sha256,
            "lineage": lineage,
            "source_id": source_id,
            "source_type": source_type,
        },
        "transcript": transcript(
            source.get("transcript"),
            default_speaker=agent_id,
            default_timestamp=birth_at,
            default_text=f"Synthetic lifetime began for {agent_id}.",
        ),
        "world": birth_world,
    }
    refs = public_reasoning_refs(source.get("exposed_reasoning_refs"))
    if refs:
        record["exposed_reasoning_refs"] = refs
    return record


def _smoke_ticks(number: int) -> list[dict]:
    worlds = ("hub", "gallery", "marketplace")
    state = {"energy": 100, "tick": 0, "world": "hub"}
    ticks = []
    for sequence, kind in enumerate(("decision", "idle", "decision")):
        before = deepcopy(state)
        state["tick"] += 1
        state["energy"] -= 5
        action = None
        idle_reason = None
        if kind == "decision":
            action = "travel" if sequence == 0 else "complete-goal"
            state["world"] = worlds[(number + sequence) % len(worlds)]
        else:
            idle_reason = "recover energy between decisions"
        ticks.append({
            "action": action,
            "explicit_deliberation": {
                "alternatives": ["act", "idle"],
                "confidence": 0.75,
                "decision": action or "idle",
                "summary": f"Public tick rationale {number}-{sequence}.",
            },
            "goal_updates": ([{
                "goal_id": f"goal-{number:03d}",
                "status": "completed",
            }] if sequence == 2 else []),
            "idle_reason": idle_reason,
            "kind": kind,
            "memory_updates": ([{
                "memory_id": f"memory-{number:03d}",
                "summary": "Observed a synthetic landmark.",
            }] if sequence == 0 else []),
            "observed_at": f"2040-05-{number:02d}T00:0{sequence + 1}:00Z",
            "relationship_updates": ([{
                "other_actor": f"smoke-peer-{number:03d}",
                "strength_delta": 1,
            }] if sequence == 1 else []),
            "sequence": sequence,
            "state_after": deepcopy(state),
            "state_before": before,
            "world": state["world"],
        })
    return ticks


def synthetic_sources(count: int = 3) -> list[dict]:
    sources = []
    for index in range(count):
        number = index + 1
        ticks = _smoke_ticks(number)
        agent_id = f"smoke-agent-{number:03d}"
        sources.append({
            "agent_id": agent_id,
            "birth_event": {
                "initial_state": {"energy": 100, "tick": 0, "world": "hub"},
                "observed_at": f"2040-05-{number:02d}T00:00:00Z",
                "world": "hub",
            },
            "explicit_deliberation": {
                "alternatives": ["begin lifecycle", "remain unspawned"],
                "confidence": round(0.83 + index * 0.03, 2),
                "decision": "complete accelerated lifecycle",
                "summary": f"Public lifetime rationale {number}.",
            },
            "exposed_reasoning_refs": ([{
                "consent": "public",
                "uri": f"synthetic://d05/reasoning/{number:03d}",
            }] if index == 0 else []),
            "id": f"smoke-lifetime-{number:03d}",
            "lineage": "synthetic-smoke",
            "source_type": "synthetic_smoke",
            "terminal_event": {
                "event_type": "goal-complete-retirement",
                "final_state": deepcopy(ticks[-1]["state_after"]),
                "observed_at": f"2040-05-{number:02d}T00:05:00Z",
                "outcome": {"goals_completed": 1, "status": "retired"},
            },
            "ticks": ticks,
            "transcript": [
                {
                    "role": "system",
                    "speaker_id": "synthetic-lifecycle",
                    "text": f"Birth event for {agent_id}.",
                    "timestamp": f"2040-05-{number:02d}T00:00:00Z",
                },
                {
                    "role": "agent",
                    "speaker_id": agent_id,
                    "text": "My accelerated synthetic lifecycle is complete.",
                    "timestamp": f"2040-05-{number:02d}T00:05:00Z",
                },
            ],
        })
    return sources


def generate(
    sources: list[dict],
    output: Path,
    *,
    checkpoint: Path | None = None,
    resume: bool = False,
) -> list[dict]:
    fingerprint = sha256(sources)
    if resume:
        if checkpoint is None or not checkpoint.exists() or not output.exists():
            raise DatasetError("--resume requires an output and checkpoint")
        state = load_checkpoint(
            checkpoint, dataset_id=DATASET_ID, input_sha256=fingerprint
        )
        if state.get("complete"):
            records = read_jsonl(output)
            if len(records) != state.get("next_source_index"):
                raise DatasetError("checkpoint count does not match output")
            return records
    records = sorted(
        (normalize(source) for source in sources),
        key=lambda item: (item["observed_at"], item["record_id"]),
    )
    write_jsonl(output, records)
    if checkpoint:
        save_checkpoint(
            checkpoint,
            dataset_id=DATASET_ID,
            input_sha256=fingerprint,
            count=len(sources),
        )
    return records


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path)
    source.add_argument("--synthetic-smoke", type=int, metavar="COUNT")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--resume", action="store_true")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.synthetic_smoke is not None:
            if args.synthetic_smoke < 1:
                raise DatasetError("synthetic smoke count must be positive")
            sources = synthetic_sources(args.synthetic_smoke)
        else:
            sources = read_jsonl(args.input)
        records = generate(
            sources,
            args.output,
            checkpoint=args.checkpoint,
            resume=args.resume,
        )
    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({"dataset_id": DATASET_ID, "records": len(records)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
