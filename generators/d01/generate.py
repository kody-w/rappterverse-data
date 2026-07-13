#!/usr/bin/env python3
"""Generate deterministic D01 Civilization Ledger records."""

from __future__ import annotations

import argparse
import json
import sys
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

DATASET_ID = "d01"
ALLOWED_SOURCE_TYPES = {
    "legacy_action_export",
    "owned_synthetic_event",
    "rappterverse_owned_event",
    "synthetic_smoke",
}


def _unwrap(source: dict) -> tuple[dict, dict]:
    value = source.get("value")
    if isinstance(value, dict):
        provenance = {
            "content_sha256": str(source.get("contentSha256", sha256(value))),
            "first_seen_commit": source.get("firstSeenCommit"),
            "last_seen_commit": source.get("lastSeenCommit"),
            "lineage": str(source.get("lineage", "unknown")),
            "source_id": str(source.get("naturalId", value.get("id", ""))),
            "source_type": "legacy_action_export",
        }
        return value, provenance
    source_id = str(source.get("source_id", source.get("id", "")))
    return source, {
        "content_sha256": sha256(source),
        "first_seen_commit": source.get("commit"),
        "last_seen_commit": source.get("commit"),
        "lineage": str(source.get("lineage", "unassigned")),
        "source_id": source_id,
        "source_type": str(
            source.get("source_type", "rappterverse_owned_event")
        ),
    }


def normalize(source: dict) -> dict:
    value, provenance = _unwrap(source)
    source_id = provenance["source_id"]
    if not source_id:
        raise DatasetError("source event requires an id")
    if provenance["source_type"] not in ALLOWED_SOURCE_TYPES:
        raise DatasetError("D01 accepts only RAPPterverse-owned or synthetic sources")
    observed_at = timestamp(value.get("timestamp"))
    actor_id = str(value.get("agentId", value.get("actor_id", "unknown-agent")))
    event_type = str(value.get("type", value.get("event_type", "unknown")))
    world = str(value.get("world", value.get("world_id", "unknown")))
    outcome = value.get("outcome", {})
    if not isinstance(outcome, dict):
        raise DatasetError("event outcome must be an object")
    text = str(
        value.get("message")
        or value.get("description")
        or f"{actor_id} performed {event_type} in {world}."
    )
    record = {
        "actors": [actor_id],
        "dataset_id": DATASET_ID,
        "deliberation": deliberation(
            value.get("explicit_deliberation", value.get("deliberation")),
            default_decision=event_type,
        ),
        "event": {
            "after_ref": value.get("after_ref"),
            "before_ref": value.get("before_ref"),
            "event_type": event_type,
            "outcome": outcome,
            "source_event_id": source_id,
        },
        "observed_at": observed_at,
        "record_id": stable_id(
            DATASET_ID,
            provenance["lineage"],
            source_id,
            provenance["content_sha256"],
        ),
        "schema": "rappterverse.d01-record/v1",
        "source": provenance,
        "transcript": transcript(
            value.get("transcript"),
            default_speaker=actor_id,
            default_timestamp=observed_at,
            default_text=text,
        ),
        "world": world,
    }
    refs = public_reasoning_refs(value.get("exposed_reasoning_refs"))
    if refs:
        record["exposed_reasoning_refs"] = refs
    return record


def synthetic_sources(count: int = 3) -> list[dict]:
    event_types = ("move", "chat", "trade_offer")
    sources = []
    for index in range(count):
        number = index + 1
        event_type = event_types[index % len(event_types)]
        sources.append({
            "actor_id": f"smoke-agent-{number:03d}",
            "after_ref": f"state://smoke/frame-{number:03d}",
            "before_ref": f"state://smoke/frame-{number - 1:03d}",
            "event_type": event_type,
            "explicit_deliberation": {
                "alternatives": ["wait", event_type],
                "confidence": round(0.6 + index * 0.05, 2),
                "decision": event_type,
                "summary": f"Public smoke rationale {number}.",
            },
            "exposed_reasoning_refs": ([{
                "consent": "public",
                "kind": "synthetic_fixture",
                "uri": f"synthetic://d01/reasoning/{number:03d}",
            }] if index == 0 else []),
            "id": f"smoke-event-{number:03d}",
            "lineage": "synthetic-smoke",
            "outcome": {"status": "observed"},
            "source_type": "synthetic_smoke",
            "timestamp": f"2040-01-01T00:{index:02d}:00Z",
            "transcript": [{
                "role": "agent",
                "speaker_id": f"smoke-agent-{number:03d}",
                "text": f"Synthetic event {number}.",
            }],
            "world_id": ("hub", "gallery", "marketplace")[index % 3],
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
    if checkpoint is not None:
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
