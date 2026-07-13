#!/usr/bin/env python3
"""Generate deterministic D02 Counterfactual Multiverse pairs."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

try:
    from ._fallback import (
        DatasetError,
        causal_contrast,
        deliberation,
        load_checkpoint,
        public_reasoning_refs,
        read_jsonl,
        replay_branch,
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
        causal_contrast,
        deliberation,
        load_checkpoint,
        public_reasoning_refs,
        read_jsonl,
        replay_branch,
        save_checkpoint,
        sha256,
        stable_id,
        timestamp,
        transcript,
        write_jsonl,
    )

DATASET_ID = "d02"


def normalize(source: dict) -> dict:
    source_id = str(source.get("source_id", source.get("id", "")))
    if not source_id:
        raise DatasetError("counterfactual scenario requires an id")
    observed_at = timestamp(source.get("observed_at", source.get("timestamp")))
    base_state = source.get("base_state")
    intervention = source.get("intervention")
    shared_steps = source.get("shared_replay_steps", [])
    if not isinstance(base_state, dict) or not isinstance(intervention, dict):
        raise DatasetError("base_state and intervention must be objects")
    if not isinstance(shared_steps, list) or not all(
        isinstance(step, dict) for step in shared_steps
    ):
        raise DatasetError("shared_replay_steps must contain objects")

    control = replay_branch(
        base_state,
        intervention=None,
        shared_steps=shared_steps,
    )
    treatment = replay_branch(
        base_state,
        intervention=intervention,
        shared_steps=shared_steps,
    )
    if (
        control["post_intervention_state_sha256"]
        != control["initial_state_sha256"]
    ):
        raise DatasetError("control branch changed during intervention phase")
    if (
        treatment["post_intervention_state_sha256"]
        == treatment["initial_state_sha256"]
    ):
        raise DatasetError("treatment intervention must change state")

    actor_id = str(source.get("actor_id", "synthetic-intervention-engine"))
    lineage = str(source.get("lineage", "synthetic-owned"))
    content_sha256 = sha256(source)
    public_deliberation = deliberation(
        source.get("explicit_deliberation", source.get("deliberation")),
        default_decision="apply isolated intervention",
    )
    if public_deliberation["status"] != "explicit":
        raise DatasetError("counterfactual pair requires explicit deliberation")
    pair = {
        "base_state": base_state,
        "base_state_sha256": sha256(base_state),
        "causal_contrast": causal_contrast(
            control["final_state"], treatment["final_state"]
        ),
        "control": control,
        "intervention": intervention,
        "isolated_intervention": True,
        "shared_replay_steps": shared_steps,
        "treatment": treatment,
    }
    record = {
        "actors": [actor_id],
        "counterfactual_pair": pair,
        "dataset_id": DATASET_ID,
        "deliberation": public_deliberation,
        "observed_at": observed_at,
        "record_id": stable_id(DATASET_ID, lineage, source_id, content_sha256),
        "schema": "rappterverse.d02-record/v1",
        "source": {
            "content_sha256": content_sha256,
            "lineage": lineage,
            "source_id": source_id,
            "source_type": str(
                source.get("source_type", "owned_synthetic_scenario")
            ),
        },
        "transcript": transcript(
            source.get("transcript"),
            default_speaker=actor_id,
            default_timestamp=observed_at,
            default_text=str(
                source.get(
                    "public_statement",
                    "Replaying one control and one isolated treatment branch.",
                )
            ),
        ),
        "world": str(source.get("world", "synthetic-multiverse")),
    }
    refs = public_reasoning_refs(source.get("exposed_reasoning_refs"))
    if refs:
        record["exposed_reasoning_refs"] = refs
    return record


def synthetic_sources(count: int = 3) -> list[dict]:
    paths = ("population", "prosperity", "trust")
    sources = []
    for index in range(count):
        number = index + 1
        path = paths[index % len(paths)]
        sources.append({
            "actor_id": "synthetic-intervention-engine",
            "base_state": {
                "climate": "clear",
                "metrics": {
                    "population": 10,
                    "prosperity": 20,
                    "trust": 30,
                },
                "tick": 0,
            },
            "explicit_deliberation": {
                "alternatives": ["no intervention", f"increase {path}"],
                "confidence": round(0.80 + index * 0.03, 2),
                "decision": f"increase {path}",
                "summary": f"Public causal test rationale {number}.",
            },
            "exposed_reasoning_refs": ([{
                "consent": "public",
                "kind": "synthetic_fixture",
                "uri": f"synthetic://d02/reasoning/{number:03d}",
            }] if index == 0 else []),
            "id": f"smoke-pair-{number:03d}",
            "intervention": {
                "op": "increment",
                "path": ["metrics", path],
                "value": number,
            },
            "lineage": "synthetic-smoke",
            "shared_replay_steps": [
                {"op": "increment", "path": ["tick"], "value": 1},
                {"op": "set", "path": ["climate"], "value": "twilight"},
            ],
            "source_type": "synthetic_smoke",
            "timestamp": f"2040-02-01T00:{index:02d}:00Z",
            "transcript": [{
                "role": "system",
                "speaker_id": "synthetic-intervention-engine",
                "text": f"Create isolated branch pair {number}.",
            }],
            "world": "synthetic-multiverse",
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
