"""D10-local normalized-record helpers pending shared lake integration."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any


def _canonical(value: Any) -> str:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def synthetic_envelope(
    dataset_id: str,
    *,
    actors: list[str],
    content: Any,
    decision: str,
    index: int,
    options: list[str],
    public_text: str,
    seed: int,
    summary: str,
    world: str,
) -> dict[str, Any]:
    observed_at = (
        datetime(2040, int(dataset_id[1:]), 1, tzinfo=timezone.utc)
        + timedelta(minutes=index)
    ).isoformat(timespec="seconds").replace("+00:00", "Z")
    source_id = f"synthetic-{dataset_id}-{seed}-{index:06d}"
    return {
        "actors": actors,
        "dataset_id": dataset_id,
        "deliberation": {
            "confidence": 1.0,
            "decision": decision,
            "options_considered": options,
            "provenance": "synthetic_fixture",
            "status": "explicit",
            "summary": summary,
        },
        "exposed_reasoning_refs": [
            {
                "consent": "public",
                "kind": layer,
                "uri": f"synthetic://{dataset_id}/reasoning/{index:06d}/{layer}",
            }
            for layer in ("observation", "inference", "decision")
        ],
        "observed_at": observed_at,
        "schema": f"rappterverse.{dataset_id}-record/v1",
        "source": {
            "content_sha256": hashlib.sha256(_canonical(content).encode()).hexdigest(),
            "lineage": "synthetic-smoke",
            "source_id": source_id,
            "source_type": "synthetic_smoke",
        },
        "transcript": [
            {
                "role": "agent",
                "speaker_id": actors[0],
                "text": public_text,
                "timestamp": observed_at,
                "turn_id": "turn-001",
            }
        ],
        "world": world,
    }


def common_envelope_errors(record: object, dataset_id: str) -> list[str]:
    if not isinstance(record, dict):
        return ["record must be an object"]
    errors: list[str] = []
    if record.get("dataset_id") != dataset_id:
        errors.append("invalid dataset_id")
    if record.get("schema") != f"rappterverse.{dataset_id}-record/v1":
        errors.append("invalid schema")
    record_id = record.get("record_id")
    if not isinstance(record_id, str) or not record_id.startswith(f"{dataset_id}-"):
        errors.append("record_id must use the dataset prefix")
    actors = record.get("actors")
    if not isinstance(actors, list) or not actors or not all(
        isinstance(actor, str) and actor for actor in actors
    ):
        errors.append("actors must be a non-empty string list")
    observed_at = record.get("observed_at")
    try:
        parsed = datetime.fromisoformat(str(observed_at).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            raise ValueError
    except ValueError:
        errors.append("observed_at must be an ISO-8601 timestamp with timezone")
    source = record.get("source")
    if not isinstance(source, dict) or not all(
        source.get(key) for key in ("content_sha256", "source_id", "source_type")
    ):
        errors.append("source provenance is incomplete")
    transcript = record.get("transcript")
    if not isinstance(transcript, list) or not transcript:
        errors.append("transcript must be non-empty")
    else:
        for turn in transcript:
            if not isinstance(turn, dict) or not all(
                turn.get(key)
                for key in ("role", "speaker_id", "text", "timestamp", "turn_id")
            ):
                errors.append("transcript turn fields are incomplete")
                break
    deliberation = record.get("deliberation")
    if (
        not isinstance(deliberation, dict)
        or deliberation.get("status") not in {"explicit", "not_recorded"}
        or not deliberation.get("decision")
    ):
        errors.append("deliberation is invalid")
    refs = record.get("exposed_reasoning_refs")
    expected_kinds = {"observation", "inference", "decision"}
    if (
        not isinstance(refs, list)
        or len(refs) != 3
        or {ref.get("kind") for ref in refs if isinstance(ref, dict)} != expected_kinds
        or any(
            not isinstance(ref, dict)
            or ref.get("consent") != "public"
            or not ref.get("uri")
            for ref in refs
        )
    ):
        errors.append("three explicitly public reasoning references are required")
    if not isinstance(record.get("world"), str) or not record["world"]:
        errors.append("world must be a non-empty string")
    return errors
