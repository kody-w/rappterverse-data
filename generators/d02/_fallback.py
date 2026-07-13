"""Small local utilities used until the shared data-lake helpers land."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


class DatasetError(ValueError):
    """Raised when source or generated dataset data is invalid."""


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )


def sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def stable_id(dataset_id: str, *parts: object) -> str:
    digest = sha256([dataset_id, *parts])
    return f"{dataset_id}-{digest[:20]}"


def timestamp(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise DatasetError("timestamp must be a non-empty ISO-8601 string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise DatasetError(f"invalid timestamp: {value}") from exc
    if parsed.tzinfo is None:
        raise DatasetError("timestamp must include a timezone")
    return parsed.astimezone(timezone.utc).isoformat(timespec="seconds").replace(
        "+00:00", "Z"
    )


def read_jsonl(path: Path) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise DatasetError(f"{path}:{line_number}: invalid JSON") from exc
            if not isinstance(value, dict):
                raise DatasetError(f"{path}:{line_number}: record must be an object")
            records.append(value)
    return records


def write_jsonl(path: Path, records: Iterable[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8", newline="\n") as stream:
        for record in records:
            stream.write(canonical_json(record))
            stream.write("\n")


def transcript(
    value: object,
    *,
    default_speaker: str,
    default_timestamp: str,
    default_text: str,
) -> list[dict]:
    turns = value if isinstance(value, list) else []
    if not turns and default_text:
        turns = [{"speaker_id": default_speaker, "text": default_text}]
    normalized = []
    for index, turn in enumerate(turns):
        if not isinstance(turn, dict):
            raise DatasetError("transcript turns must be objects")
        text = turn.get("text") or turn.get("message")
        if not isinstance(text, str) or not text.strip():
            raise DatasetError("transcript text must be non-empty")
        role = str(turn.get("role", "agent"))
        if role not in {"agent", "human", "npc", "system", "tool"}:
            raise DatasetError(f"unsupported transcript role: {role}")
        normalized.append({
            "role": role,
            "speaker_id": str(turn.get("speaker_id", default_speaker)),
            "text": text.strip(),
            "timestamp": timestamp(turn.get("timestamp", default_timestamp)),
            "turn_id": str(turn.get("turn_id", f"turn-{index + 1:03d}")),
        })
    if not normalized:
        raise DatasetError("a normalized record requires a public transcript")
    return normalized


def deliberation(value: object, *, default_decision: str) -> dict:
    if not isinstance(value, dict):
        return {
            "confidence": None,
            "decision": default_decision,
            "options_considered": [],
            "provenance": "not_available",
            "status": "not_recorded",
            "summary": "No explicit public rationale was recorded.",
        }
    confidence = value.get("confidence")
    if confidence is not None and (
        isinstance(confidence, bool)
        or not isinstance(confidence, (int, float))
        or not 0 <= confidence <= 1
    ):
        raise DatasetError("deliberation confidence must be between 0 and 1")
    summary = value.get("summary") or value.get("rationale")
    if not isinstance(summary, str) or not summary.strip():
        raise DatasetError("explicit deliberation requires a summary")
    options = value.get("options_considered", value.get("alternatives", []))
    if not isinstance(options, list) or not all(isinstance(item, str) for item in options):
        raise DatasetError("deliberation options must be strings")
    return {
        "confidence": confidence,
        "decision": str(value.get("decision", default_decision)),
        "options_considered": options,
        "provenance": "participant_public_statement",
        "status": "explicit",
        "summary": summary.strip(),
    }


def public_reasoning_refs(value: object) -> list[dict]:
    if not isinstance(value, list):
        return []
    refs = []
    for item in value:
        if not isinstance(item, dict) or item.get("consent") != "public":
            continue
        uri = item.get("uri")
        if isinstance(uri, str) and uri:
            refs.append({
                "consent": "public",
                "kind": str(item.get("kind", "participant_exposed")),
                "uri": uri,
            })
    return refs


def save_checkpoint(
    path: Path,
    *,
    dataset_id: str,
    input_sha256: str,
    count: int,
) -> None:
    value = {
        "complete": True,
        "dataset_id": dataset_id,
        "input_sha256": input_sha256,
        "next_source_index": count,
        "schema": f"rappterverse.{dataset_id}-checkpoint/v1",
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=4, sort_keys=True) + "\n", encoding="utf-8")


def load_checkpoint(path: Path, *, dataset_id: str, input_sha256: str) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise DatasetError(f"invalid checkpoint: {path}") from exc
    if value.get("dataset_id") != dataset_id:
        raise DatasetError("checkpoint belongs to a different dataset")
    if value.get("input_sha256") != input_sha256:
        raise DatasetError("checkpoint input fingerprint does not match")
    return value


def common_errors(record: object, dataset_id: str) -> list[str]:
    if not isinstance(record, dict):
        return ["record must be an object"]
    errors = []
    if record.get("schema") != f"rappterverse.{dataset_id}-record/v1":
        errors.append("invalid schema")
    if record.get("dataset_id") != dataset_id:
        errors.append("invalid dataset_id")
    if not isinstance(record.get("record_id"), str) or not record["record_id"].startswith(
        f"{dataset_id}-"
    ):
        errors.append("record_id must be a string")
    try:
        timestamp(record.get("observed_at"))
    except DatasetError as exc:
        errors.append(str(exc))
    source = record.get("source")
    if not isinstance(source, dict):
        errors.append("source must be an object")
    elif not all(source.get(key) for key in ("content_sha256", "source_id", "source_type")):
        errors.append("source requires content_sha256, source_id, and source_type")
    actors = record.get("actors")
    if (
        not isinstance(actors, list)
        or not actors
        or not all(isinstance(actor, str) and actor for actor in actors)
    ):
        errors.append("actors must be a non-empty list")
    turns = record.get("transcript")
    if not isinstance(turns, list) or not turns:
        errors.append("transcript must be a non-empty list")
    else:
        previous_turn_at = None
        for turn in turns:
            if not isinstance(turn, dict):
                errors.append("transcript turns must be objects")
                continue
            if (
                turn.get("role") not in {"agent", "human", "npc", "system", "tool"}
                or not isinstance(turn.get("speaker_id"), str)
                or not turn.get("speaker_id")
                or not isinstance(turn.get("text"), str)
                or not turn.get("text")
                or not isinstance(turn.get("turn_id"), str)
                or not turn.get("turn_id")
            ):
                errors.append("transcript turn fields are invalid")
            try:
                turn_at = timestamp(turn.get("timestamp"))
                if previous_turn_at and turn_at < previous_turn_at:
                    errors.append("transcript turns must be chronological")
                previous_turn_at = turn_at
            except DatasetError as exc:
                errors.append(str(exc))
    decision = record.get("deliberation")
    if not isinstance(decision, dict):
        errors.append("deliberation must be an object")
    elif decision.get("status") not in {"explicit", "not_recorded"}:
        errors.append("deliberation status is invalid")
    elif decision.get("status") == "explicit" and not decision.get("summary"):
        errors.append("explicit deliberation requires a summary")
    elif not decision.get("decision"):
        errors.append("deliberation decision is required")
    refs = record.get("exposed_reasoning_refs", [])
    if not isinstance(refs, list):
        errors.append("exposed_reasoning_refs must be a list when present")
    elif any(
        not isinstance(ref, dict)
        or ref.get("consent") != "public"
        or not ref.get("uri")
        for ref in refs
    ):
        errors.append("reasoning references must be explicitly public and have a URI")
    return errors


def apply_operation(state: dict, operation: object) -> dict:
    """Apply one small deterministic operation to a copied JSON object."""
    if not isinstance(state, dict) or not isinstance(operation, dict):
        raise DatasetError("state and operation must be objects")
    path = operation.get("path")
    if not isinstance(path, list) or not path or not all(
        isinstance(part, str) and part for part in path
    ):
        raise DatasetError("operation path must contain non-empty strings")
    op = operation.get("op")
    if op not in {"set", "increment"}:
        raise DatasetError("operation op must be set or increment")
    result = deepcopy(state)
    target = result
    for part in path[:-1]:
        child = target.get(part)
        if not isinstance(child, dict):
            raise DatasetError(f"operation parent does not exist: {part}")
        target = child
    key = path[-1]
    if op == "set":
        if key not in target:
            raise DatasetError(f"set target does not exist: {key}")
        target[key] = deepcopy(operation.get("value"))
    else:
        current = target.get(key)
        amount = operation.get("value")
        if (
            isinstance(current, bool)
            or not isinstance(current, (int, float))
            or isinstance(amount, bool)
            or not isinstance(amount, (int, float))
        ):
            raise DatasetError("increment requires numeric current and delta values")
        target[key] = current + amount
    return result


def replay_branch(
    base_state: dict,
    *,
    intervention: dict | None,
    shared_steps: list[dict],
) -> dict:
    state = deepcopy(base_state)
    initial_hash = sha256(state)
    if intervention is not None:
        state = apply_operation(state, intervention)
    post_intervention_hash = sha256(state)
    replay = []
    for index, step in enumerate(shared_steps):
        before_hash = sha256(state)
        state = apply_operation(state, step)
        replay.append({
            "after_state_sha256": sha256(state),
            "before_state_sha256": before_hash,
            "operation": deepcopy(step),
            "sequence": index,
        })
    return {
        "final_state": state,
        "final_state_sha256": sha256(state),
        "initial_state_sha256": initial_hash,
        "intervention_applied": intervention is not None,
        "post_intervention_state_sha256": post_intervention_hash,
        "replay": replay,
    }


def causal_contrast(control: object, treatment: object, path: str = "") -> list[dict]:
    """Return deterministic leaf-level differences between two JSON values."""
    if isinstance(control, dict) and isinstance(treatment, dict):
        differences = []
        for key in sorted(set(control) | set(treatment)):
            child_path = f"{path}.{key}" if path else key
            differences.extend(
                causal_contrast(control.get(key), treatment.get(key), child_path)
            )
        return differences
    if control == treatment:
        return []
    contrast = {
        "control_value": control,
        "path": path,
        "treatment_value": treatment,
    }
    if (
        not isinstance(control, bool)
        and isinstance(control, (int, float))
        and not isinstance(treatment, bool)
        and isinstance(treatment, (int, float))
    ):
        contrast["numeric_delta"] = treatment - control
    return [contrast]
