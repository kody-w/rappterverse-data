#!/usr/bin/env python3
"""Generate deterministic D04 Verified Agentic Work Trajectories."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path, PurePosixPath

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

DATASET_ID = "d04"
CAPTURE = {
    "assistant_outputs": True,
    "complete": True,
    "final_outcomes": True,
    "patches": True,
    "public_safe": True,
    "system_prompts": True,
    "tool_arguments": True,
    "tool_calls": True,
    "tool_results": True,
    "user_prompts": True,
    "verifier_results": True,
}


def _task(value: object) -> dict:
    if not isinstance(value, dict):
        raise DatasetError("work trajectory task must be an object")
    task_id = value.get("task_id")
    instruction = value.get("instruction")
    if not isinstance(task_id, str) or not task_id:
        raise DatasetError("task.task_id is required")
    if not isinstance(instruction, str) or not instruction:
        raise DatasetError("task.instruction is required")
    return {
        "instruction": instruction,
        "repository": str(value.get("repository", "synthetic/repository")),
        "task_id": task_id,
    }


def _tool_calls(value: object) -> list[dict]:
    if not isinstance(value, list) or not value:
        raise DatasetError("work trajectory requires tool_calls")
    calls = []
    for sequence, call in enumerate(value):
        if not isinstance(call, dict):
            raise DatasetError("tool call must be an object")
        call_id = call.get("call_id")
        tool_name = call.get("tool_name")
        if not isinstance(call_id, str) or not call_id:
            raise DatasetError("tool call requires call_id")
        if not isinstance(tool_name, str) or not tool_name:
            raise DatasetError("tool call requires tool_name")
        started_at = timestamp(call.get("started_at"))
        completed_at = timestamp(call.get("completed_at"))
        if completed_at < started_at:
            raise DatasetError("tool call completed_at precedes started_at")
        calls.append({
            "arguments": call.get("arguments", {}),
            "call_id": call_id,
            "completed_at": completed_at,
            "result": call.get("result"),
            "sequence": sequence,
            "started_at": started_at,
            "status": str(call.get("status", "succeeded")),
            "tool_name": tool_name,
        })
    return calls


def _patches(value: object) -> list[dict]:
    if not isinstance(value, list) or not value:
        raise DatasetError("work trajectory requires patches")
    patches = []
    for sequence, patch in enumerate(value):
        if not isinstance(patch, dict):
            raise DatasetError("patch must be an object")
        path = patch.get("path")
        before = patch.get("before_content")
        after = patch.get("after_content")
        unified_diff = patch.get("unified_diff")
        applied = patch.get("applied", True)
        if (
            not isinstance(path, str)
            or not path
            or PurePosixPath(path).is_absolute()
            or ".." in PurePosixPath(path).parts
        ):
            raise DatasetError("patch path must be safe and repository-relative")
        if (
            not all(isinstance(item, str) for item in (before, after, unified_diff))
            or not unified_diff
        ):
            raise DatasetError("patch content and unified_diff must be strings")
        if not isinstance(applied, bool):
            raise DatasetError("patch applied must be boolean")
        patches.append({
            "after_content": after,
            "after_sha256": sha256(after),
            "applied": applied,
            "before_content": before,
            "before_sha256": sha256(before),
            "patch_id": str(patch.get("patch_id", f"patch-{sequence + 1:03d}")),
            "path": path,
            "sequence": sequence,
            "unified_diff": unified_diff,
        })
    return patches


def _verifier_evidence(value: object) -> list[dict]:
    if not isinstance(value, list) or not value:
        raise DatasetError("work trajectory requires verifier_evidence")
    evidence = []
    for sequence, result in enumerate(value):
        if not isinstance(result, dict):
            raise DatasetError("verifier evidence must be an object")
        command = result.get("command")
        output = result.get("output")
        exit_code = result.get("exit_code")
        if not isinstance(command, str) or not command:
            raise DatasetError("verifier command is required")
        if not isinstance(output, str):
            raise DatasetError("verifier output must be visible text")
        if isinstance(exit_code, bool) or not isinstance(exit_code, int):
            raise DatasetError("verifier exit_code must be an integer")
        evidence.append({
            "command": command,
            "exit_code": exit_code,
            "name": str(result.get("name", f"verifier-{sequence + 1}")),
            "output": output,
            "output_sha256": sha256(output),
            "passed": exit_code == 0,
            "sequence": sequence,
        })
    return evidence


def normalize(source: dict) -> dict:
    source_id = str(source.get("source_id", source.get("id", "")))
    if not source_id:
        raise DatasetError("work trajectory requires an id")
    started_at = timestamp(source.get("started_at", source.get("timestamp")))
    completed_at = timestamp(source.get("completed_at"))
    if completed_at < started_at:
        raise DatasetError("trajectory completed_at precedes started_at")
    outcome = source.get("outcome")
    if not isinstance(outcome, dict) or outcome.get("status") not in {
        "succeeded",
        "failed",
        "partial",
    }:
        raise DatasetError("outcome requires succeeded, failed, or partial status")
    if not isinstance(outcome.get("summary"), str) or not outcome["summary"]:
        raise DatasetError("outcome.summary is required")
    artifact_refs = outcome.get("artifact_refs", [])
    if not isinstance(artifact_refs, list):
        raise DatasetError("outcome.artifact_refs must be a list")

    actor_id = str(source.get("actor_id", "synthetic-worker"))
    lineage = str(source.get("lineage", "owned-synthetic"))
    content_sha256 = sha256(source)
    public_deliberation = deliberation(
        source.get("explicit_deliberation", source.get("deliberation")),
        default_decision=str(outcome["status"]),
    )
    if public_deliberation["status"] != "explicit":
        raise DatasetError("work trajectory requires explicit deliberation")
    record = {
        "actors": [actor_id],
        "dataset_id": DATASET_ID,
        "deliberation": public_deliberation,
        "observed_at": started_at,
        "record_id": stable_id(DATASET_ID, lineage, source_id, content_sha256),
        "schema": "rappterverse.d04-record/v1",
        "source": {
            "content_sha256": content_sha256,
            "lineage": lineage,
            "source_id": source_id,
            "source_type": str(source.get("source_type", "owned_synthetic_work")),
        },
        "transcript": transcript(
            source.get("transcript"),
            default_speaker=actor_id,
            default_timestamp=started_at,
            default_text=str(source.get("public_statement", "Completed work episode.")),
        ),
        "work_trajectory": {
            "capture": dict(CAPTURE),
            "completed_at": completed_at,
            "outcome": {
                "artifact_refs": [str(ref) for ref in artifact_refs],
                "status": outcome["status"],
                "summary": outcome["summary"],
            },
            "patches": _patches(source.get("patches")),
            "started_at": started_at,
            "task": _task(source.get("task")),
            "tool_calls": _tool_calls(source.get("tool_calls")),
            "verifier_evidence": _verifier_evidence(
                source.get("verifier_evidence")
            ),
        },
        "world": "agentic-workbench",
    }
    refs = public_reasoning_refs(source.get("exposed_reasoning_refs"))
    if refs:
        record["exposed_reasoning_refs"] = refs
    return record


def synthetic_sources(count: int = 3) -> list[dict]:
    sources = []
    for index in range(count):
        number = index + 1
        before = f"value = {number}\n"
        after = f"value = {number + 1}\n"
        sources.append({
            "actor_id": f"synthetic-worker-{number:03d}",
            "completed_at": f"2040-04-{number:02d}T00:03:00Z",
            "explicit_deliberation": {
                "alternatives": ["leave unchanged", "apply verified increment"],
                "confidence": round(0.82 + index * 0.03, 2),
                "decision": "apply verified increment",
                "summary": f"Public work rationale {number}.",
            },
            "exposed_reasoning_refs": ([{
                "consent": "public",
                "uri": f"synthetic://d04/reasoning/{number:03d}",
            }] if index == 1 else []),
            "id": f"smoke-work-{number:03d}",
            "lineage": "synthetic-smoke",
            "outcome": {
                "artifact_refs": [f"synthetic://d04/artifact/{number:03d}"],
                "status": "succeeded",
                "summary": f"Synthetic task {number} passed verification.",
            },
            "patches": [{
                "after_content": after,
                "before_content": before,
                "path": f"src/example_{number}.py",
                "unified_diff": (
                    f"--- a/src/example_{number}.py\n"
                    f"+++ b/src/example_{number}.py\n"
                    f"@@ -1 +1 @@\n-value = {number}\n+value = {number + 1}\n"
                ),
            }],
            "source_type": "synthetic_smoke",
            "started_at": f"2040-04-{number:02d}T00:00:00Z",
            "task": {
                "instruction": f"Increment synthetic value {number}.",
                "repository": "synthetic/workbench",
                "task_id": f"task-{number:03d}",
            },
            "tool_calls": [{
                "arguments": {"path": f"src/example_{number}.py"},
                "call_id": f"call-{number:03d}",
                "completed_at": f"2040-04-{number:02d}T00:01:10Z",
                "result": {"content": before},
                "started_at": f"2040-04-{number:02d}T00:01:00Z",
                "status": "succeeded",
                "tool_name": "read_file",
            }],
            "transcript": [
                {
                    "role": "human",
                    "speaker_id": "synthetic-user",
                    "text": f"Increment synthetic value {number}.",
                    "timestamp": f"2040-04-{number:02d}T00:00:00Z",
                },
                {
                    "role": "agent",
                    "speaker_id": f"synthetic-worker-{number:03d}",
                    "text": "I will make the smallest verified change.",
                    "timestamp": f"2040-04-{number:02d}T00:00:30Z",
                },
            ],
            "verifier_evidence": [{
                "command": f"python3 -m unittest synthetic_test_{number}",
                "exit_code": 0,
                "name": "unit-test",
                "output": "Ran 1 test\nOK\n",
            }],
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
