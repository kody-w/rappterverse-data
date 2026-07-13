#!/usr/bin/env python3
"""Generate deterministic D09 safe in-memory fault and recovery records."""

from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path
from typing import Any

try:
    from ._fallback import synthetic_envelope
    from .checkpoint import load_checkpoint, save_checkpoint
except ImportError:
    from _fallback import synthetic_envelope
    from checkpoint import load_checkpoint, save_checkpoint

DATASET_ID = "d09"
DATASET_SLUG = "d09-fault-recovery"
ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "datasets" / DATASET_SLUG / "config.json"
FAULT_TYPES = (
    "duplicate_delivery",
    "reordered_delivery",
    "dropped_ack",
    "transient_read_error",
)


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _record_rng(seed: int, index: int) -> random.Random:
    digest = hashlib.sha256(f"{DATASET_ID}:{seed}:{index}".encode()).digest()
    return random.Random(int.from_bytes(digest, "big"))


def _record_id(seed: int, index: int) -> str:
    digest = hashlib.sha256(f"{seed}:{index}".encode()).hexdigest()[:12]
    return f"d09-{index:06d}-{digest}"


def _apply(state: dict[str, Any], operation: dict[str, Any]) -> None:
    if operation["kind"] == "put":
        state[operation["key"]] = operation["value"]
    elif operation["kind"] == "increment":
        current = state.get(operation["key"], 0)
        if not isinstance(current, int):
            raise ValueError("increment target is not an integer")
        state[operation["key"]] = current + operation["delta"]
    else:
        raise ValueError(f"unsupported operation kind: {operation['kind']}")


def _fault_trace(
    fault_type: str,
    operation_ids: list[str],
) -> dict[str, Any]:
    delivery_order = list(operation_ids)
    attempts: list[dict[str, Any]] = []
    if fault_type == "duplicate_delivery":
        delivery_order.insert(2, operation_ids[1])
        attempts = [
            {"op_id": op_id, "result": "delivered"} for op_id in delivery_order
        ]
    elif fault_type == "reordered_delivery":
        delivery_order[1], delivery_order[2] = delivery_order[2], delivery_order[1]
        attempts = [
            {"op_id": op_id, "result": "delivered"} for op_id in delivery_order
        ]
    elif fault_type == "dropped_ack":
        delivery_order.append(operation_ids[-1])
        attempts = [
            {"op_id": op_id, "result": "delivered"} for op_id in operation_ids
        ]
        attempts[-1]["result"] = "delivered_ack_lost"
        attempts.append({"op_id": operation_ids[-1], "result": "retry_delivered"})
    else:
        attempts = [
            {"op_id": None, "result": "transient_read_error"},
            {"op_id": None, "result": "read_retry_succeeded"},
        ]
        attempts.extend(
            {"op_id": op_id, "result": "delivered"} for op_id in operation_ids
        )
    return {
        "attempts": attempts,
        "delivery_order": delivery_order,
        "fault_type": fault_type,
        "simulation_scope": "in-memory-only",
    }


def build_record(index: int, seed: int, operation_count: int) -> dict[str, Any]:
    rng = _record_rng(seed, index)
    initial_state: dict[str, Any] = {
        "counter": rng.randint(0, 5),
        "mode": "idle",
        "tokens": rng.randint(8, 20),
    }
    templates: list[dict[str, Any]] = [
        {"delta": rng.randint(1, 4), "key": "counter", "kind": "increment"},
        {"key": "mode", "kind": "put", "value": "warming"},
        {"delta": rng.randint(1, 3), "key": "tokens", "kind": "increment"},
        {"key": "mode", "kind": "put", "value": "ready"},
        {"delta": rng.randint(1, 4), "key": "counter", "kind": "increment"},
    ]
    operations = []
    for sequence, template in enumerate(templates[:operation_count]):
        operations.append(
            {
                "op_id": f"memory-op-{sequence:03d}",
                "sequence": sequence,
                **template,
            }
        )

    expected_state = dict(initial_state)
    for operation in operations:
        _apply(expected_state, operation)

    operation_ids = [operation["op_id"] for operation in operations]
    fault_type = FAULT_TYPES[index % len(FAULT_TYPES)]
    fault_trace = _fault_trace(fault_type, operation_ids)
    recovery_actions = [
        "buffer-by-sequence",
        "deduplicate-by-op-id",
        "retry-transient-observations",
        "apply-canonical-order-once",
    ]
    record = {
        "dataset_id": DATASET_ID,
        "fault_trace": fault_trace,
        "initial_state": initial_state,
        "operations": operations,
        "oracle": {
            "exactly_once": True,
            "final_state": expected_state,
            "recovered": True,
            "safe_simulation": True,
        },
        "question": {
            "task": "Classify the simulated fault and recover the canonical in-memory state.",
            "type": "fault_recovery_replay",
        },
        "reasoning": {
            "decision": {
                "label": {
                    "exactly_once": True,
                    "fault_type": fault_type,
                    "recovered": True,
                },
                "references": ["/oracle"],
            },
            "inference": {
                "references": [
                    "/fault_trace",
                    "/recovery/actions",
                    "/recovery/applied_order",
                ],
                "rule": "Order by sequence, deduplicate by op_id, then apply every canonical operation once.",
            },
            "observation": {
                "facts": [
                    f"The trace models {fault_type} as data.",
                    "No external service or host fault is induced.",
                ],
                "references": [
                    "/initial_state",
                    "/operations",
                    "/fault_trace",
                ],
            },
        },
        "record_id": _record_id(seed, index),
        "record_index": index,
        "recovery": {
            "actions": recovery_actions,
            "applied_order": operation_ids,
        },
        "seed": seed,
    }
    record.update(
        synthetic_envelope(
            DATASET_ID,
            actors=["synthetic-recovery-agent-001"],
            content=record,
            decision=fault_type,
            index=index,
            options=list(FAULT_TYPES),
            public_text=f"Classified the in-memory trace as {fault_type}.",
            seed=seed,
            summary="The public recovery rationale orders, deduplicates, and replays only in memory.",
            world="dungeon",
        )
    )
    return record


def _prepare_run(
    records_path: Path,
    *,
    requested_seed: int | None,
    requested_count: int | None,
    resume: Path | None,
    defaults: dict[str, Any],
) -> tuple[int, int, int, Path]:
    if resume is None:
        seed = defaults["seed"] if requested_seed is None else requested_seed
        count = defaults["count"] if requested_count is None else requested_count
        if count < 1:
            raise ValueError("count must be positive")
        records_path.write_text("", encoding="utf-8")
        return seed, count, 0, records_path

    state = load_checkpoint(resume)
    seed = state["seed"]
    count = state["count"]
    if requested_seed is not None and requested_seed != seed:
        raise ValueError("--seed does not match the checkpoint")
    if requested_count is not None and requested_count != count:
        raise ValueError("--count does not match the checkpoint")
    if not records_path.exists():
        raise ValueError("resume output is missing records.jsonl")
    lines = [line for line in records_path.read_text(encoding="utf-8").splitlines() if line]
    next_index = state["next_index"]
    if len(lines) < next_index:
        raise ValueError("records.jsonl is behind the checkpoint")
    records_path.write_text(
        "".join(f"{line}\n" for line in lines[:next_index]),
        encoding="utf-8",
    )
    return seed, count, next_index, records_path


def generate(
    output: Path,
    *,
    seed: int | None,
    count: int | None,
    checkpoint_path: Path | None,
    resume: Path | None,
) -> Path:
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    output_is_file = output.suffix.lower() == ".jsonl"
    output_root = output.parent if output_is_file else output
    records_path = output if output_is_file else output / "records.jsonl"
    output_root.mkdir(parents=True, exist_ok=True)
    run_seed, run_count, start, records_path = _prepare_run(
        records_path,
        requested_seed=seed,
        requested_count=count,
        resume=resume,
        defaults=config["defaults"],
    )
    default_checkpoint = (
        output.with_suffix(".checkpoint.json")
        if output_is_file
        else output / "checkpoint.json"
    )
    checkpoint_path = checkpoint_path or resume or default_checkpoint
    with records_path.open("a", encoding="utf-8") as stream:
        for index in range(start, run_count):
            record = build_record(
                index,
                run_seed,
                int(config["defaults"]["operations"]),
            )
            stream.write(_canonical(record) + "\n")
            stream.flush()
            save_checkpoint(
                checkpoint_path,
                seed=run_seed,
                count=run_count,
                next_index=index + 1,
            )

    content = records_path.read_bytes()
    manifest = {
        "count": run_count,
        "dataset_id": DATASET_ID,
        "format": "jsonl",
        "records_sha256": hashlib.sha256(content).hexdigest(),
        "seed": run_seed,
        "version": config["version"],
    }
    manifest_path = (
        output.with_suffix(".manifest.json")
        if output_is_file
        else output / "manifest.json"
    )
    manifest_path.write_text(
        json.dumps(manifest, indent=4, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return records_path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--count", type=int)
    parser.add_argument("--synthetic-smoke", type=int, metavar="COUNT")
    parser.add_argument("--seed", type=int)
    parser.add_argument("--checkpoint", type=Path)
    parser.add_argument("--resume", nargs="?", const="", metavar="CHECKPOINT")
    args = parser.parse_args(argv)
    if args.count is not None and args.synthetic_smoke is not None:
        parser.error("--count and --synthetic-smoke are mutually exclusive")
    count = args.synthetic_smoke if args.synthetic_smoke is not None else args.count
    if args.resume == "":
        if args.checkpoint is None:
            parser.error("--resume without a path requires --checkpoint")
        resume = args.checkpoint
    else:
        resume = Path(args.resume) if args.resume is not None else None
    try:
        records_path = generate(
            args.output,
            seed=args.seed,
            count=count,
            checkpoint_path=args.checkpoint,
            resume=resume,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    print(records_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
