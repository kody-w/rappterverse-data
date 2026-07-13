#!/usr/bin/env python3
"""Generate deterministic D07 conservation and ordering tapes."""

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

DATASET_ID = "d07"
DATASET_SLUG = "d07-conservation-order"
ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "datasets" / DATASET_SLUG / "config.json"


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _record_rng(seed: int, index: int) -> random.Random:
    digest = hashlib.sha256(f"{DATASET_ID}:{seed}:{index}".encode()).digest()
    return random.Random(int.from_bytes(digest, "big"))


def _record_id(seed: int, index: int) -> str:
    digest = hashlib.sha256(f"{seed}:{index}".encode()).hexdigest()[:12]
    return f"d07-{index:06d}-{digest}"


def build_record(index: int, seed: int, event_count: int) -> dict[str, Any]:
    rng = _record_rng(seed, index)
    account_ids = [f"account-{letter}" for letter in "abcd"]
    initial_state = {
        account_id: rng.randint(24, 70) for account_id in account_ids
    }
    balances = dict(initial_state)
    tape: list[dict[str, Any]] = []
    previous_hash = "GENESIS"

    for sequence in range(event_count):
        source = rng.choice([key for key, value in balances.items() if value > 0])
        destination = rng.choice([key for key in account_ids if key != source])
        amount = rng.randint(1, min(15, balances[source]))
        event = {
            "amount": amount,
            "event_id": f"transfer-{sequence:03d}",
            "from": source,
            "kind": "transfer",
            "previous_event_hash": previous_hash,
            "sequence": sequence,
            "to": destination,
        }
        event_hash = hashlib.sha256(_canonical(event).encode()).hexdigest()
        event["event_hash"] = event_hash
        tape.append(event)
        balances[source] -= amount
        balances[destination] += amount
        previous_hash = event_hash

    initial_total = sum(initial_state.values())
    final_total = sum(balances.values())
    record = {
        "dataset_id": DATASET_ID,
        "initial_state": initial_state,
        "oracle": {
            "conserved": initial_total == final_total,
            "final_state": balances,
            "final_total": final_total,
            "initial_total": initial_total,
            "ordered": True,
            "terminal_event_hash": previous_hash,
        },
        "question": {
            "task": "Replay the tape in sequence and test the closed-system invariant.",
            "type": "ordered_conservation_replay",
        },
        "reasoning": {
            "decision": {
                "label": {
                    "conserved": initial_total == final_total,
                    "ordered": True,
                },
                "references": ["/oracle/conserved", "/oracle/ordered"],
            },
            "inference": {
                "references": [
                    "/tape",
                    "/oracle/initial_total",
                    "/oracle/final_total",
                ],
                "rule": "Apply each transfer once in sequence; transfers preserve the global integer total.",
            },
            "observation": {
                "facts": [
                    f"The tape contains {event_count} sequenced transfers.",
                    "Every event points to the preceding event hash.",
                ],
                "references": ["/initial_state", "/tape"],
            },
        },
        "record_id": _record_id(seed, index),
        "record_index": index,
        "seed": seed,
        "tape": tape,
    }
    record.update(
        synthetic_envelope(
            DATASET_ID,
            actors=["synthetic-ledger-operator-001"],
            content=record,
            decision="conserved_and_ordered",
            index=index,
            options=["conserved_and_ordered", "invariant_or_order_failure"],
            public_text=f"Replayed {event_count} synthetic transfers in canonical order.",
            seed=seed,
            summary="The public replay applies every transfer once and compares closed-system totals.",
            world="marketplace",
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
                int(config["defaults"]["events_per_tape"]),
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
