#!/usr/bin/env python3
"""Generate deterministic D06 paired-world social causality records."""

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

DATASET_ID = "d06"
DATASET_SLUG = "d06-social-causality"
ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "datasets" / DATASET_SLUG / "config.json"


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _record_rng(seed: int, index: int) -> random.Random:
    digest = hashlib.sha256(f"{DATASET_ID}:{seed}:{index}".encode()).digest()
    return random.Random(int.from_bytes(digest, "big"))


def _record_id(seed: int, index: int) -> str:
    digest = hashlib.sha256(f"{seed}:{index}".encode()).hexdigest()[:12]
    return f"d06-{index:06d}-{digest}"


def _clamp(value: int) -> int:
    return max(0, min(100, value))


def build_record(index: int, seed: int, ticks: int) -> dict[str, Any]:
    rng = _record_rng(seed, index)
    common_noise = [
        {
            "resource_shock": rng.randint(-2, 2),
            "social_shock": rng.randint(-3, 3),
            "tick": tick,
        }
        for tick in range(ticks)
    ]
    noise_digest = hashlib.sha256(_canonical(common_noise).encode()).hexdigest()
    baseline = rng.randint(32, 58)
    shared_shift = sum(
        event["social_shock"] + event["resource_shock"] for event in common_noise
    )
    control_score = _clamp(baseline + shared_shift)
    intervention_lift = rng.randint(5, 14)
    treatment_score = _clamp(control_score + intervention_lift)

    arm_order = ["control", "treatment"]
    rng.shuffle(arm_order)
    worlds = []
    for world_label, arm in zip(("world-a", "world-b"), arm_order):
        score = control_score if arm == "control" else treatment_score
        worlds.append(
            {
                "arm": arm,
                "common_noise_digest": noise_digest,
                "common_noise_ref": "/pair/common_noise",
                "intervention": {
                    "bridge_prompt": arm == "treatment",
                    "strength": intervention_lift if arm == "treatment" else 0,
                },
                "outcome": {
                    "cooperation_score": score,
                    "successful_exchanges": score // 10,
                },
                "world_id": world_label,
            }
        )

    assignment = {world["world_id"]: world["arm"] for world in worlds}
    paired_effect = treatment_score - control_score
    record = {
        "dataset_id": DATASET_ID,
        "pair": {
            "assignment": assignment,
            "baseline_cooperation_score": baseline,
            "common_noise": common_noise,
            "common_noise_digest": noise_digest,
            "pair_id": f"pair-{index:06d}",
            "worlds": worlds,
        },
        "question": {
            "estimand": "treatment minus control cooperation_score",
            "type": "paired_average_treatment_effect",
        },
        "reasoning": {
            "decision": {
                "label": {
                    "effect_direction": (
                        "positive"
                        if paired_effect > 0
                        else "negative"
                        if paired_effect < 0
                        else "zero"
                    ),
                    "paired_effect": paired_effect,
                },
                "references": ["/oracle"],
            },
            "inference": {
                "references": ["/pair/worlds", "/oracle/paired_effect"],
                "rule": "Subtract the control outcome from the treatment outcome within the pair.",
            },
            "observation": {
                "facts": [
                    "The two arms share one common-noise digest.",
                    "Exactly one world is assigned to each arm.",
                ],
                "references": [
                    "/pair/assignment",
                    "/pair/common_noise",
                    "/pair/worlds",
                ],
            },
        },
        "record_id": _record_id(seed, index),
        "record_index": index,
        "seed": seed,
        "oracle": {
            "common_noise_shared": True,
            "control_outcome": control_score,
            "paired_effect": paired_effect,
            "treatment_outcome": treatment_score,
        },
    }
    direction = (
        "positive" if paired_effect > 0 else "negative" if paired_effect < 0 else "zero"
    )
    record.update(
        synthetic_envelope(
            DATASET_ID,
            actors=["synthetic-social-agent-001", "synthetic-social-agent-002"],
            content=record,
            decision=direction,
            index=index,
            options=["negative", "zero", "positive"],
            public_text=f"The paired synthetic effect is {paired_effect}.",
            seed=seed,
            summary="The public oracle compares randomized paired worlds under shared common noise.",
            world="hub",
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
            stream.write(
                _canonical(
                    build_record(index, run_seed, int(config["defaults"]["ticks"]))
                )
                + "\n"
            )
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
