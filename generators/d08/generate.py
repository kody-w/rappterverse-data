#!/usr/bin/env python3
"""Generate deterministic D08 fictional governance rule-oracle records."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import random
from pathlib import Path
from typing import Any

try:
    from ._fallback import synthetic_envelope
    from .checkpoint import load_checkpoint, save_checkpoint
except ImportError:
    from _fallback import synthetic_envelope
    from checkpoint import load_checkpoint, save_checkpoint

DATASET_ID = "d08"
DATASET_SLUG = "d08-governance-oracle"
ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "datasets" / DATASET_SLUG / "config.json"


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _record_rng(seed: int, index: int) -> random.Random:
    digest = hashlib.sha256(f"{DATASET_ID}:{seed}:{index}".encode()).digest()
    return random.Random(int.from_bytes(digest, "big"))


def _record_id(seed: int, index: int) -> str:
    digest = hashlib.sha256(f"{seed}:{index}".encode()).hexdigest()[:12]
    return f"d08-{index:06d}-{digest}"


def _evaluate(
    rules: dict[str, Any],
    members: list[dict[str, str]],
    ballots: list[dict[str, str]],
) -> dict[str, Any]:
    member_roles = {member["member_id"]: member["role"] for member in members}
    eligible = len(members)
    turnout = len(ballots)
    yes = sum(ballot["vote"] == "yes" for ballot in ballots)
    no = sum(ballot["vote"] == "no" for ballot in ballots)
    abstain = sum(ballot["vote"] == "abstain" for ballot in ballots)
    decisive = yes + no
    quorum_met = turnout * 100 >= rules["quorum_percent"] * eligible
    threshold_met = (
        decisive > 0 and yes * 100 >= rules["approval_percent"] * decisive
    )
    veto_triggered = rules["guardian_veto"] and any(
        ballot["vote"] == "no"
        and member_roles[ballot["member_id"]] == rules["veto_role"]
        for ballot in ballots
    )
    return {
        "approved": quorum_met and threshold_met and not veto_triggered,
        "counts": {
            "abstain": abstain,
            "decisive": decisive,
            "eligible": eligible,
            "no": no,
            "turnout": turnout,
            "yes": yes,
        },
        "quorum_met": quorum_met,
        "threshold_met": threshold_met,
        "veto_triggered": veto_triggered,
    }


def _ballots_for_mode(
    mode: str,
    members: list[dict[str, str]],
    rules: dict[str, Any],
) -> list[dict[str, str]]:
    eligible = len(members)
    required_yes = math.ceil(rules["approval_percent"] * eligible / 100)
    if mode == "approved":
        yes_count = required_yes
        votes = ["yes"] * yes_count + ["no"] * (eligible - yes_count)
    elif mode == "quorum_failure":
        turnout = max(1, math.ceil(rules["quorum_percent"] * eligible / 100) - 1)
        votes = ["yes"] * turnout
    elif mode == "threshold_failure":
        yes_count = max(1, required_yes - 1)
        votes = ["yes"] * yes_count + ["no"] * (eligible - yes_count)
    else:
        votes = ["no"] + ["yes"] * (eligible - 1)

    ballots = []
    for member, vote in zip(members, votes):
        ballots.append({"member_id": member["member_id"], "vote": vote})
    return ballots


def build_record(index: int, seed: int, member_count: int) -> dict[str, Any]:
    rng = _record_rng(seed, index)
    roles = ["guardian", "steward", "builder", "archivist", "navigator", "witness"]
    members = [
        {
            "member_id": f"council-member-{member_index:02d}",
            "role": roles[member_index % len(roles)],
        }
        for member_index in range(member_count)
    ]
    rules = {
        "approval_percent": rng.choice([50, 60, 67]),
        "guardian_veto": True,
        "quorum_percent": rng.choice([50, 60, 67]),
        "veto_role": "guardian",
    }
    mode = ("approved", "quorum_failure", "threshold_failure", "guardian_veto")[
        index % 4
    ]
    ballots = _ballots_for_mode(mode, members, rules)
    oracle = _evaluate(rules, members, ballots)
    proposals = [
        "rotate the observatory lantern pattern",
        "open the moss archive for one moon",
        "move the echo garden rehearsal hour",
        "fund a bridge of paper stars",
    ]
    record = {
        "ballots": ballots,
        "dataset_id": DATASET_ID,
        "members": members,
        "oracle": oracle,
        "proposal": {
            "proposal_id": f"fictional-proposal-{index:06d}",
            "summary": rng.choice(proposals),
            "synthetic": True,
        },
        "question": {
            "task": "Apply the embedded fictional council rules to the ballots.",
            "type": "rule_oracle_decision",
        },
        "reasoning": {
            "decision": {
                "label": {
                    "approved": oracle["approved"],
                    "controlling_mode": mode,
                },
                "references": ["/oracle"],
            },
            "inference": {
                "references": [
                    "/rules/quorum_percent",
                    "/rules/approval_percent",
                    "/oracle/counts",
                ],
                "rule": "Approval requires quorum, the decisive-vote threshold, and no guardian veto.",
            },
            "observation": {
                "facts": [
                    f"{oracle['counts']['turnout']} of {member_count} eligible members cast ballots.",
                    "The rules and all ballots are embedded in the record.",
                ],
                "references": ["/rules", "/members", "/ballots"],
            },
        },
        "record_id": _record_id(seed, index),
        "record_index": index,
        "rules": rules,
        "seed": seed,
    }
    decision = "approved" if oracle["approved"] else "rejected"
    record.update(
        synthetic_envelope(
            DATASET_ID,
            actors=[member["member_id"] for member in members],
            content=record,
            decision=decision,
            index=index,
            options=["approved", "rejected"],
            public_text=f"The fictional council decision is {decision}.",
            seed=seed,
            summary="The public rule oracle applies quorum, threshold, and fictional veto rules.",
            world="gallery",
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
                int(config["defaults"]["members"]),
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
