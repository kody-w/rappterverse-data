#!/usr/bin/env python3
"""Generate deterministic D10 acyclic software-agent lineage records."""

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

DATASET_ID = "d10"
DATASET_SLUG = "d10-agent-lineage"
ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "datasets" / DATASET_SLUG / "config.json"


def _canonical(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def _record_rng(seed: int, index: int) -> random.Random:
    digest = hashlib.sha256(f"{DATASET_ID}:{seed}:{index}".encode()).digest()
    return random.Random(int.from_bytes(digest, "big"))


def _record_id(seed: int, index: int) -> str:
    digest = hashlib.sha256(f"{seed}:{index}".encode()).hexdigest()[:12]
    return f"d10-{index:06d}-{digest}"


def _ancestors(target: str, parents_by_child: dict[str, list[str]]) -> list[str]:
    found: set[str] = set()
    pending = list(parents_by_child.get(target, []))
    while pending:
        current = pending.pop()
        if current in found:
            continue
        found.add(current)
        pending.extend(parents_by_child.get(current, []))
    return sorted(found)


def build_record(
    index: int,
    seed: int,
    minimum_nodes: int,
    maximum_nodes: int,
) -> dict[str, Any]:
    rng = _record_rng(seed, index)
    node_count = rng.randint(minimum_nodes, maximum_nodes)
    capability_pool = [
        "map",
        "summarize",
        "verify",
        "simulate",
        "project",
        "audit",
    ]
    nodes: list[dict[str, Any]] = []
    edges: list[dict[str, str]] = []
    generations: dict[str, int] = {}
    parents_by_child: dict[str, list[str]] = {}

    for node_index in range(node_count):
        agent_id = f"software-agent-{node_index:03d}"
        if node_index == 0:
            parents: list[str] = []
        else:
            parent_count = 2 if node_index >= 3 and rng.random() < 0.4 else 1
            parents = sorted(
                rng.sample(
                    [node["agent_id"] for node in nodes],
                    k=min(parent_count, len(nodes)),
                )
            )
        generation = (
            0
            if not parents
            else max(generations[parent] for parent in parents) + 1
        )
        generations[agent_id] = generation
        parents_by_child[agent_id] = parents
        inherited = {
            capability
            for node in nodes
            if node["agent_id"] in parents
            for capability in node["capabilities"]
        }
        inherited.add(rng.choice(capability_pool))
        artifact_digest = hashlib.sha256(
            _canonical(
                {
                    "agent_id": agent_id,
                    "index": index,
                    "parents": parents,
                    "seed": seed,
                }
            ).encode()
        ).hexdigest()
        nodes.append(
            {
                "agent_id": agent_id,
                "artifact_sha256": artifact_digest,
                "capabilities": sorted(inherited),
                "generation": generation,
                "parents": parents,
                "software_only": True,
            }
        )
        relation = "merge" if len(parents) > 1 else "fork"
        edges.extend(
            {"child": agent_id, "parent": parent, "relation": relation}
            for parent in parents
        )

    target = nodes[-1]["agent_id"]
    topological_order = [node["agent_id"] for node in nodes]
    ancestors = _ancestors(target, parents_by_child)
    max_generation = max(generations.values())
    record = {
        "dataset_id": DATASET_ID,
        "lineage": {
            "edges": edges,
            "nodes": nodes,
            "scope": "fictional-software-agent-provenance",
        },
        "oracle": {
            "acyclic": True,
            "max_generation": max_generation,
            "target_ancestors": ancestors,
            "topological_order": topological_order,
        },
        "query": {
            "target_agent_id": target,
            "task": "Validate the DAG and recover all software-agent ancestors.",
        },
        "reasoning": {
            "decision": {
                "label": {
                    "acyclic": True,
                    "max_generation": max_generation,
                    "target_ancestor_count": len(ancestors),
                },
                "references": ["/oracle"],
            },
            "inference": {
                "references": [
                    "/lineage/edges",
                    "/oracle/topological_order",
                    "/oracle/target_ancestors",
                ],
                "rule": "Every parent precedes its child; traverse parent links to compute the target's ancestors.",
            },
            "observation": {
                "facts": [
                    f"The graph contains {node_count} fictional software-agent nodes.",
                    "Every parent link targets an earlier emitted node.",
                ],
                "references": [
                    "/lineage/nodes",
                    "/lineage/edges",
                    "/query/target_agent_id",
                ],
            },
        },
        "record_id": _record_id(seed, index),
        "record_index": index,
        "seed": seed,
    }
    record.update(
        synthetic_envelope(
            DATASET_ID,
            actors=topological_order,
            content=record,
            decision="acyclic",
            index=index,
            options=["acyclic", "cyclic"],
            public_text=f"Validated {node_count} fictional software-agent lineage nodes.",
            seed=seed,
            summary="The public provenance rationale checks parent-before-child order and ancestry.",
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
                int(config["defaults"]["minimum_nodes"]),
                int(config["defaults"]["maximum_nodes"]),
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
