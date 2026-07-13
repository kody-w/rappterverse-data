"""Generator-local checkpoint contract for D10."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

DATASET_ID = "d10"
CHECKPOINT_VERSION = 1


def load_checkpoint(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("checkpoint_version") != CHECKPOINT_VERSION:
        raise ValueError("unsupported checkpoint version")
    if data.get("schema") != "rappterverse.d10-checkpoint/v1":
        raise ValueError("unsupported checkpoint schema")
    if data.get("dataset_id") != DATASET_ID:
        raise ValueError("checkpoint belongs to another dataset")
    if not isinstance(data.get("seed"), int):
        raise ValueError("checkpoint seed must be an integer")
    count = data.get("count")
    next_index = data.get("next_index")
    if not isinstance(count, int) or count < 1:
        raise ValueError("checkpoint count must be positive")
    if not isinstance(next_index, int) or not 0 <= next_index <= count:
        raise ValueError("checkpoint next_index is out of range")
    return data


def save_checkpoint(path: Path, *, seed: int, count: int, next_index: int) -> None:
    payload = {
        "checkpoint_version": CHECKPOINT_VERSION,
        "count": count,
        "dataset_id": DATASET_ID,
        "next_index": next_index,
        "schema": "rappterverse.d10-checkpoint/v1",
        "seed": seed,
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    staged = path.with_name(f".{path.name}.next")
    staged.write_text(
        json.dumps(payload, indent=4, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    staged.replace(path)
