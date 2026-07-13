#!/usr/bin/env python3
"""Verify D10 acyclic software-agent lineage JSONL records."""

from __future__ import annotations

import argparse
import hashlib
import json
import string
import sys
from collections import deque
from pathlib import Path
from typing import Any

try:
    from ._fallback import common_envelope_errors
except ImportError:
    from _fallback import common_envelope_errors

DATASET_ID = "d10"


def _validate_reasoning(record: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    reasoning = record.get("reasoning")
    if not isinstance(reasoning, dict):
        return ["reasoning must be an object"]
    required = {
        "observation": ("references", "facts"),
        "inference": ("references", "rule"),
        "decision": ("references", "label"),
    }
    if set(reasoning) != set(required):
        errors.append("reasoning must contain exactly observation, inference, and decision")
        return errors
    for layer, fields in required.items():
        value = reasoning[layer]
        if not isinstance(value, dict):
            errors.append(f"reasoning.{layer} must be an object")
            continue
        for field in fields:
            if field not in value:
                errors.append(f"reasoning.{layer}.{field} is required")
        references = value.get("references")
        if not isinstance(references, list) or not references:
            errors.append(f"reasoning.{layer}.references must be non-empty")
        elif not all(isinstance(ref, str) and ref.startswith("/") for ref in references):
            errors.append(f"reasoning.{layer}.references must be JSON Pointers")
    return errors


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


def validate_record(record: dict[str, Any]) -> list[str]:
    errors = common_envelope_errors(record, DATASET_ID)
    errors.extend(_validate_reasoning(record))
    if record.get("dataset_id") != DATASET_ID:
        errors.append(f"dataset_id must be {DATASET_ID}")
    lineage = record.get("lineage")
    oracle = record.get("oracle")
    query = record.get("query")
    if not isinstance(lineage, dict) or not isinstance(oracle, dict):
        return errors + ["lineage and oracle must be objects"]
    if not isinstance(query, dict):
        return errors + ["query must be an object"]
    if lineage.get("scope") != "fictional-software-agent-provenance":
        errors.append("lineage scope must be fictional software-agent provenance")
    nodes = lineage.get("nodes")
    edges = lineage.get("edges")
    if not isinstance(nodes, list) or not nodes:
        return errors + ["lineage.nodes must be non-empty"]
    if not isinstance(edges, list):
        return errors + ["lineage.edges must be a list"]

    node_map: dict[str, dict[str, Any]] = {}
    parents_by_child: dict[str, list[str]] = {}
    for node in nodes:
        if not isinstance(node, dict):
            errors.append("each lineage node must be an object")
            continue
        agent_id = node.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id:
            errors.append("node agent_id must be a non-empty string")
            continue
        if agent_id in node_map:
            errors.append(f"duplicate agent_id {agent_id}")
            continue
        node_map[agent_id] = node
        parents = node.get("parents")
        if not isinstance(parents, list) or len(parents) > 2:
            errors.append(f"{agent_id} parents must be a list of at most two IDs")
            parents_by_child[agent_id] = []
        else:
            parents_by_child[agent_id] = parents
        if node.get("software_only") is not True:
            errors.append(f"{agent_id} must be marked software_only")
        digest = node.get("artifact_sha256")
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in string.hexdigits for character in digest)
        ):
            errors.append(f"{agent_id} artifact_sha256 is invalid")

    for child, parents in parents_by_child.items():
        for parent in parents:
            if parent not in node_map:
                errors.append(f"{child} references missing parent {parent}")
            if parent == child:
                errors.append(f"{child} cannot parent itself")

    expected_edges = {
        (
            parent,
            child,
            "merge" if len(parents) > 1 else "fork",
        )
        for child, parents in parents_by_child.items()
        for parent in parents
    }
    actual_edges: set[tuple[Any, Any, Any]] = set()
    for edge in edges:
        if not isinstance(edge, dict):
            errors.append("each lineage edge must be an object")
            continue
        actual_edges.add((edge.get("parent"), edge.get("child"), edge.get("relation")))
    if actual_edges != expected_edges:
        errors.append("lineage edges do not match node parent lists")

    topological_order = oracle.get("topological_order")
    if not isinstance(topological_order, list) or set(topological_order) != set(node_map):
        errors.append("oracle topological_order must contain every node exactly once")
        topological_order = list(node_map)
    elif len(topological_order) != len(set(topological_order)):
        errors.append("oracle topological_order contains duplicates")
    positions = {agent_id: position for position, agent_id in enumerate(topological_order)}
    for child, parents in parents_by_child.items():
        for parent in parents:
            if parent in positions and child in positions and positions[parent] >= positions[child]:
                errors.append(f"parent {parent} does not precede child {child}")

    children: dict[str, list[str]] = {agent_id: [] for agent_id in node_map}
    indegree = {agent_id: 0 for agent_id in node_map}
    for child, parents in parents_by_child.items():
        for parent in parents:
            if parent in children:
                children[parent].append(child)
                indegree[child] += 1
    queue = deque(sorted(agent_id for agent_id, degree in indegree.items() if degree == 0))
    visited: list[str] = []
    while queue:
        parent = queue.popleft()
        visited.append(parent)
        for child in sorted(children[parent]):
            indegree[child] -= 1
            if indegree[child] == 0:
                queue.append(child)
    acyclic = len(visited) == len(node_map)
    if oracle.get("acyclic") is not acyclic or not acyclic:
        errors.append("oracle acyclicity does not match independent graph traversal")

    computed_generations: dict[str, int] = {}
    for agent_id in topological_order:
        parents = parents_by_child.get(agent_id, [])
        if any(parent not in computed_generations for parent in parents):
            errors.append(f"cannot derive generation for {agent_id}")
            continue
        generation = (
            0
            if not parents
            else max(computed_generations[parent] for parent in parents) + 1
        )
        computed_generations[agent_id] = generation
        if node_map[agent_id].get("generation") != generation:
            errors.append(f"{agent_id} generation mismatch")
    max_generation = max(computed_generations.values(), default=0)
    if oracle.get("max_generation") != max_generation:
        errors.append("oracle max_generation mismatch")

    target = query.get("target_agent_id")
    if target not in node_map:
        errors.append("query target_agent_id is missing from the graph")
    else:
        ancestors = _ancestors(target, parents_by_child)
        if oracle.get("target_ancestors") != ancestors:
            errors.append("oracle target_ancestors mismatch")
    return errors


def _records_path(path: Path) -> Path:
    return path / "records.jsonl" if path.is_dir() else path


def verify(path: Path) -> tuple[int, list[str]]:
    records_path = _records_path(path)
    errors: list[str] = []
    seen: set[str] = set()
    count = 0
    previous_order: tuple[str, str] | None = None
    try:
        lines = records_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        return 0, [str(exc)]
    for line_number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        count += 1
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            errors.append(f"line {line_number}: invalid JSON: {exc.msg}")
            continue
        if not isinstance(record, dict):
            errors.append(f"line {line_number}: record must be a JSON object")
            continue
        record_id = record.get("record_id")
        if not isinstance(record_id, str) or not record_id:
            errors.append(f"line {line_number}: record_id is required")
        elif record_id in seen:
            errors.append(f"line {line_number}: duplicate record_id {record_id}")
        else:
            seen.add(record_id)
        order = (str(record.get("observed_at", "")), str(record_id))
        if previous_order is not None and order < previous_order:
            errors.append(f"line {line_number}: records are not deterministically ordered")
        previous_order = order
        errors.extend(
            f"line {line_number}: {error}" for error in validate_record(record)
        )
    if count == 0:
        errors.append("no records found")

    manifest_path = records_path.parent / "manifest.json"
    if not manifest_path.exists():
        manifest_path = records_path.with_suffix(".manifest.json")
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if manifest.get("dataset_id") != DATASET_ID:
                errors.append("manifest dataset_id mismatch")
            if manifest.get("count") != count:
                errors.append("manifest count mismatch")
            digest = hashlib.sha256(records_path.read_bytes()).hexdigest()
            if manifest.get("records_sha256") != digest:
                errors.append("manifest records_sha256 mismatch")
        except (OSError, json.JSONDecodeError) as exc:
            errors.append(f"invalid manifest: {exc}")
    return count, errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    args = parser.parse_args(argv)
    count, errors = verify(args.input)
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"verified {count} {DATASET_ID} records")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
