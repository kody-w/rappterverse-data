#!/usr/bin/env python3
"""Generate blinded D03 candidates and separately consented gold labels."""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from pathlib import Path

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

DATASET_ID = "d03"
PRIVATE_KEYS = {
    "adjudication",
    "agreement",
    "consent",
    "gold_label",
    "judgment",
    "judgments",
    "label",
    "reviewer",
    "reviewer_id",
    "actor_id",
    "agent_id",
    "model",
    "model_id",
    "operator",
    "owner",
    "provider",
}


def _candidate_content(source: dict) -> dict:
    return {key: value for key, value in source.items() if key not in PRIVATE_KEYS}


def _blind_transcript(source: dict, observed_at: str) -> list[dict]:
    turns = transcript(
        source.get("transcript"),
        default_speaker="blinded-candidate",
        default_timestamp=observed_at,
        default_text=str(source.get("public_statement", "Blinded candidate response.")),
    )
    speaker_aliases = {}
    for turn in turns:
        role = turn["role"]
        if role in {"system", "tool"}:
            turn["speaker_id"] = role
            continue
        original = turn["speaker_id"]
        if original not in speaker_aliases:
            prefix = "candidate" if role in {"agent", "npc"} else "participant"
            speaker_aliases[original] = f"{prefix}-{len(speaker_aliases) + 1:03d}"
        turn["speaker_id"] = speaker_aliases[original]
    return turns


def normalize_candidate(source: dict) -> dict:
    content = _candidate_content(source)
    source_id = str(content.get("source_id", content.get("id", "")))
    if not source_id:
        raise DatasetError("judgment candidate requires an id")
    observed_at = timestamp(content.get("observed_at", content.get("timestamp")))
    context = content.get("context", {})
    if not isinstance(context, dict):
        raise DatasetError("candidate context must be an object")
    lineage = str(content.get("lineage", "owned-candidate"))
    visible_transcript = _blind_transcript(content, observed_at)
    public_deliberation = deliberation(
        content.get("explicit_deliberation", content.get("deliberation")),
        default_decision=str(content.get("public_action", "submit candidate")),
    )
    if public_deliberation["status"] != "explicit":
        raise DatasetError("judgment candidate requires explicit deliberation")
    content_sha256 = sha256({
        "context": context,
        "deliberation": public_deliberation,
        "source_id": source_id,
        "transcript": visible_transcript,
    })
    record = {
        "actors": ["blinded-candidate"],
        "context": context,
        "dataset_id": DATASET_ID,
        "deliberation": public_deliberation,
        "label_status": "unlabeled_candidate",
        "observed_at": observed_at,
        "record_id": stable_id(DATASET_ID, lineage, source_id, content_sha256),
        "schema": "rappterverse.d03-record/v1",
        "source": {
            "content_sha256": content_sha256,
            "lineage": lineage,
            "source_id": source_id,
            "source_type": str(content.get("source_type", "owned_review_candidate")),
        },
        "transcript": visible_transcript,
        "world": "blinded-review",
    }
    refs = public_reasoning_refs(content.get("exposed_reasoning_refs"))
    if refs:
        record["exposed_reasoning_refs"] = refs
    return record


def _consent(value: object) -> dict | None:
    if not isinstance(value, dict):
        return None
    scopes = value.get("scopes")
    if (
        value.get("status") != "granted"
        or not isinstance(scopes, list)
        or "public_dataset_label" not in scopes
        or not value.get("evidence_ref")
        or not value.get("granted_at")
    ):
        return None
    return {
        "evidence_ref": str(value["evidence_ref"]),
        "granted_at": timestamp(value["granted_at"]),
        "scopes": sorted(set(str(scope) for scope in scopes)),
        "status": "granted",
    }


def agreement_metrics(labels: list[str]) -> dict:
    counts = Counter(labels)
    pairs = len(labels) * (len(labels) - 1) // 2
    agreeing = sum(count * (count - 1) // 2 for count in counts.values())
    entropy = 0.0
    for count in counts.values():
        probability = count / len(labels)
        entropy -= probability * math.log2(probability)
    return {
        "label_entropy_bits": round(entropy, 6),
        "pairwise_agreement": round(agreeing / pairs, 6) if pairs else 1.0,
        "unanimous": len(counts) == 1,
        "vote_counts": dict(sorted(counts.items())),
    }


def normalize_consented_label(source: dict, record_id: str) -> dict | None:
    raw_judgments = source.get("judgments")
    if not isinstance(raw_judgments, list):
        return None
    judgments = []
    for raw in raw_judgments:
        if not isinstance(raw, dict):
            continue
        consent = _consent(raw.get("consent"))
        label = raw.get("label")
        reviewer_id = raw.get("reviewer_id")
        if consent is None or not isinstance(label, str) or not label or not reviewer_id:
            continue
        judgments.append({
            "consent": consent,
            "label": label,
            "reviewer_ref": f"reviewer-{sha256([record_id, reviewer_id])[:16]}",
        })
    if len(judgments) < 2:
        return None
    judgments.sort(key=lambda item: item["reviewer_ref"])
    labels = [judgment["label"] for judgment in judgments]
    metrics = agreement_metrics(labels)
    counts = Counter(labels)
    most_common = counts.most_common()
    if len(most_common) > 1 and most_common[0][1] == most_common[1][1]:
        return None

    if metrics["unanimous"]:
        adjudication = {
            "consent": None,
            "method": "unanimous",
            "rationale": "All consented judgments agree.",
            "selected_label": most_common[0][0],
        }
    else:
        raw_adjudication = source.get("adjudication")
        if not isinstance(raw_adjudication, dict):
            return None
        consent = _consent(raw_adjudication.get("consent"))
        selected = raw_adjudication.get("selected_label")
        reviewer_id = raw_adjudication.get("reviewer_id")
        rationale = raw_adjudication.get("rationale")
        if (
            consent is None
            or selected not in counts
            or not reviewer_id
            or not isinstance(rationale, str)
            or not rationale
        ):
            return None
        adjudication = {
            "consent": consent,
            "method": "consented_adjudication",
            "rationale": rationale,
            "reviewer_ref": f"reviewer-{sha256([record_id, reviewer_id])[:16]}",
            "selected_label": selected,
        }

    return {
        "adjudication": adjudication,
        "agreement": metrics,
        "dataset_id": DATASET_ID,
        "gold_label": adjudication["selected_label"],
        "judgments": judgments,
        "publication": {
            "candidate_blinded": True,
            "consent_verified": True,
            "review_safe": True,
        },
        "record_id": record_id,
        "schema": "rappterverse.d03-consented-label/v1",
    }


def _public_consent(number: int, reviewer: int) -> dict:
    return {
        "evidence_ref": f"synthetic://d03/consent/{number:03d}/{reviewer}",
        "granted_at": f"2040-03-{number:02d}T01:0{reviewer}:00Z",
        "scopes": ["public_dataset_label"],
        "status": "granted",
    }


def synthetic_sources(count: int = 3) -> list[dict]:
    sources = []
    for index in range(count):
        number = index + 1
        if index % 3 == 0:
            labels = ["meets-rubric", "meets-rubric", "meets-rubric"]
        elif index % 3 == 1:
            labels = ["needs-revision", "needs-revision", "meets-rubric"]
        else:
            labels = ["meets-rubric"]
        judgments = [
            {
                "consent": _public_consent(number, reviewer + 1),
                "label": label,
                "reviewer_id": f"private-reviewer-{reviewer + 1}",
            }
            for reviewer, label in enumerate(labels)
        ]
        source = {
            "context": {"rubric": "synthetic-quality-v1", "task": f"task-{number}"},
            "explicit_deliberation": {
                "alternatives": ["submit", "revise"],
                "confidence": round(0.70 + index * 0.04, 2),
                "decision": "submit",
                "summary": f"Public candidate rationale {number}.",
            },
            "id": f"smoke-candidate-{number:03d}",
            "judgments": judgments,
            "lineage": "synthetic-smoke",
            "public_action": "submit",
            "source_type": "synthetic_smoke",
            "timestamp": f"2040-03-{number:02d}T00:00:00Z",
            "transcript": [
                {
                    "role": "human",
                    "speaker_id": f"private-user-{number}",
                    "text": f"Synthetic task request {number}.",
                },
                {
                    "role": "agent",
                    "speaker_id": f"private-agent-{number}",
                    "text": f"Synthetic candidate response {number}.",
                },
            ],
        }
        if index % 3 == 1:
            source["adjudication"] = {
                "consent": _public_consent(number, 9),
                "rationale": "The revision criteria outweigh the passing vote.",
                "reviewer_id": "private-adjudicator",
                "selected_label": "needs-revision",
            }
        sources.append(source)
    return sources


def generate(
    sources: list[dict],
    candidates_output: Path,
    labels_output: Path,
    *,
    checkpoint: Path | None = None,
    resume: bool = False,
) -> tuple[list[dict], list[dict]]:
    fingerprint = sha256(sources)
    if resume:
        if (
            checkpoint is None
            or not checkpoint.exists()
            or not candidates_output.exists()
            or not labels_output.exists()
        ):
            raise DatasetError("--resume requires both outputs and a checkpoint")
        state = load_checkpoint(
            checkpoint, dataset_id=DATASET_ID, input_sha256=fingerprint
        )
        if state.get("complete"):
            candidates = read_jsonl(candidates_output)
            labels = read_jsonl(labels_output)
            if len(candidates) != state.get("next_source_index"):
                raise DatasetError("checkpoint count does not match candidate output")
            return candidates, labels

    pairs = []
    for source in sources:
        candidate = normalize_candidate(source)
        pairs.append((candidate, normalize_consented_label(source, candidate["record_id"])))
    candidates = sorted(
        (candidate for candidate, _ in pairs),
        key=lambda item: (item["observed_at"], item["record_id"]),
    )
    labels = sorted(
        (label for _, label in pairs if label is not None),
        key=lambda item: item["record_id"],
    )
    write_jsonl(candidates_output, candidates)
    write_jsonl(labels_output, labels)
    if checkpoint:
        save_checkpoint(
            checkpoint,
            dataset_id=DATASET_ID,
            input_sha256=fingerprint,
            count=len(sources),
        )
    return candidates, labels


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", type=Path)
    source.add_argument("--synthetic-smoke", type=int, metavar="COUNT")
    parser.add_argument("--candidates-output", type=Path, required=True)
    parser.add_argument("--labels-output", type=Path, required=True)
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
        candidates, labels = generate(
            sources,
            args.candidates_output,
            args.labels_output,
            checkpoint=args.checkpoint,
            resume=args.resume,
        )
    except DatasetError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({
        "candidates": len(candidates),
        "consented_labels": len(labels),
        "dataset_id": DATASET_ID,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
