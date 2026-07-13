# D01 — Open Agent Civilization Ledger

D01 is an append-friendly, provenance-preserving ledger of observable
RAPPterverse events. It turns action, message, economy, and world-transition
sources into deterministic JSONL records without collapsing divergent git
lineages.

Accepted inputs are pinned RAPPterverse history exports and owned synthetic
events only. External datasets are rejected by the generator and verifier.

This directory is a scaffold only. Release data is generated outside the
repository; synthetic smoke records are created and deleted by
`tests/datasets/test_d01.py`.

## Record contract

Every record contains:

- a stable `record_id`, observation time, actors, world, and source provenance;
- a normalized public `transcript`;
- structured `deliberation` containing only an explicit public rationale (or an
  explicit `not_recorded` marker);
- optional `exposed_reasoning_refs` only when the source marks them public; and
- an `event` payload with before/after references and observable outcome.

Private chain-of-thought is never inferred or reconstructed.

## Generate and verify

```bash
python3 generators/d01/generate.py \
  --input path/to/pinned-source-actions.jsonl \
  --output path/to/d01.jsonl \
  --checkpoint path/to/d01.checkpoint.json
python3 generators/d01/verify.py --input path/to/d01.jsonl
```

`--resume` validates a completed checkpoint and reuses its output. The
checkpoint format deliberately remains local to D01 until common lake
integration lands.

For deterministic development smoke data only:

```bash
python3 generators/d01/generate.py --synthetic-smoke 3 --output path/to/smoke.jsonl
```

Do not publish smoke output as release data.
