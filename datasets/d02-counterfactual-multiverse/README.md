# D02 — Counterfactual Multiverse

D02 creates deterministic paired world branches from one base state. The
control branch receives no intervention; the treatment branch receives exactly
one declared intervention. Both then replay the same ordered operations.

Every pair publishes canonical state hashes, replay steps, final states, and a
leaf-level causal contrast. This makes intervention isolation independently
verifiable instead of merely asserted.

This directory is a scaffold only. Tests generate three deterministic synthetic
pairs in cleaned test output; no release data is committed.

## Record contract

Each normalized record contains source provenance, actors, a visible
`transcript`, explicit public `deliberation`, optional reviewed
`exposed_reasoning_refs`, and `counterfactual_pair`:

- `base_state` and its canonical hash;
- one `intervention` (`set` or `increment`);
- ordered `shared_replay_steps`;
- independently hashed `control` and `treatment` branches; and
- deterministic `causal_contrast` values.

Private chain-of-thought is neither requested nor inferred.

## Generate and verify

```bash
python3 generators/d02/generate.py \
  --input path/to/scenarios.jsonl \
  --output path/to/d02.jsonl \
  --checkpoint path/to/d02.checkpoint.json
python3 generators/d02/verify.py --input path/to/d02.jsonl
```

`--resume` reuses a matching completed checkpoint. `--synthetic-smoke 3`
exists only for deterministic tests and local development.
