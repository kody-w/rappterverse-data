# D06 — Social Causality

D06 creates paired, randomized fictional worlds for estimating the effect of a
single social intervention. Each pair shares an identical common-noise tape.
Only the randomized intervention arm differs, so the paired outcome delta is
an auditable causal label rather than an unpaired correlation.

## Record contract

Each JSONL record contains:

- a randomized `world-a`/`world-b` assignment;
- one shared exogenous noise tape and its digest;
- control and treatment outcomes;
- a paired-effect oracle; and
- three compact reasoning layers whose JSON Pointer references identify the
  evidence, inference, and decision fields.

Every record also carries the normalized dataset envelope: schema, synthetic
source provenance, public transcript, structured deliberation, and exactly
three explicitly public `exposed_reasoning_refs`.

All agents, worlds, and interactions are synthetic. The scaffold contains no
committed generated release.

## Generate and verify

```bash
python3 generators/d06/generate.py --output build/d06 --count 100 --seed 6060
python3 generators/d06/verify.py --input build/d06/records.jsonl
python3 generators/d06/generate.py \
  --synthetic-smoke 3 --seed 6060 --output build/d06-smoke.jsonl
```

The generator checkpoints after every record. Resume an interrupted run with:

```bash
python3 generators/d06/generate.py \
  --output build/d06 \
  --resume build/d06/checkpoint.json
```

See `DATA_CARD.md`, `reasoning.json`, and
`../../worldpacks/projections/d06/recipe.json` for intended use and the
playable paired-world projection.
