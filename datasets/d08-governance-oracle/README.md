# D08 — Fictional Governance Oracle

D08 generates rule-bound decisions for invented councils. Each case includes
an explicit quorum rule, approval threshold, optional fictional guardian veto,
eligible members, ballots, and a deterministic decision oracle.

The task is rule execution, not political persuasion. Names, roles, proposals,
and institutions are fictional, and records do not encode real laws or public
policy.

Every normalized record includes synthetic provenance, a public transcript,
structured deliberation, and three explicitly public reasoning references.

## Generate and verify

```bash
python3 generators/d08/generate.py --output build/d08 --count 100 --seed 8080
python3 generators/d08/verify.py --input build/d08/records.jsonl
python3 generators/d08/generate.py \
  --synthetic-smoke 3 --seed 8080 --output build/d08-smoke.jsonl
```

Resume from the generator-local checkpoint:

```bash
python3 generators/d08/generate.py \
  --output build/d08 \
  --resume build/d08/checkpoint.json
```

Each record includes three auditable reasoning layers. The council-chamber
projection recipe is `../../worldpacks/projections/d08/recipe.json`. No
generated release is committed.
