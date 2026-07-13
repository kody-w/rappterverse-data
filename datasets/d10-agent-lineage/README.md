# D10 — Software-Agent Lineage

D10 creates deterministic directed acyclic graphs describing derivation among
fictional software agents. Parent links always point to earlier nodes, and the
oracle includes a topological order, generation depth, and target ancestors.

“Lineage” means software artifact provenance only. It does not describe human
employment, identity, family, biology, or protected characteristics.

Each normalized record includes synthetic source provenance, a public
transcript, structured deliberation, and three explicitly public reasoning
references.

## Generate and verify

```bash
python3 generators/d10/generate.py --output build/d10 --count 100 --seed 10100
python3 generators/d10/verify.py --input build/d10/records.jsonl
python3 generators/d10/generate.py \
  --synthetic-smoke 3 --seed 10100 --output build/d10-smoke.jsonl
```

Resume from a deterministic checkpoint:

```bash
python3 generators/d10/generate.py \
  --output build/d10 \
  --resume build/d10/checkpoint.json
```

Each record's three reasoning layers cite graph nodes, edges, and oracle
properties. A playable provenance-constellation recipe is available at
`../../worldpacks/projections/d10/recipe.json`. This scaffold commits no
generated release.
