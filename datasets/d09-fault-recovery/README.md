# D09 — Safe In-Memory Fault Recovery

D09 models delivery faults against a tiny in-memory key/value state machine.
Faults are data, not real failures: the generator does not alter networking,
processes, repository state, or the host filesystem beyond writing its chosen
output files.

Records cover duplicate delivery, reordering, dropped acknowledgements, and
transient read errors. A canonical operation tape plus idempotent, ordered
recovery yields the oracle final state.

The normalized envelope carries synthetic provenance, a public transcript,
structured deliberation, and exactly three explicitly public reasoning
references.

## Generate and verify

```bash
python3 generators/d09/generate.py --output build/d09 --count 100 --seed 9090
python3 generators/d09/verify.py --input build/d09
python3 generators/d09/generate.py \
  --synthetic-smoke 3 --seed 9090 --output build/d09-smoke.jsonl
```

Resume safely from `build/d09/checkpoint.json`:

```bash
python3 generators/d09/generate.py \
  --output build/d09 \
  --resume build/d09/checkpoint.json
```

Three reasoning layers reference the initial state, operation/fault traces,
recovery actions, and final oracle. The playable recovery-console recipe lives
at `../../worldpacks/projections/d09/recipe.json`. No generated records are
committed.
