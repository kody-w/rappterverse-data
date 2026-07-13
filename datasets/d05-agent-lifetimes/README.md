# D05 — Complete Agent Lifetimes

D05 contains accelerated, synthetic, birth-to-terminal agent lifetimes. Every
decision and idle tick is present, ordered, state-continuous, and hashable.
Memory, goal, and relationship updates are preserved both per tick and as
verified lifetime aggregates.

Only complete terminal lifetimes are eligible. Last activity is never treated
as an inferred terminal event, and this simulated lifecycle must not be read as
a claim about consciousness, personhood, or a real operator.

This independent scaffold commits no release records. Unit tests generate
three deterministic synthetic lifetimes in cleaned test output.

## Record payload

`agent_lifetime` contains:

- a birth event and initial state;
- every contiguous `decision` or `idle` tick;
- before/after state snapshots and canonical hashes;
- explicit public tick deliberation;
- memory, goal, and relationship updates;
- verified aggregate histories and action counts; and
- a terminal event whose final state joins exactly to the last tick.

The envelope also includes a public transcript, explicit lifetime
deliberation, provenance, and optional reviewed `exposed_reasoning_refs`.
Inaccessible reasoning is not requested or inferred.

## Generate and verify

```bash
python3 generators/d05/generate.py \
  --input path/to/complete-lifetimes.jsonl \
  --output path/to/d05.jsonl \
  --checkpoint path/to/d05.checkpoint.json
python3 generators/d05/verify.py --input path/to/d05.jsonl
```

`--resume` reuses a matching completed checkpoint. `--synthetic-smoke 3` is
limited to deterministic tests and development.
