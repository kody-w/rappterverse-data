# D07 — Conservation and Order

D07 produces deterministic transaction tapes for replaying a closed fictional
economy. Transfers are integer-valued, globally conservative, and chained in a
strict sequence. The oracle records both conservation and ordering claims.

## Record contract

Every JSONL record contains an initial account state, an ordered transfer tape,
a SHA-256 previous-event chain, the replayed final state, and three referenced
reasoning layers. Verifiers replay the tape rather than trusting supplied
balances.

The normalized envelope adds deterministic source provenance, a public
transcript, structured deliberation, and three explicitly public reasoning
references.

No generated release is committed.

## Generate and verify

```bash
python3 generators/d07/generate.py --output build/d07 --count 100 --seed 7070
python3 generators/d07/verify.py --input build/d07
python3 generators/d07/generate.py \
  --synthetic-smoke 3 --seed 7070 --output build/d07-smoke.jsonl
```

Checkpoint state defaults to `build/d07/checkpoint.json`. Resume with:

```bash
python3 generators/d07/generate.py \
  --output build/d07 \
  --resume build/d07/checkpoint.json
```

The projection in `../../worldpacks/projections/d07/recipe.json` turns a tape
into a playable marketplace replay puzzle.
