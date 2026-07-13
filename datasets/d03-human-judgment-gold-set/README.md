# D03 — Human Judgment Gold Set

D03 has a hard publication boundary between:

1. a blinded, **unlabeled candidate queue**; and
2. separately joinable **consented gold labels**.

Candidates contain no judgments, reviewer metadata, consent records, agreement
metrics, adjudication, or gold labels. A public label is emitted only from at
least two consented judgments. Disagreement additionally requires a consented
adjudication. Withheld candidates remain useful as an unlabeled review queue.

The generator publishes agreement metrics with each gold label and
pseudonymizes reviewer references. This scaffold commits no release data;
tests create three deterministic synthetic candidates in cleaned test output.

## Record surfaces

Candidates include normalized provenance, blinded actors, context, a visible
`transcript`, explicit publishable `deliberation`, and optional reviewed
`exposed_reasoning_refs`. Labels are a separate artifact joined by `record_id`.
No inaccessible chain-of-thought is requested or inferred.

## Generate and verify

```bash
python3 generators/d03/generate.py \
  --input path/to/review-sources.jsonl \
  --candidates-output path/to/candidates.jsonl \
  --labels-output path/to/consented-labels.jsonl \
  --checkpoint path/to/d03.checkpoint.json
python3 generators/d03/verify.py \
  --candidates path/to/candidates.jsonl \
  --labels path/to/consented-labels.jsonl
```

`--resume` requires both matching outputs. `--synthetic-smoke 3` is restricted
to deterministic tests and development.
