# D04 — Verified Agentic Work Trajectories

D04 captures complete, visible software-agent work episodes from task receipt
through outcome. A trajectory includes public messages, explicit deliberation,
tool calls and arguments, tool results, patches, verifier evidence, and the
final outcome.

The capture contract is deliberately strict: an episode cannot claim
`capture.complete` unless every required surface is present and public-safe.
No inaccessible chain-of-thought is requested or reconstructed.

This independent scaffold contains no release records. Unit tests generate
three deterministic synthetic trajectories in cleaned test output.

## Record payload

`work_trajectory` contains:

- task identity and public instruction;
- capture-completeness flags;
- ordered tool calls with arguments and results;
- full synthetic before/after patch content, unified diffs, and hashes;
- verifier commands, outputs, exit codes, and hashes; and
- an explicit terminal outcome and artifact references.

The normalized envelope also contains a visible `transcript`, explicit public
`deliberation`, provenance, and optional reviewed `exposed_reasoning_refs`.

## Generate and verify

```bash
python3 generators/d04/generate.py \
  --input path/to/work-sources.jsonl \
  --output path/to/d04.jsonl \
  --checkpoint path/to/d04.checkpoint.json
python3 generators/d04/verify.py --input path/to/d04.jsonl
```

`--resume` validates and reuses a completed checkpoint.
`--synthetic-smoke 3` is for deterministic tests and local development only.
