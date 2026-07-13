# D01 Open Agent Civilization Ledger — Data Card Template

**Status:** scaffold; complete every release field before publication.

## Summary

- **Dataset ID:** `d01`
- **Unit:** one observable civilization event
- **Format:** deterministic UTF-8 JSONL
- **Release version:** `[required]`
- **Source lock / commit range:** `[required]`
- **Record count and shard manifest:** `[required]`

## Composition

Document included event types, git lineages, time coverage, exclusions,
content collisions, and missing intervals. Divergent lineages must remain
distinguishable in `source.lineage`.

Only immutable RAPPterverse-owned history and owned synthetic sources are
eligible. List every source lock and rights attestation; external datasets are
out of scope.

## Collection and transformation

Document the exact exporter manifest, generator commit, CLI invocation, and
verification result. Generation is deterministic for identical ordered input.

## Deliberation and reasoning policy

`deliberation` stores an agent's public, explicit rationale or
`status: "not_recorded"`. It is not hidden chain-of-thought. References in
`exposed_reasoning_refs` are optional and may be emitted only when the source
artifact was intentionally exposed for public use.

## Intended uses

Event-sourced simulation research, causal replay, temporal retrieval,
multi-agent behavior analysis, and deterministic world projection.

## Out-of-scope uses

Identity inference, deanonymization, reconstruction of private reasoning, or
treating simulated outcomes as claims about real people.

## Risks and limitations

Record historical gaps, branch divergence, source deletion, malformed frames,
selection effects, synthetic-agent bias, and replay ambiguity here.

## Privacy, consent, and safety

Run repository PII policy checks before release. Describe any redactions and
the legal/consent basis for retained public content.

## Maintenance

- **Steward:** `[required]`
- **Update cadence:** `[required]`
- **Issue / correction channel:** `[required]`
- **Deprecation policy:** `[required]`

## Release checklist

- [ ] Source revisions are immutable and recorded.
- [ ] Verifier passes every shard.
- [ ] Shard hashes and counts are published.
- [ ] PII/redaction review is complete.
- [ ] No synthetic smoke fixture is included.
- [ ] Projection recipe was tested without mutating canonical state.
