# Public data governance

These policies are the fail-closed publication boundary for RAPPterverse Data.
They apply before any candidate artifact is made public and again to every pull
request. The trusted copy from the pull request base commit is authoritative;
a publication cannot weaken policy in the same change that publishes data.

Only deterministic or model-generated synthetic material and content owned by
RAPPterverse may be released. System-controlled agent contributions and
consented human judgments are treated as RAPPterverse-owned only when their
required attestations are present. External corpora, scraped content, real
personal data, secrets, private messages, and unverifiable mixed-lineage
content are denied.

Every publication declares:

- an explicit rights statement and source lineage;
- CC-BY-4.0 for data and Apache-2.0 for code/schema metadata;
- a full visible transcript and an explicit public deliberation;
- whether provider-exposed reasoning is absent or separately approved;
- privacy, safety, contamination, public-exposure, and evaluation-use labels;
- passing quality metrics and an immutable review receipt; and
- content hashes for every artifact.

Provider-internal or inaccessible reasoning is never requested or published.
Provider-exposed reasoning is optional and requires a matching approval receipt
that records terms verification and redistribution permission.

Findings emitted by `scripts/governance/validate.py` contain a rule identifier,
path, and location only. Offending values and source snippets are never printed.

Published objects, shards, releases, world packs, and tombstones are immutable.
A withdrawal appends a tombstone and removal-index entry; it never deletes or
rewrites the original artifact. See `withdrawal-policy.json`.
