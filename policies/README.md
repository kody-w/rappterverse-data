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
- passing quality metrics and a separate immutable public review receipt; and
- content hashes for every artifact.

Provider-internal or inaccessible reasoning is never requested or published.
Provider-exposed reasoning is optional and requires a matching approval receipt
whose exact artifact list records `approve_public`, explicit redistribution
approval, and a content-bound provider-terms reference.

New release activation uses `publication-trust-v2.json`. This canonical,
digest-pinnable bundle contains the public reviewer roster (`kody-w`) and
release requirements, but no secret, credential, signing key, or assertion that
signed approvals are operational. V2 receipts allow a nullable future signed
approval reference; the current operational value is null.
The bundle pins the exact path, byte count, and raw SHA-256 of the closed
`rights-statements-v2.json` registry. Each provenance statement must be active,
authorize every declared source type and rights basis, and require the
source-type-specific ownership or consent attestations.

Every v2 publication pull request retains the five-file hard limit. Immutable
artifact batches are covered exactly once by changed content-addressed
receipts. Release activation changes only reachable control files, validates
the complete prepublished graph, and anchors a non-genesis predecessor to the
trusted base revision.

Findings emitted by `scripts/governance/validate.py` contain a rule identifier,
path, and location only. Offending values and source snippets are never printed.

Published objects, shards, releases, world packs, and tombstones are immutable.
A catalog release pointer under `catalog/releases/` is also immutable.
A withdrawal appends a tombstone and removal-index entry; it never deletes or
rewrites the original artifact. See `withdrawal-policy.json`.
