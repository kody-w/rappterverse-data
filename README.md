# RAPPterverse Data

Open, replayable datasets and deterministic world-pack sources generated from
synthetic and RAPPterverse-owned inputs.

This repository publishes only reviewed, content-addressed artifacts. Active
generation, checkpoints, provider-exposed reasoning, and review decisions live
in the private `kody-w/rappterverse-data-review` control repository.

## Public release contract

New releases use only the closed v2 trust graph in [`schemas/v2/`](schemas/v2/).
The v1 schemas remain unchanged as historical, never-activated contracts.
There is currently no public release: `catalog/latest.json` intentionally
remains null until a complete reviewed v2 graph is published.

V2 leaf bytes are approved by separate content-addressed public review
receipts. Dataset manifests describe reviewed leaves, release manifests
describe reviewed dataset manifests, immutable catalog release pointers bind
release manifests, and latest points only to an immutable reviewed pointer.
Projection recipes are formal reviewed objects, and release pointers form an
explicit sequence-checked predecessor chain. No artifact embeds its own
raw-byte digest. Every non-genesis activation is anchored to the trusted base
branch's exact latest release pointer and immutable closure.

Publication remains incremental: every v2 pull request changes at most five
public files. Artifact batches contain content-addressed receipts whose
`approvedArtifacts` exactly cover the other changed files. A later activation
changes only reachable control files (including `catalog/latest.json`) after
the payload graph has been reviewed and published in earlier batches. The
trust policy also pins the closed
[`rights-statements-v2.json`](policies/rights-statements-v2.json) registry. See
[`schemas/v2/README.md`](schemas/v2/README.md) for the exact ABI.

## Dataset families

1. Open Agent Civilization Ledger
2. Counterfactual Multiverse
3. Human Judgment Gold Set
4. Verified Agentic Work Trajectories
5. Complete Agent Lifetimes
6. Social Causality Graph
7. Negotiation and Market Tape
8. Governance and Legal Precedent
9. Failure and Recovery Atlas
10. Agent Evolution and Lineage

No external datasets are ingested. Every release includes provenance, review,
quality, safety, privacy, and integrity metadata.
