# Public release trust ABI v2

V2 is the only contract accepted for a new public release. Files under
`schemas/v1/` are unchanged historical contracts and have never activated a
public release.

## Closed artifact map

| Artifact kind | `schemaVersion` | Schema |
|---|---|---|
| public record | `rappterverse.public-record/v2` | `records/public-record.schema.json` |
| visible transcript | `rappterverse.visible-transcript/v2` | `transcripts/visible-transcript.schema.json` |
| public deliberation | `rappterverse.public-deliberation/v2` | `deliberations/public-deliberation.schema.json` |
| provider reasoning | `rappterverse.provider-reasoning/v2` | `deliberations/provider-reasoning.schema.json` |
| data card | `rappterverse.data-card/v2` | `governance/data-card.schema.json` |
| public review receipt | `rappterverse.public-review-receipt/v2` | `governance/public-review-receipt.schema.json` |
| active review set | `rappterverse.active-review-set/v2` | `governance/active-review-set.schema.json` |
| trust policy/roster | `rappterverse.publication-trust-policy/v2` | `governance/publication-trust-policy.schema.json` |
| rights registry | `rappterverse.rights-statements/v2` | `governance/rights-statements.schema.json` |
| dataset manifest | `rappterverse.dataset-manifest/v2` | `manifests/dataset-manifest.schema.json` |
| release manifest | `rappterverse.release-manifest/v2` | `manifests/release-manifest.schema.json` |
| world-pack source | `rappterverse.world-pack-source/v2` | `worldpacks/world-pack-source.schema.json` |
| projection recipe | `rappterverse.projection-recipe/v2` | `worldpacks/projection-recipe.schema.json` |
| catalog release pointer | `rappterverse.catalog-release-pointer/v2` | `catalog/release-pointer.schema.json` |
| catalog latest pointer | `rappterverse.catalog-latest-pointer/v2` | `catalog/latest-pointer.schema.json` |

JSONL artifact kinds are closed: `record-shard`, `transcript-shard`,
`deliberation-shard`, and `provider-reasoning-shard`. Each maps to exactly one
line schema in `scripts/contracts/registry.py`.

## Non-circular integrity graph

```text
leaf bytes <- public review receipt
    ^                 ^
dataset manifest descriptors
    ^                 |
release manifest dataset descriptors
    ^
catalog/releases/<releaseId>.json
    ^
catalog/latest.json
```

Raw descriptors contain exactly `path`, `artifactKind`, `mediaType`, `bytes`,
and `sha256`. Parent descriptors add `reviewReceiptRef`. A receipt's
`approvedArtifacts` lists the exact raw descriptors it approves and is stored
at:

```text
objects/review-receipts/sha256/<first-two>/<64-hex>.json
```

Every reviewed leaf uses its exact kind-specific object namespace and raw-byte
address. In particular, projection recipes use
`objects/projection-recipes/sha256/<first-two>/<64-hex>.json`. The only
non-object reviewed documents are dataset manifests, release manifests, and
immutable catalog release pointers at their release/dataset identity paths;
their parent descriptor binds their raw bytes.

The receipt omits its own digest. Records, transcripts, deliberations,
provider-reasoning artifacts, data cards, projection recipes, world-pack sources, dataset
manifests, release manifests, active review sets, and catalog pointers also
omit their own raw-byte digest. Dataset manifests are approved by descriptors
in the release manifest. The immutable catalog pointer approves and binds the
release manifest and active review set. Latest contains only a reviewed
descriptor for that immutable pointer.

Release history is explicit. Genesis is sequence `1` with a null predecessor.
Every later release names the prior release ID, includes its raw catalog
pointer descriptor, and advances exactly one sequence. The current catalog
pointer repeats that identity and predecessor digest. Validation of a
non-genesis release also requires a caller-supplied trusted predecessor anchor:
the descriptor, pointer bytes, release identity, sequence, and immutable
referenced closure must equal the trusted base branch.

The active review set contains content-bound receipt nodes and declared heads.
Semantic validation rejects duplicate references, forks, cycles, stale heads,
rejected heads, non-head artifact references, and incomplete receipt/artifact
closure.

Provider-exposed reasoning is optional. Its shard receipt must use
`approve_public`, set `providerRedistributionApproval.approved` to true, and
bind the same `provider-terms` bytes referenced by the reasoning artifact.

The trust policy pins the exact canonical bytes of the closed v2 rights
registry. Record provenance resolves through that registry; unknown, revoked,
rights-basis-mismatched, source-type-mismatched, or incompletely attested
statements fail closed.

## Incremental publication

The five-file hard limit applies to every v2 publication PR:

- An artifact batch adds at most five immutable files. One or more changed,
  content-addressed receipts must cover every changed non-receipt artifact
  exactly once. Unchanged dependencies resolve only through exact descriptors.
- Release activation changes at most five reachable control files and includes
  `catalog/latest.json`. The complete graph is validated across changed and
  pre-existing immutable files; payload artifacts and manifests are published
  in prior reviewed batches.

## Canonical JSON v2

`scripts/contracts/canonical.py:canonical_json_v2` defines the project format:
strict UTF-8, NFC strings and keys, sorted object keys, compact separators, no
floating-point numbers, and one terminal LF for stored JSON and JSONL lines.
Unicode key collisions, duplicate source keys, NaN, and Infinity are rejected.
Array/object nesting is deterministically limited to 64 containers.
This project format does **not** claim RFC 8785 compatibility.

Schemas and the public policy are loaded only from the trusted base checkout.
Candidate files cannot extend the schema registry. JSON Schema handles closed
shape validation; `scripts/contracts/release_trust.py` enforces byte paths,
hashes, counts, review supersession, approval, and graph closure.
Steady-state CI additionally passes candidate schemas, policies, and templates
through a trusted-base vector harness, then runs candidate v2 tests separately
without credentials against a read-only checkout.
