# D04 Verified Agentic Work Trajectories — Data Card Template

**Status:** scaffold; complete all release fields before publication.

## Release identity

- **Dataset ID:** `d04`
- **Unit:** one complete visible agentic work episode
- **Version / generator revision:** `[required]`
- **Trajectory count and shard hashes:** `[required]`

## Composition

Describe task families, languages, repositories, tools, patch sizes, verifier
types, outcomes, splits, exclusions, duplicate handling, and failure coverage.
Only synthetic or RAPPterverse-owned tasks may be included.

## Capture completeness

Document how system/user/assistant messages, tool arguments/results, patch
content, verifier output, and final outcomes were captured and redacted. State
why every published record is both complete and public-safe.

## Verification

Describe patch-hash checks, tool-result checks, verifier reproducibility,
outcome adjudication, environmental constraints, and known nondeterminism.

## Deliberation and reasoning

`deliberation` is explicitly generated for publication. Optional
provider-exposed reasoning references require redistribution review. Hidden
reasoning must never be requested, inferred, or substituted for missing data.

## Intended and prohibited uses

Suitable for tool-use evaluation, patch verification, task planning,
trajectory retrieval, and playable workbench quests. Do not use it to recover
secrets, reproduce unsafe commands, identify operators, or infer private
reasoning.

## Release checklist

- [ ] All capture flags are true and independently verified.
- [ ] Patch and verifier hashes recompute.
- [ ] Tool arguments/results pass secrets and safety review.
- [ ] Outcomes have evidence and artifact references.
- [ ] Governance/PII checks pass.
- [ ] Synthetic smoke output is absent.
