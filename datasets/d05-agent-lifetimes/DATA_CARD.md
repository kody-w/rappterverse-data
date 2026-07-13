# D05 Complete Agent Lifetimes — Data Card Template

**Status:** scaffold; complete all release fields before publication.

## Release identity

- **Dataset ID:** `d05`
- **Unit:** one complete accelerated synthetic lifetime
- **Version / simulator revision:** `[required]`
- **Lifetime and tick counts / hashes:** `[required]`

## Composition

Describe birth-state distribution, tick cadence, decision/idle balance, world
coverage, memory and goal systems, relationship dynamics, terminal-event
types, splits, exclusions, and duplicate policy.

## Completeness and continuity

Document why every tick is captured, how sequence gaps are rejected, how state
hashes and transitions are verified, and how terminal states join to final
ticks. Incomplete, censored, or naturally observed lifetimes are out of scope.

## Deliberation and reasoning

Each tick and lifetime contains explicitly publishable deliberation. Optional
provider-exposed reasoning references require separate redistribution review.
No inaccessible chain-of-thought may be requested, inferred, or backfilled.

## Intended and prohibited uses

Suitable for long-horizon planning, memory/goal evaluation, state-transition
models, relationship dynamics, and lifecycle quests. Do not equate simulated
termination with real death, infer operator identity or wellbeing, or
generalize synthetic survival patterns to people.

## Risks and limitations

Document acceleration artifacts, simulator bias, deterministic policies,
terminal-condition selection, state simplification, and limited external
validity.

## Release checklist

- [ ] Every sequence starts at zero and has no gaps.
- [ ] All before/after state links and hashes verify.
- [ ] Memory, goal, and relationship aggregates recompute.
- [ ] Birth and terminal events are explicit.
- [ ] Governance/PII checks pass.
- [ ] Synthetic smoke output is absent.
