# D02 Counterfactual Multiverse — Data Card Template

**Status:** scaffold; complete all release fields before publication.

## Release identity

- **Dataset ID:** `d02`
- **Unit:** one control/treatment world pair
- **Version and source revisions:** `[required]`
- **Scenario count and shard hashes:** `[required]`

## Composition

Describe worlds, base-state distribution, intervention paths and operators,
replay lengths, outcome surfaces, split policy, exclusions, and duplicate
handling.

## Pair construction

Document canonicalization, seed derivation, intervention assignment, proof that
the control remains untouched, shared replay semantics, state hash algorithm,
and contrast computation. Identify any intervention whose effect is later
overwritten by a shared operation.

## Deliberation and reasoning

`deliberation` is an explicitly generated, publishable decision surface.
Optional exposed-reasoning references require separate review and
redistribution permission. Hidden reasoning must not be requested or inferred.

## Intended uses

Causal evaluation, deterministic planning, counterfactual prediction, replay
verification, intervention robustness, and paired playable worlds.

## Invalid uses

Do not claim real-world causality, mix unequal replay policies, infer private
mental state, or treat an unreviewed contrast as scientific ground truth.

## Risks and limitations

Document simulation misspecification, limited interventions, path collisions,
overwritten effects, deterministic-policy artifacts, and external validity.

## Release checklist

- [ ] Every control/treatment pair replays from one identical base.
- [ ] Exactly one isolated treatment intervention is declared.
- [ ] All state and replay hashes verify.
- [ ] Governance, PII, and review gates pass.
- [ ] Synthetic smoke outputs are absent.
