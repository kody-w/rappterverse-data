# Data card: D06 Social Causality

## Summary

D06 is a deterministic synthetic benchmark for paired causal reasoning in
small social simulations. A record contains two fictional worlds that receive
the same exogenous shocks. Treatment assignment to world labels is randomized,
and the oracle is the within-pair outcome difference.

## Intended uses

- recover treatment assignment from structured evidence;
- calculate and explain a paired effect;
- check that common noise is truly shared; and
- project a record into a two-world cooperative game.

It is not evidence about real people, communities, interventions, or policy.
It must not be used to make claims about human behavior.

## Generation and provenance

`generators/d06/generate.py` uses only Python's standard library. A SHA-256
derived per-record seed makes records stable across interruption and resume.
Names and outcomes are fictional. No live RAPPterverse state or user content is
read.

## Fields and labels

`pair.common_noise` is the shared exogenous tape. `pair.worlds` contains one
control and one treatment arm. `oracle.paired_effect` is treatment outcome
minus control outcome. `reasoning` carries evidence references, a compact
inference, and the final label; it does not contain hidden chain-of-thought.
`exposed_reasoning_refs` contains exactly three synthetic, explicitly public
URIs for the observation, inference, and decision layers.

## Limitations

The simulator intentionally has a small, transparent structural model. It is
useful for testing causal bookkeeping, not for estimating externally valid
effects. Labels should be split by `record_id`, with seeds held out when
evaluating generalization.

## Release policy

This directory is scaffold-only. Generated records belong in ignored or
ephemeral output directories and are not committed as releases.
