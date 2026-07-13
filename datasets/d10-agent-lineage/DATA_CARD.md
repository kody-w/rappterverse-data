# Data card: D10 Software-Agent Lineage

## Summary

D10 is a deterministic synthetic benchmark for provenance reasoning over
software-agent derivation DAGs. Nodes represent fictional software instances
and immutable artifact digests. Edges represent fork or merge derivation.

## Intended uses

- validate acyclicity and parent existence;
- derive a topological order and generation depth;
- recover the ancestors of a target software agent;
- distinguish a fork from a multi-parent merge; and
- render a navigable lineage constellation.

## Scope and safety

This dataset is strictly about software provenance. It contains no human
genealogy, employee evaluation, demographic inference, biological claims, or
real identities. Agent names and artifact hashes are synthetic.

## Generation and labels

The independent standard-library generator chooses parents only from nodes
already emitted. SHA-256-derived per-record seeds make DAGs stable across
checkpoint/resume. `oracle.acyclic`, `oracle.topological_order`,
`oracle.max_generation`, and `oracle.target_ancestors` are independently
checked by the verifier.
Observation, inference, and decision references use explicitly public
synthetic URIs and never reconstruct private reasoning.

## Limitations

The model excludes deletion, mutable ancestry, and cyclic dependency systems.
It is a provenance benchmark, not a software supply-chain security attestation.

## Release policy

Generated records are ephemeral. No dataset release is committed with this
scaffold.
