# Data card: D07 Conservation and Order

## Summary

D07 is a synthetic deterministic benchmark for ordered replay and conservation
reasoning. Each record begins with four fictional accounts and applies a tape
of valid transfers. The total quantity is closed and therefore invariant.

## Intended uses

- replay ordered events to derive final state;
- validate a previous-event hash chain;
- distinguish local balance changes from global conservation; and
- render a transaction-order puzzle.

This is not a financial dataset and must not be presented as financial advice,
market behavior, or evidence about real transactions.

## Generation and provenance

The standard-library generator derives each record's RNG seed with SHA-256.
Transfer amounts are bounded by the source balance, so canonical tapes never
overdraw. No external state, services, or identities are used.

## Labels

`oracle.conserved` and `oracle.ordered` are the primary labels.
`oracle.initial_total`, `oracle.final_total`, and `oracle.final_state` provide
replay targets. Structured reasoning references point directly to the initial
state, tape, and oracle. Three explicitly public synthetic URIs expose the
observation, inference, and decision reference layers without private
chain-of-thought.

## Limitations

The scaffold models only integer transfers in a closed system. It does not
cover exchange rates, fees, concurrent commits, or real accounting rules.

## Release policy

Generated JSONL and manifests are ephemeral build artifacts. This scaffold
commits no release records.
