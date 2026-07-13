# Data card: D08 Fictional Governance Oracle

## Summary

D08 tests whether a system can apply an explicit fictional rule set to a set
of ballots. Cases cover approval, quorum failure, threshold failure, and
fictional guardian vetoes. The generator deliberately balances these modes by
record index.

## Intended uses

- compute quorum and decisive-vote ratios;
- identify which rule controls an outcome;
- cite rules and ballots in a compact decision explanation; and
- power a cooperative council-chamber game.

## Safety and exclusions

All institutions and proposals are invented. D08 is not legal, electoral,
civic, or policy advice. It contains no real officeholders, jurisdictions,
political parties, or laws. Do not map labels onto real governance disputes.

## Generation and provenance

The independent standard-library generator uses SHA-256-derived per-record
seeds. The oracle is a transparent pure function over the embedded rule set and
ballots. It reads no live repository state.

## Labels

`oracle.approved` is the final label. Supporting labels include
`quorum_met`, `threshold_met`, `veto_triggered`, and the exact vote counts.
The three reasoning layers reference the embedded rules, member roster,
ballots, and oracle. Their synthetic URIs are marked explicitly public; no
private rationale is inferred.

## Limitations and release policy

Rules are intentionally small and do not represent the ambiguity of real
institutions. Generated records remain ephemeral; no release data is committed
with this scaffold.
