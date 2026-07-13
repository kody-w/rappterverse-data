# Data card: D09 Safe In-Memory Fault Recovery

## Summary

D09 is a deterministic synthetic benchmark for reasoning about recoverable
message-delivery faults. Every scenario is represented and executed as Python
data in memory. Recovery replays canonical operations once and in order.

## Intended uses

- recognize duplicate, reordered, unacknowledged, and transient-error traces;
- choose deduplication, retry, and ordering-buffer responses;
- derive the exactly-once final state; and
- drive a safe recovery-console game.

## Safety boundary

The generator never induces actual faults. It does not kill processes, alter
network interfaces, exhaust resources, corrupt files, or modify repository
state. The only I/O is normal dataset/checkpoint output selected by the caller.

## Generation and labels

The standard-library generator uses a SHA-256-derived seed for each record.
`oracle.final_state`, `oracle.exactly_once`, and `oracle.recovered` are computed
from the canonical operation tape. Reasoning is represented as three compact
layers of JSON Pointer references plus three explicitly public synthetic URIs,
not hidden chain-of-thought.

## Limitations

The in-memory model is single-threaded and intentionally small. It does not
claim to validate a production distributed system or its operational controls.

## Release policy

This is scaffold-only. Generated JSONL is kept in temporary or ignored build
directories; no release data is committed.
