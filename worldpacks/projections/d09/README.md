# D09 projection: Memory Recovery Console

`recipe.json` maps a simulated D09 trace to a dungeon control console. Players
classify a represented fault, arrange operation cards in canonical order, and
deduplicate them before replaying against a local in-memory state.

The recipe forbids real fault injection. A projection may animate only the
recorded trace and local round data; it must not manipulate networking,
processes, files, resource limits, or authoritative world state.
