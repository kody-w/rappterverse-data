# D07 projection: Ledger Relay

`recipe.json` turns a D07 transfer tape into a marketplace replay puzzle.
Players carry transfer tokens between four account plinths in strict sequence.
Each accepted move lights the event-hash chain. The final gate opens only when
all balances and the conserved total match the oracle.

The projection is read-only with respect to the dataset record. Round state is
local and can be discarded or replayed from the record seed.
