# D06 projection: Twin Bridges

`recipe.json` maps one D06 record into two visually matched pocket worlds. The
player inspects the shared shock tape, identifies randomized treatment
assignment, and submits the within-pair effect. A renderer can implement the
recipe using ordinary world objects and local round state; it must not mutate
the source record.

Generate records first, select one by `record_index`, then initialize both
world panels from the same `/pair/common_noise` tape. The round is complete
when the player selects both arms and enters the exact paired effect.
