# V2 release templates

These JSON files document exact v2 field names. Angle-bracket values are
placeholders, not publishable artifacts. A publisher must replace every
placeholder, encode stored JSON with `canonical_json_v2(..., stored=True)`,
compute descriptors from the resulting raw bytes, and validate the complete
graph. Templates never contain a self hash or an inline review decision.

Projection recipes are formal reviewed artifacts stored only at
`objects/projection-recipes/sha256/<first-two>/<digest>.json`. Release pointer
templates show the genesis chain; sequence 2 and later must identify and bind
the immediately preceding immutable catalog pointer from the trusted base
latest document. Receipt `approvedArtifacts` must exactly cover the
non-receipt files in an artifact batch. Each artifact or activation PR remains
subject to the five-file hard limit.
