# D03 Human Judgment Gold Set — Data Card Template

**Status:** scaffold; publication is blocked until every consent and review
field below is complete.

## Release identity

- **Dataset ID:** `d03`
- **Units:** blinded candidate and separately stored consented gold label
- **Version / source revisions:** `[required]`
- **Candidate and label counts / hashes:** `[required]`

## Candidate construction

Describe sampling, blinding, speaker pseudonymization, task categories,
languages, candidate exclusions, duplicate handling, and any residual
re-identification risk.

## Judgment protocol

Document label vocabulary, rubric, reviewer eligibility, randomization,
minimum judgments, consent collection, conflict handling, and withdrawal.
Reviewers must consent specifically to `public_dataset_label`.

## Adjudication and agreement

Document unanimous handling, disagreement adjudication, adjudicator
independence, pairwise agreement, entropy, class balance, and unresolved
candidate policy. No tie or unconsented adjudication may become a gold label.

## Mandatory artifact separation

Candidate JSONL must not contain labels, judgments, reviewers, agreement
metrics, adjudication, or label-consent evidence. Consented labels join only by
`record_id`.

## Deliberation and reasoning

Only explicit publishable deliberation is included. Provider-exposed reasoning
references require independent redistribution review; label consent does not
authorize inaccessible reasoning collection.

## Intended and prohibited uses

Suitable uses include evaluator calibration, rubric research, agreement
analysis, and review-game projections. Prohibited uses include reviewer
identification, surveillance, unconsented labeling, or claims about private
mental state.

## Release checklist

- [ ] Candidate leakage verifier passes.
- [ ] Every published judgment and adjudication has scoped consent.
- [ ] Agreement metrics recompute exactly.
- [ ] Withdrawal/takedown process is active.
- [ ] PII and governance gates pass.
- [ ] Synthetic smoke output is absent.
