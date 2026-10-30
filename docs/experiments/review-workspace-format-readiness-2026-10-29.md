# Workspace citation-format readiness — 2026-10-29

Milestone M2 offline work is complete. The bounded live retest remains pending until the Sol comparison closes. No paid calls were made in this work; product code and active Sol inputs are unchanged.

Artifacts: `C:/dmitry/scan-runs/workspace-format-20261029-bm`.

## Cause and correction

Terra BK's second workspace response used two navigation-result IDs in an answer's evidence list. The stable wire schema permitted arbitrary strings; exact local membership validation correctly rejected the response. Rejection also prevented the other actions in that response from being admitted.

The study adapter now constrains only the four workspace update evidence fields (proposition, applicability, answer and focus) to positive numbered source aliases, matching `review_workspace_bridge.py`'s `source1`, `source2`, … generation. The pattern is `^source[1-9][0-9]*(?![\s\S])`; the final assertion excludes trailing characters, including a newline. This narrows the provider's valid output space without embedding the changing handle list.

Native schemas, path/line decision citations, lookup arguments, prompt text and local exact schemas are unchanged. A well-formed alias such as `source999999` is still rejected locally unless actually offered. Source syntax does not prove availability or relevance.

## Verification

- The exact saved BK response passes its original wire schema and fails both the new wire schema and the unchanged exact local schema. It was not repaired or admitted.
- Removing the new evidence patterns reproduces the original wire schema exactly; no other schema field changes.
- All four evidence fields accept generated aliases and reject navigation IDs, zero/negative/leading-zero aliases, whitespace and suffixes.
- The schema hash stays identical when offered claims shrink, handles change and query budget reaches zero.
- Fake-provider calls demonstrate valid acceptance and local rejection of malformed/unavailable citations with usage receipts retained. Elapsed time is checked at the top level of the receipt, avoiding the earlier recovery-wrapper bug.
- Existing adapter suites pass: 13 native checks and 13 workspace checks. Six additional format/replay checks pass. Fourteen fake calls across the workspace suite and new receipt cases made no provider requests.
- Scheduling regression preserves a failed group's paid tokens, elapsed time, model-call/query/byte charges and timers while allowing an independent offer. Failed redispatch and unknown-usage dispatch remain blocked.
- Every frozen Sol source/runtime/input hash still matches. The live runners were not modified.

Artifacts include `format-verification.json`, `offline-verification.json`, `workspace-offline-verification.json` and `isolation-verification.json`. The new stable workspace schema hash for the replay is `394fc2b72834f77ba59e9bb6efd579776fe7f8dfe2eceaeedb465c5ec2f20d22`.

## Live gate

JSON Schema validation here establishes the intended restriction, not provider acceptance of this pattern or a reduction in live failure rate. After M1, prepare fresh bound state for the same eight-claim workspace group, freeze this single schema change and preserve the same evidence/routing. Check provider schema acceptance before interpreting review quality. If the provider rejects the pattern, correct the compatible format constraint offline and record the attempt; do not weaken local evidence validation.

Measure accepted coverage, rejections, source-supported mechanisms, cached input, all usage, price and elapsed time. A schema change may alter cache reuse. Retain failed-call spend and explicit execution gaps; do not splice the retest into BK's original timing or promote this study adapter directly to product defaults.
