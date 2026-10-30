# Two-consumer receipt-reuse validation — 2026-10-29

Both Terra arms completed 13 JWT/authentication claims. The new receipt-reference API delivered the same source and preserved separate consumer questions, provenance and expiry qualifications. **This run does not demonstrate cheaper model review:** direct preparation cost $0.127680 and receipt reuse $0.139438. Keep the opt-in API as a controller/provenance convenience; do not promote it as an efficiency default.

Artifacts: `C:/dmitry/scan-runs/evidence-reuse-20261029-bt`. The [frozen plan](review-evidence-reuse-live-plan-2026-10-29.md) distinguishes this real workspace-evidence integration from native scanner admission. The source tree is a fresh hash-preserving diagnostic catalog of application and versioned vendor files, not an installed dependency tree or proof of deployment resolution.

| Metric | Direct preparation | Receipt reuse |
| --- | ---: | ---: |
| Completed claims | 13 | 13 |
| Calls / reconciled receipts | 8 / 8 | 9 / 9 |
| Input / cached input / output | 305,183 / 221,440 / 6,573 | 356,630 / 264,960 / 6,904 |
| Cached-input fraction | 72.56% | 74.30% |
| Standard API equivalent | $0.127680 | $0.139438 |
| Same usage without cache discount | $0.338048 | $0.391150 |
| Base plus review | $1.6904448 | $1.7022028 |
| Arm elapsed | 108.809s | 120.233s |
| Lookups | 31 | 37 |
| Source stored in evidence workspace | 15,755 bytes / 8 records | 15,755 bytes / 8 records |
| Source citation checks | 103 | 95 |

All known cache-write counters were zero. These are published Standard equivalents, not invoices. Concurrent arms may share cache routing. Total study inference equivalent was $0.267118. Preparation/operator analysis is outside arm elapsed; offline evidence preparation took 40/44 ms, too small and uncontrolled to infer a speed difference.

## What the handoff actually proved

The original API already deduplicates repeated source captures. Reuse therefore does not improve source storage over direct preparation. It lets the controller reference an existing receipt rather than restating the paths/hashes, and records `reused_from` with the original work and receipt. The recipient keeps its distinct deciding question.

Rendered source and first-pass proposals are identical for both consumer groups. Actual producer model tasks are identical; recipient tasks differ only in deciding-evidence receipt/provenance metadata. Frozen evidence databases remain unchanged throughout inference. No judgments, applicability, answered questions, model usage or new authority were transferred. The model's usage is accounted in the diagnostic ledger. Initial source still appears in each independent reviewer context.

Authorization used five calls in direct and six in reuse even though its producer task is identical. This accounts for the one extra call and cannot be attributed to the recipient handoff. Credential review used three calls in each arm. Recipient input was 93,974 versus 95,529 tokens, with 58,112 versus 57,984 cached. Neither result demonstrates less input or review work from reuse. A single stochastic/cache-affected comparison does not establish that the API causes a price regression either.

## Quality and integrity

Both arms distinguish configured signing duration from the expiration actually emitted by the versioned signer, and retain map-based acceptance without a bounded deadline while the entry remains present. Both keep dependency-resolution qualifications and independent caller checks. No root-signer lookup is repeated, because both arms already receive that source.

The only verdict disagreement is quantity deletion: direct retains `needs_review`; reuse reports an issue conditional on dependency resolution, accounting-role acceptance and the IP filter. Both preserve the independent IP restriction. This label difference is not scored as a quality improvement. The other 12 verdicts agree. Conditions and flow explanations remain available for review rather than silently replacing first-pass results.

All 17 calls reconcile with raw per-turn/cumulative usage, every reply satisfies the same schema, and all 198 cited ranges across arms are within delivered hash-checked source. Frozen source/runtime/config/evidence hashes match. The diagnostic packages retain 103 unselected base results plus the 13 amendments. No native product admission or full-application precision claim is made.

`comparison-audit.json`, `handoff-audit.json`, `claim-comparison.json` and the per-arm packages preserve the evidence and accounting.

## Decision

The implementation/integration gate passes. The model-cost or critical-path savings gate does not pass on this run. Keep the bounded API available for deliberate reuse; leave ordinary routing and native SQL closure unchanged. Do not add a producer agent or broad memory preload to manufacture a benefit.

Next: bounded concurrency of unchanged independent review groups, with explicit shared-budget reservations and failure handling. Keep prompts, source preparation, model and grouping fixed so scheduling can be assessed separately. Broader automatic reuse still needs a relevant contract-selection policy and fresh-application validation; this result does not supply either.
