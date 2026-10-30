# Stable schema cache test — 2026-10-29

BI2 completed 116 claims with no cached input. All 59 continuations changed their output schema. This experiment tests that specific candidate cause; it does not assume that stabilizing schemas will guarantee cache hits.

The official [prompt caching documentation](https://developers.openai.com/api/docs/guides/prompt-caching) specifies a minimum of 1,024 visible input **tokens**, not bytes, for GPT-5.6 and later. The entire rendered prefix must match through an eligible cached breakpoint. Merely preserving its first 1,024 tokens is insufficient. Output-format instructions participate in that prefix. The existing CLI launcher already resumes the same thread and appends new evidence messages; this behavior stays unchanged.

## Frozen comparison

Study: `C:/dmitry/scan-runs/stable-schema-20261029-bj`.

Terra 6.1 medium, two fresh independent arms run concurrently with the same pinned runtime, native scanner, current package, evidence and model settings. One worker per arm. Original BI2 bundles 1, 3, 11, 14 and 24: 27 claims in five bundles, including authority and credential mechanisms, YAML trust boundaries, parameterized SQL and unresolved MarsDB behavior, and XXE. No regrouping, helper, new guidance or injected dependency source. No artificial warmups. Fresh threads are not asserted to be cold caches; provider cache routing is shared and not experimentally controlled.

Dynamic control sends the existing turn-specific schema. Stable treatment sends the existing unbound continuation schema. Both validate the response against the exact original turn-specific schema locally, then use the unchanged envelope and native source/claim validation. This isolates the wire-schema difference while keeping the extra validator common to both arms. Dynamic handles, query ceilings, final-only behavior, authority checks and static claim IDs are still enforced. Invalid results remain invalid: no new repair instruction or relaxed fallback is introduced.

Usage and continuation state are persisted before local validation, including when it rejects a response. Raw responses, wire/local schemas and tasks are retained privately per round; public receipts record schema hashes and rejection paths. The study wrapper does not modify or promote product defaults. Its pinned JSON Schema validator is installed only in a private study directory; all dependency files are frozen.

The original allowances remain 6 calls / 24 query units / 512 KiB per bundle, 900 seconds per bundle, and 30 calls per arm. No aggregate time/token censor. Stop new dispatch on unknown paid usage or frozen-input drift. Do not silently retry an incomplete arm. Complete valid claims remain useful if results are mixed.

## Readiness and evaluation

Before inference: verify original bundle membership and exact initial source windows; prove stable hashes across changing handles/budgets; test valid resumed calls, unknown handles/IDs, extra fields, query ceilings, final-only constraints, malformed CWEs, authority-check requirements and paid rejected-response accounting. No model calls in these tests.

Report per-call and token-weighted caching, initial/continuation splits, cache writes, total published Standard price equivalents, provider time and end-to-end elapsed. Reconcile raw provider receipts independently. Compare all 27 outcomes and source-supported mechanisms, not just labels or completed-call prices; preserve unresolved questions and inspect new dismissals. Distinguish lookup failures, local schema rejections and native finalization failures.

Advance to a wider test only if the stable arm shows a substantial cache/cost improvement (working target: at least 30% lower total price), with complete coverage and no demonstrated loss of a supported mechanism or new wrong dismissal. A rejection or mixed outcome calls for a narrow repair/retest, not discarding the approach. If cache stays poor, inspect actual message-prefix/breakpoint behavior before another live rerun. Speed is secondary to quality and total price. One paired slice cannot establish general quality equivalence.

Preparation notes: an empty source-profile target list was rejected offline; no selected bundle uses that profile, so it was omitted. Narrowing the population changes native bundle fingerprints; membership and exact content, rather than fingerprint equality, establish parity. No live calls were spent on preparation corrections.

After this cache test, return to the [targeted completion plan](../review-targeted-completion-plan-2026-10-29.md). Keep native SQL closure and selective shared investigations; this experiment does not generalize review modes.
