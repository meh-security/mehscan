# Terra full Juice Shop cache measurement — 2026-10-29

Status: **complete, 116/116 source-validated dispositions, 84/84 provider receipts reconciled**. User requested a full Terra rerun with cache, cost and time measurement after the interrupted helper-isolation study. This run received **zero cache hits**; it does not demonstrate cache savings.

## Result

| Metric | Stored Terra native | Current Terra native rerun |
|---|---:|---:|
| Claims / native bundles | 116 / 25 | 116 / 25 |
| Provider calls | 88 | 84 |
| Total input tokens | 3,274,578 | 3,120,380 |
| Cached input tokens | 12,032 | **0** |
| Token-weighted cache fraction | 0.367% | **0%** |
| Output tokens | 59,512 | 58,116 |
| Standard API cost equivalent | $3.5607076 | **$3.410960** |
| Standard Codex credit equivalent | 89.01769 | **85.27400** |
| Summed provider time | 17m 12s | **16m 19s** |
| Full review execution elapsed | 19m 59s | **18m 18s** |
| Issue / not_issue / needs_review | 44 / 42 / 30 | 42 / 47 / 27 |

The rerun cost 4.2% less and completed 8.5% faster. **Neither improvement came from measured cache reuse.** Runtime, existing format/recovery fixes and model-run variation prevent assigning the difference to one cause. The same receipts repriced without cache discounts also cost $3.410960: the measured cache discount is exactly $0.

Successful preparation took another 22.29 seconds, separate from the review execution. This does not include all operator analysis/setup time. There were no live retries or unknown paid calls. All reported cache-write counters were explicitly zero; the largest call had 90,210 input tokens, below the long-context pricing threshold. Prices are published Standard equivalents, not invoice charges; the [Terra pricing page](https://developers.openai.com/api/docs/models/gpt-6.1-terra) specifies $1/M input, $0.05/M cached input and $5/M output.

Initial calls used 561,365 input tokens and cost $0.616685. The 59 continuations used 2,559,015 input tokens (**82.0% of input**) and cost $2.794275. Every continuation changed its output-schema hash relative to the prior turn. The large continuation bill and absent cache reuse remain the relevant cost problem.

Verification reconciled all 84 raw provider event streams with the per-call deltas, checked all 337 exported source excerpts against physical bytes, verified source/runtime hashes and unchanged native admitted work, and matched all 25 initial packets. The full review package exists; this is not a partial-run price comparison.

Artifacts: `comparison.json` contains phase/rule-set accounting; `claim-comparison.json` preserves both results for all 116 claims; `observations.jsonl` contains every offered call and receipt. They are under the run directory below. A separate closure manifest hashes the completed artifacts.

## Quality differences to retain

Thirteen verdicts changed: five issue → needs_review, three needs_review → issue, and five needs_review → not_issue. This is not evidence of equal or improved quality. Source validation establishes valid references and package structure, not semantic correctness.

| Claim suffix | Change | Material difference |
|---|---|---|
| `262317b675829863` | issue → needs_review | Broad generated-CRUD review shifted from administrative registration to unresolved basket ownership; do not count this as preserving the registration mechanism. |
| `ba583b9dd72566ed` | issue → needs_review | Basket ownership mechanism remains, but model/hooks were unread when the query budget ended. |
| `26fdb36787840417` | needs_review → not_issue | YAML fix metadata: absence of an established lower-trust writer now closes the claim. |
| `4ba7b6d946e5c9d9` | needs_review → not_issue | YAML RSN metadata: same trust-boundary closure concern. |
| `57b7e3fa1f3c163b` | needs_review → not_issue | YAML CLI lint: same trust-boundary closure concern. |
| `8aef4b93c57c4b32` | needs_review → not_issue | YAML snippet metadata: same trust-boundary closure concern. |
| `b668efbfecb92de6` | needs_review → issue | Public log index now reports access-log filename exposure. |
| `e423b09f6e9efd20` | needs_review → not_issue | Well-known index treated as published security metadata. |
| `0420b4d41a5ad0d7` | issue → needs_review | Review-update selector mechanism retained; MarsDB operator interpretation unresolved. |
| `64fb2337e4bd00bd` | issue → needs_review | Order-tracking `$where` construction retained, with dependency semantics unresolved. |
| `7576e8ab5c778f14` | issue → needs_review | Product-review `$where` construction retained, with dependency semantics unresolved. |
| `3dac0ddb94de0f62` | needs_review → issue | ZIP traversal linked to subtitle content inserted into promotion HTML. |
| `c200c14fa5ec441e` | needs_review → issue | Registration email linked to trusted HTML in the administration table. |

The YAML dismissals and lost registration mechanism are review targets, not accepted improvements. The new positive chains also need semantic comparison before promotion. This measurement leaves the targeted-completion direction intact; it does not replace the saved baseline with the new package by default.

## Scope and comparison

Run directory: `C:/dmitry/scan-runs/terra-full-cache-20261029-bi2`.

Terra 6.1 medium, native review, all 116 original claims in 25 original native bundles (default maximum 20). Initial source windows and bundle membership exactly match the saved BC preparation. No evaluator dependency source is injected. This is a validation-only experiment; it does not admit results into the native work state.

Provider caching uses its existing automatic behavior. No warmups, extra helper, stable-schema modification or prompt rewrite is included. This is a measured native rerun, not a cache optimization treatment. A fresh conversation is not proof of a cold cache.

The runtime is now `codex-cli 0.165.0-alpha.1.2`, copied to a private directory outside the app updater. The former pinned executable disappeared during an app update, interrupting BH. The runtime change means this comparison cannot isolate cache as the cause of a cost or latency change. The detached runner requests Windows idle-sleep prevention only while active.

The package also includes the already-existing CWE-format and finalization-recovery fixes developed since BC/BD. A file comparison found two changed files: `codex_protocol.py` constrains CWE syntax; `review_worker.py` supports bounded citation/CWE correction and validates retained candidates before recovery. The scanner and all other packaged files match. No changes were made to these files for this run. Thus “unchanged” refers to the current native workflow, not byte identity with the older baseline; `package-differences.json` records the distinction.

The full run has no aggregate input/output-token or elapsed-time censor. Original finite per-bundle allowances remain: 6 calls, 24 query units, 512 KiB returned JSON, 900 seconds. Native total allowances remain 150 calls, 600 query units and 12.5 MiB returned JSON. Unknown prior usage blocks further dispatch.

The first BI preparation failed offline because workspace preparation rejects unlimited experiment settings. It made zero model calls and remains preserved. BI2 uses the established execution-only allowance overlay after verifying the frozen preparation, and passed readiness with zero model calls.

## Measurement

- Per-call total input, cached input, uncached input, output, cache-write counters, provider time, conversation/round and output-schema hash.
- Token-weighted cache fraction and calls with cache, separately for initial and continuation calls.
- Full-run elapsed time and preparation time, distinct from summed provider time.
- Published Standard API-dollar and Codex-credit equivalents, using the same rate basis as the saved comparison. These are not account invoices.
- The same receipts repriced without the cache discount, labeled as a counterfactual rather than a measured cache-disabled run.
- Every final claim and exported source excerpt, plus exact decision/severity differences against the stored native result. Structural/source validation is not a semantic accuracy score.

Saved native Terra baseline: 88 calls; 3,274,578 input, 12,032 cached input (0.367%), 59,512 output; $3.5607076 Standard API equivalent / 89.01769 Standard Codex credits; 17.20 minutes provider time and 19.99 minutes outer elapsed; 116 dispositions (44 issue, 42 not_issue, 30 needs_review).

## Cache hypothesis to retain

Native review varies its output schema as evidence handles and remaining budgets change. The isolated BH diagnostic used a stable schema and showed much higher cache fractions, but its prompts and task scope also differed. Official [prompt caching documentation](https://developers.openai.com/api/docs/guides/prompt-caching) confirms that structured-output schemas contribute to the cached prefix. Schema churn is therefore a plausible investigation target, not an established cause or an already validated fix.

If this unchanged full run again has little cache reuse, the next bounded treatment should stabilize the provider-facing schema while retaining exact current handle, budget and final-turn constraints in local validation. Paid usage must be persisted even when local validation rejects a response. Test those invariants offline before spending on a matched slice. Do not attribute BH savings solely to helpers or assume native caching is disabled.

The prior targeted-completion plan remains the broader quality/price plan. This measurement does not replace its quality gates or authorize a generalized workflow rewrite.
