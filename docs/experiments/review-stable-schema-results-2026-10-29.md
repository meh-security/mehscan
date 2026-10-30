# Stable schema cache results — 2026-10-29

**Complete matched Terra 6.1 medium slice: 27/27 claims in both arms. Stable schema reduced total price by 61.4%, with no local-schema rejections and identical verdicts and severities.** Keep this variant and validate it more broadly; this is not a production-default promotion or proof of general quality equivalence.

Live artifacts: `C:/dmitry/scan-runs/stable-schema-20261029-bj2`, arms `dynamic-checked` and `stable-checked`. The earlier BJ wrapper attempt made zero provider calls. The [frozen plan](review-stable-schema-plan-2026-10-29.md) describes the comparison and gates; the implementation is study-only, inside each bound skill package. Product defaults remain unchanged.

## Price, cache and time

| Metric | Dynamic schema control | Stable schema |
|---|---:|---:|
| Claims / original bundles | 27 / 5 | 27 / 5 |
| Provider calls | 22 | 24 |
| Input tokens | 942,545 | 977,641 |
| Cached input tokens | 0 | 701,056 |
| Token-weighted cache fraction | 0% | **71.71%** |
| Continuation cache fraction | 0% | **80.62%** |
| Output tokens | 17,279 | 17,153 |
| Standard API price equivalent | $1.028940 | **$0.3974028** |
| Standard Codex credit equivalent | 25.72350 | **9.93507** |
| Provider time | 4m 46s | 4m 53s |
| Review elapsed | 5m 26s | 5m 35s |
| Local-schema rejections | 0 | 0 |
| Issue / not_issue / needs_review | 10 / 7 / 10 | 10 / 7 / 10 |

Stable used two additional calls and 3.7% more input. Repricing its same receipts without cache discounts gives $1.063406, slightly more than the dynamic arm. The observed cache discount was $0.6660032, turning that extra work into a **61.4% lower total price**. This repricing is a counterfactual, not a separate cold run. The two live arms together cost $1.4263428 Standard API-equivalent. Prices are estimates using published Standard rates, not invoice charges. All cache-write counters were explicitly zero, and no long-context multiplier applied.

There was no speed improvement: stable took 9.07 seconds longer end to end. This passes the price objective while retaining the actual time tradeoff. Preparation/operator analysis time is separate and not included in these execution times.

For historical context, the identical selected BI2 bundles cost $0.850904 in 20 calls. Stable is also 53.3% cheaper than that stored slice. The fresh dynamic control did more work than BI2, so historical comparison alone would not isolate the treatment.

All five initial calls missed cache in both arms. **All 19 stable continuations hit cache; all 17 dynamic continuations missed.** Stable had one wire-schema hash per conversation; dynamic changed its schema on each continuation. This is strong evidence for the schema change as a useful cache intervention in this workflow, while provider routing and model variation remain uncontrolled.

## What the 1,024 rule means

The official [prompt caching documentation](https://developers.openai.com/api/docs/guides/prompt-caching) specifies **tokens, not bytes**. Cache eligibility and prefix/breakpoint matching matter; a matching first 1,024-token substring alone does not guarantee a hit. The CLI resumes existing threads and appends messages. The treatment preserves that behavior and stabilizes the wire schema rather than padding prompts.

The five initial prompts were compared line by line. Differences were limited to the legitimately different bound skill/package IDs and the fractional `seconds_remaining` values. Source, review instructions and questions matched. No extra guidance or dependency source was supplied to either arm. `prompt-parity-audit.json` records the exact differing JSON paths.

## Quality and limitations

All 27 verdicts and all diagnosis severities match. The paired source review found no supported mechanism lost by the stable treatment and no new treatment-only dismissal. Important comparisons:

- Both retain basket-item ownership failure and public registration role assignment. Dynamic emphasizes `admin`; stable uses the accepted `accounting` role and its role consumer, while also describing the non-blocking admin challenge. The user model accepts both roles. This is a supported difference in example, not identical prose.
- Both retain unbound SQL in login/search, including the login second-factor qualification. Both identify multi-review selector injection using the same API test assertion. Tests were read as source, not executed.
- Both keep four YAML trust-boundary questions unresolved. They also preserve six unresolved MarsDB/like-route claims rather than force a safe or exploitable verdict. The exact deciding questions differ; complete results are retained.
- Both preserve optional current-password proof, conditional forwarded-address rate-limit bypass, decoded chat identity with its order-tool effect, and XML entity expansion before the later error response. Stable explicitly qualifies chat-tool invocation and XXE disclosure through error handling.
- Both retain the local owner/password predicates and the separate JWT route gates. **Agreement is not proof that their broad negative conclusions are correct:** the prior dependency audit still requires exact legacy verifier behavior and independent gates to be considered.
- Both repeat the unsupported “issued six-hour JWT” premise in the session-cache finding. The [prior dependency work](review-subagent-isolation-results-2026-10-29.md) distinguished the applicable JWT option/version contracts. Unbounded cached authorization remains relevant, but these particular expiration explanations still need correction. Cache optimization does not replace targeted evidence completion.

Correction to the frozen plan's wording: the selected database bundle contains **raw-SQL positives**, not parameterized-SQL clean controls. The slice includes local authorization controls and unresolved cases, but broader testing must include the omitted parameterized-query/ORM controls. No population was changed after seeing live results.

## Verification and implementation

All 46 provider receipts were independently reconciled against raw event counters, including exact cumulative-to-per-turn deltas. All 46 local schema checks accepted. Native source validation produced 27 dispositions per arm; 78 dynamic and 79 stable exported source excerpts matched physical bytes. Both native admitted work packages remained unchanged, and frozen source/runtime/package/dependency hashes matched. There were no live retries or unknown paid calls.

The stable arm sends the existing unbound schema, then validates against the original exact turn-specific schema locally, after usage persistence and before the normal envelope/controller. Static IDs and format rules, current handles, current query/final-turn constraints, authority checks and source validation remain enforced. Both arms use the same private pinned JSON Schema validator. The extra dependency is an experiment fixture, not an unreviewed product packaging decision.

Offline checks covered resumed conversations, schema stability, invalid handles/IDs, unexpected fields, query ceilings, final-only behavior, malformed CWEs, required authority checks and paid rejected-response accounting. End-to-end native preflight reached all five provider boundaries per arm with inference blocked. Two preparation problems were corrected without paid calls: native binding rejected an external wrapper, so it was moved into the skill before binding; schema diagnostics were given a filename outside the usage-log glob. Neither native binding nor usage checks were weakened.

Primary artifacts: `comparison.json`, `claim-comparison.json`, `prompt-parity-audit.json`, `quality-audit.json`, per-arm `comparison.json`, and the completed-artifact hash manifest. Private logs preserve each wire/local schema, response and task.

## Next decision

**Keep the stable-schema variant and freeze further prompt/workflow changes for the next test.** It passes the working 30% slice-price gate and has no observed treatment-specific mechanism regression. Next, run full Juice Shop on Terra with this exact variant, including the omitted SQL/ORM controls, UI/output families and remaining singleton cases; compare against BI2 and audit new dismissals/qualifications. Measure cache writes, total cost, elapsed time and any local rejection explicitly. A rejection should trigger a narrow diagnosis, not abandoning the approach or relaxing validation.

Do not assume the 61.4% slice reduction applies to the full application or to Sol. Sol can receive the same paired slice if needed for the later reviewer choice. After broader Terra validation, return to the [targeted-completion plan](../review-targeted-completion-plan-2026-10-29.md), especially version-bound JWT facts, risky dismissals and consequential unresolved mechanisms. Native SQL closure and compatible shared investigations remain separate review choices.
