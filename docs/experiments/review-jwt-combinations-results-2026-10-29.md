# Terra JWT guidance/source combinations — 2026-10-29

All four arms completed all 13 JWT/authentication claims. **All four corrected the unsupported six-hour emitted-expiry premise, including the control.** Combined guidance plus prepared source used the fewest calls/lookups and lowest recorded review price, while retaining the source-audited mechanisms and qualifications. Keep it as a promising scoped combination; this single run does not establish a causal quality improvement from guidance alone.

Artifacts: `C:/dmitry/scan-runs/jwt-combinations-20261029-bs`. Read with the [frozen plan](review-jwt-combinations-plan-2026-10-29.md). Terra 6.1 medium, same 13 claims/two original groups, first-pass proposals, full source access, schema and budgets. The proposed 68-claim BR comparison was closed before inference.

## Actual price, cache and time

| Arm | Calls | Input | Cached input | Output | Cache fraction | Review API equivalent | Elapsed | Lookups |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Control | 10 | 317,311 | 227,840 | 7,221 | 71.80% | $0.136968 | 134.848s | 41 |
| Guidance | 10 | 333,350 | 257,792 | 7,118 | 77.33% | $0.1240376 | 130.318s | 43 |
| Source upfront | 10 | 391,455 | 308,992 | 7,143 | 78.93% | $0.1336276 | 119.524s | 39 |
| Combined | 8 | 298,749 | 221,824 | 6,792 | 74.25% | $0.1219762 | 115.366s | 31 |

Relative to control, combined uses 20% fewer calls, 24.4% fewer lookups, 5.8% less input, 10.9% less review price and 14.4% less elapsed time in this run. Its cache fraction is below the other two treatments: optimize complete review cost and quality, not cache percentage. Source-only adds 23.4% input and achieves little price reduction; supplying more source is not automatically efficient.

All amounts use the frozen Standard API equivalents, not invoices. Known cache-write counters were zero. Without the cache-read discount, the same receipts price at $0.353416, $0.368940, $0.427170 and $0.332709 respectively. Concurrent arms may share cache routing; there are no independent cold-cache measurements or synthetic warm-ups.

Base-plus-review package equivalents are $1.6997328, $1.6868024, $1.6963924 and $1.6847410. These include the saved $1.5627648 first pass once and review of these 13 claims only; they are not forecasts for reviewing all 116. Experimental spend across all four arms is $0.5166094. Initial prepared source is included in model input; no helper-model producer cost is hidden.

## Source-informed outcomes

- **JWT cache lifetime:** every arm inspected or was supplied the legacy signer and distinguishes the application's configured duration from the emitted expiration. All retain acceptance by map membership without an enforced deadline while the entry persists. None retains the categorical story of a demonstrated six-hour-expired token being accepted. Each qualifies installed resolution and separate invalidation behavior.
- **Source acquisition:** control and guidance each request the root signer twice, once per group. The source and combined arms request it zero times because it is already supplied. This supports reusing inspected dependency source across compatible consumers; it does not prove that a model-produced shared summary would save cost.
- **Verifier chains:** all preserve version-qualified legacy verification mechanisms rather than treating a random secret as unconditional denial. Top-level cache verification and nested middleware remain separate bindings, with actual transitive/deployment resolution explicitly unconfirmed.
- **Caller controls:** owner predicates remain locally valid against direct parameter substitution, while identity provenance is assessed separately. The 2FA comparison is traced to the cached password field rather than assumed to be an independent database-password check. Basket quantity constraints and generated update effects are retained.
- **Independent gates:** all retain the later accounting and IP restrictions on quantity deletion. Guidance-only returns `needs_review` because IP behavior is unresolved; the other three return an issue conditional on acceptance by that filter. This is the only verdict disagreement. The audit does not count the more closed label as superior, nor claim an unrestricted deletion.
- **Credential peers:** all retain conditional forwarded-address rate limiting, decoded chat identity and omission of current-password verification. The combined chat assessment explicitly distinguishes passing an order-ownership comparison from guaranteed disclosure through the model/service output.

Control, source and combined label all 13 as issues, many with version or caller conditions. Guidance labels 12 issues and one unresolved. Counts are not accuracy scores. The supported scope and remaining conditions matter more than whether the IP-filter case is an issue or uncertainty. Flow-status values likewise are not a count of errors corrected.

The richer current control also corrected the expiry story that failed in BP. Possible contributors include model variation and the current common prompt/context; the experiment does not isolate those against historical BP. New guidance is useful review material and fits the existing skill routing, but all-control success prevents claiming this run proves it caused the correction.

## Verification and limits

All 38 actual calls have reconciled raw usage receipts and exact cumulative-to-turn deltas. All structured replies satisfy the same schema. All four cover exactly the selected 13 IDs. The 436 citation-range checks across arms are against supplied/read, hash-pinned source; they overlap and are not 436 unique facts. Frozen source, runtime, configs and guidance hashes match. No live target execution or native product admission occurred.

Each assembled diagnostic package retains all 116 IDs: 13 amendments and 103 unselected first-pass outcomes, with original results and amendments separate. `comparison-audit.json`, `claim-comparison.json` and per-arm results preserve the full evidence. The selection is a known development regression set, not a blinded fresh-app precision benchmark.

## Decision

Keep the new on-demand token guide. Keep combined guidance plus **relevant** prepared dependency source as the leading candidate where that contract decides several claims. Do not preload every library or add another helper model by default. Reuse an existing source-bound contract record and retain caller-specific checks.

No further full JWT tournament is justified now. The next implementation work is a bounded, source-backed handoff using existing evidence records, with regression checks for the expiry explanation and independent gates; then the separate concurrency experiment. Before broader promotion, exercise the routing and handoff on another token implementation/application. Keep the source-only and guidance-only measurements as alternatives rather than declaring a universal winner from a cent-scale, single-run difference.
