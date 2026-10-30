# Stable-schema full Juice Shop results — 2026-10-29

Study artifacts: `C:/dmitry/scan-runs/stable-full-20261029-bk`. Model: Terra 6.1 medium. Study-only implementation; product defaults are unchanged. Read with the [frozen plan](review-stable-full-native-hybrid-plan-2026-10-29.md) and [failure-isolation record](review-failure-isolation-2026-10-29.md).

## Completed native result

| Metric | Saved dynamic native (BI2) | Stable native (BK) |
|---|---:|---:|
| Reviewed claims | 116 | 116 |
| Calls | 84 | 90 |
| Input tokens | 3,120,380 | 3,383,539 |
| Cached input tokens | 0 | 2,235,136 |
| Cached fraction | 0% | 66.06% |
| Output tokens | 58,116 | 60,521 |
| Standard API price equivalent | $3.410960 | $1.562765 |
| Standard Codex credits equivalent | 85.274 | 39.069 |
| Provider time | 16m 19s | 17m 43s |
| Arm elapsed | 18m 18s | 21m 02s |
| Issue / not issue / needs review | 42 / 47 / 27 | 43 / 43 / 30 |

Price fell **54.2%**, while input increased **8.4%** and elapsed increased **15.0%**. This is cheaper repeated work, not less work. The same BK usage without the cache discount would cost $3.686144. All costs use the frozen published Standard rate basis, not an invoice. Preparation and operator analysis are outside arm elapsed time.

64 of 65 continuation calls hit cache, with 78.95% of continuation input cached. One of 25 initial calls hit, with 1.14% of initial input cached. Cache-write counters were zero. Parallel arms could share provider cache routing; do not label these independent cold-cache trials. BI2 is historical, not a randomized cache-only control; the earlier paired BJ2 slice provides the narrower intervention evidence.

All 90 paid receipts reconciled against raw events, all 90 exact local schema checks accepted, and 331 exported source excerpts matched physical source bytes. All 25 initial packets matched the frozen baseline source/question metadata. Source validation establishes evidence integrity, not semantic correctness.

## Source-informed quality review

There are 12 changed verdicts against BI2, and **no newly introduced `not_issue` verdict**. This is not a claim of equal accuracy: unchanged conclusions can share errors, and unresolved findings can increase reviewer work.

| Claim suffix | Change | Audit assessment |
|---|---|---|
| `1d71a2d4a3344456` | not issue → issue | CAPTCHA endpoint returns the answer; verification neither consumes nor binds the stored challenge. A supported reusable-verification mechanism, though it is broader than SQL injection. |
| `262317b675829863` | needs review → issue | Generated basket-item update lacks ownership enforcement. Preserve this mechanism; it does not settle every generated-resource operation. |
| `ba583b9dd72566ed` | needs review → issue | Same basket-item ownership relationship. Quantity checking is independent and remains applicable. |
| `3804323035b5836c` | needs review → issue | Source proves `400` followed by `next()`, non-blocking challenge handlers and resource registration. The stronger claim of persisted creation after response completion still needs the exact Finale create contract; not counted as fully verified here. |
| `6821f10442521e88` | needs review → issue | Challenge-enabled request ID is returned as order ID, trusted by the Angular component and rendered via innerHTML. Supported conditional HTML injection. |
| `26fdb36787840417` | not issue → needs review | YAML fix metadata reaches a callable consumer; lower-trust writer/access relationship remains unresolved. Useful investigation lead, not proven execution. |
| `4ba7b6d946e5c9d9` | not issue → needs review | Similar YAML consumer in the RSN workflow; writer and subsequent workflow invocation remain open. |
| `57b7e3fa1f3c163b` | not issue → needs review | Linter configuration trust and executable-value consumer remain unestablished. Do not infer execution merely from YAML loading. |
| `a1d0787f2828a99b` | issue → needs review | Public key-directory indexing is distinguished from sensitive private material; actual contents remain relevant. |
| `b668efbfecb92de6` | issue → needs review | Log filename listing is distinguished from log-content retrieval. More precise scope, with retrieval still worth completing. |
| `3dac0ddb94de0f62` | issue → needs review | Subtitle-to-script sink retained; exact writable file and upload access relationship unresolved. |
| `c200c14fa5ec441e` | issue → needs review | Trusted email HTML sink retained; lower-trust writer relationship unresolved. |

Eight additional claims change severity while retaining their verdict. Basket access, duplicate-key mutation, search HTML, cookie attributes, directory listing and password-change mechanisms remain represented. These severity changes are not an accuracy score; duplicate basket-update claims also show inconsistent medium/high calibration within the same package.

Both raw-SQL positives remain issues. Seven NoSQL candidates retain concrete unresolved selector/interpreter questions; no same-record shortcut became a safe dismissal. Correct the earlier “19 clean ORM controls” description: the 19-claim observation bundle now has 16 negatives and three positives (basket-item update, basket checkout and CAPTCHA reuse). Across all 21 Sequelize-resource claims, there are 16 negatives and five positives. The negative explanations distinguish public catalog/inventory lookups and owner-constrained records from independent basket authorization. These are ownership/resource-access controls, not a dedicated parameterized-SQL injection benchmark.

The known JWT contract defect survives: `review-3911a056715584a6` again asserts an issued six-hour expiry, despite the earlier version audit showing the relevant legacy signer ignores that option. Cached authorization without an expiry check remains meaningful, but that precise issuance/expiry story needs correction. The hardcoded signing-key finding also repeats the six-hour premise in ancillary prose. Stable schemas reduce price; they do not supply missing dependency contracts or eliminate shared reasoning errors.

## Hybrid recovery result

Recovery completed with **102/116 source-validated claims in 23 complete original bundles**, not a full-app package. Fourteen claims remain execution gaps: seven unfinished workspace claims and seven claims in the native group interrupted by the recovery-wrapper bug. All 14 later independent native groups completed. Original failed artifacts remain preserved.

| Metric | Recovered hybrid, all attempts |
|---|---:|
| Actual provider calls | 82 |
| Input / cached input / output tokens | 2,923,983 / 1,876,480 / 56,043 |
| Cached input fraction | 64.18% |
| Standard API price equivalent | $1.421542 |
| Standard Codex credits equivalent | 35.539 |
| Same usage without cache discount | $3.204198 |
| Provider time | 15m 23s |
| Sum of active attempt elapsed times | 19m 13s |
| Wall time from first start, including recovery pauses | 32m 15s |
| Issue / not issue / needs review | 37 / 41 / 24 |
| Rejected local schema responses | 1 |

All 82 actual calls reconcile against raw receipts and the combined recovery ledger. One additional reservation demonstrably failed before provider dispatch; its zero provider usage is documented and its reservation remains charged. There is no unknown actual usage. Both attempts' paid work is included. All 24 initial packet groups matched baseline source/question metadata, including the interrupted group.

The native portion used 80 calls and cost $1.343411. The workspace portion used two calls and cost $0.078131; **both workspace calls had zero cached input**. Only one of its eight claims was accepted. Thus the useful cache result applies to native continuations; this run does not establish workspace cache savings. The workspace's second response used navigation IDs as source citations and was correctly rejected locally.

The recovered package was regenerated exactly from the workspace state. Its 289 exported decisive source excerpts matched physical bytes; the separate native-unit audit checked 287 excerpts. These counts overlap and must not be added as unique evidence. Frozen source, runtime and immutable study hashes matched; admitted native work remained unchanged. `comparison.json`, `claim-comparison.json` and the recovery completion/ledger files preserve the detailed accounting.

### Eight disagreements on the 102 common claims

| Claim suffix | Native | Hybrid | Practical interpretation |
|---|---|---|---|
| `1d71a2d4a3344456` | issue | not issue | Native identifies CAPTCHA reuse. Hybrid's answer comparison does not address reuse or disclosure of the answer. Retain the mechanism in the review package even though the candidate originated as resource access. |
| `3804323035b5836c` | issue | needs review | Native finds more registration context, but the precise post-response persistence contract remains a completion target. |
| `57b7e3fa1f3c163b` | needs review | not issue | Hybrid distinguishes function construction from invocation. Its scoped negative is useful, but does not establish trusted configuration or all validator behavior. |
| `9bdb9475c1030df9` | issue | needs review | Native supports the basket ownership gap; hybrid leaves the generated update contract open. Other claims in hybrid still retain the basket-update mechanism. |
| `c684d73665767d34` | not issue | needs review | Both see a configuration value. Native excludes a separately compromised configuration source; hybrid asks for the actual value/type. This is a scope/evidence threshold difference. |
| `0420b4d41a5ad0d7` | needs review | issue | Hybrid reads an API test supplying `$ne` and asserting all reviews modified. Stronger repository evidence for selector injection. |
| `64fb2337e4bd00bd` | needs review | issue | Hybrid reads the true-expression order query and challenge assertion alongside the route's multi-order condition. Supports the conditional exfiltration mechanism. |
| `7576e8ab5c778f14` | needs review | issue | Hybrid reads the injected sleep test and blocking helper. Supports executable predicate/blocking work under the enabled branch. |

The NoSQL test assertions were inspected as source, **not executed**. The Cypress examples also exclude Docker. Their existence is stronger contract evidence than the package name alone, not fresh runtime verification. All three improvements came from native-routed groups inside hybrid, not from the workspace group. Do not attribute stochastic evidence-discovery differences to workspace architecture.

Hybrid also has ten verdict differences against stored BG on its reviewed subset. This report does not certify every unchanged or changed conclusion as semantic gold; the full claim-level JSON preserves each result for targeted completion. Neither arm is uniformly superior on the reviewed mechanisms. Hybrid's $1.42 cannot be ranked as a cheaper complete package while 14 claims are missing.

## Decision

Keep stable native as the leading first-pass candidate. Keep compatible workspace investigations available; a workspace format rejection is a reason for a narrow format fix and recovery test, not abandoning the mode. Do not rank partial hybrid price against complete native price.

After recovery accounting closes, return to the [targeted-completion plan](../review-targeted-completion-plan-2026-10-29.md): version-bound JWT facts, consequential unresolved writer-to-effect relationships and unsupported stronger impacts. No further full-app rerun is justified before those smaller checks. A stable source-handle syntax constraint can prevent the observed workspace navigation-ID mistake while exact local membership validation remains mandatory.
