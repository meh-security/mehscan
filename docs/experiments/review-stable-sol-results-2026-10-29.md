# Stable-schema Sol comparison — 2026-10-29

**Later recovery update:** [Sol native recovery](review-sol-native-recovery-2026-10-29.md)
now validates all 116 claims, with $3.8097692 known price and one historical unknown
receipt. The original partial-run measurements below remain preserved. Recovered
claim comparisons live in BO2, not in the historical BL2 files.

Sol hybrid completed all 116 claims. Sol native stopped with 86 validated claims after an account-security block. This supports a complete Terra-native versus Sol-hybrid comparison, plus partial comparisons; it is not a completed four-arm tournament.

Artifacts: `C:/dmitry/scan-runs/stable-full-sol-20261029-bl2`. See the [frozen Sol plan](review-stable-full-sol-plan-2026-10-29.md), [Terra results](review-stable-full-native-hybrid-results-2026-10-29.md) and [latest decision plan](../review-targeted-completion-plan-2026-10-29.md). Both models used medium effort and matching initial evidence/question metadata. Prices are published Standard API equivalents, not invoices.

## Whole-package accounting

| Arm | Validated claims | Actual / receipted calls | Known API equivalent | Cached input | Provider time | Arm elapsed |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Terra native BK | 116 | 90 / 90 | $1.562765 | 66.06% | 17m 43s | 21m 02s |
| Terra hybrid BK, recovered | 102 | 82 / 82 | $1.421542 | 64.18% | 15m 23s | 19m 13s active attempts; 32m 15s including pauses |
| Sol native BL2, incomplete | 86 | 72 / 71 | $2.797630 known only; total unknown | 66.50% of known input | 28m 29s known only | 31m 27s |
| Sol hybrid BL2 | 116 | 98 / 98 | $4.203882 | 62.83% | 40m 29s | 45m 39s |

Sol hybrid costs 2.69× Terra native and takes 2.17× its arm elapsed time. Neither metric alone establishes review quality. All attempts remain included; partial arms cannot win a full-package price ranking. Preparation and operator analysis are outside arm elapsed.

Sol hybrid used 4,105,361 input tokens, including 2,579,200 cached, and 89,364 output tokens. Same-usage repricing without cache discounts is $9.104362; observed cache-read discounts reduce that amount by 53.8%. Cache-write counters were zero. Standard Codex credit equivalent is 105.09705. Concurrent arms may share provider cache routing; these are not independent cold runs.

Its native portion used 92 calls and cost $3.635346, with 67.03% cached input. Its workspace portion completed all eight selected claims in six calls, cost $0.568536, and recorded **zero cached input**. Thus stable workspace schema alone has not demonstrated workspace cache savings. Workspace outcomes: one SSRF issue, three scoped redirect negatives, four cookie-delivery/CSRF uncertainties. Distinct success and fallback profile updates remain separate claims. No local schema rejection occurred in Sol hybrid.

## Native interruption: preserve, do not reroute

Call 72, conversation `32c79d66718c4efe568cd88c6a90a8625919c0b98742af505a6f61bfed81ecf7`, round 3, failed inside the launcher before normal usage/event artifacts were saved. The private CLI rollout reports `cyber_policy`: this session does not meet Daybreak account-security requirements and requests sign-in with an approved hardware security key. It was not a PC sleep or timeout failure.

The runtime's cumulative token counters did not advance, and its failure record reports 18,540 ms. That is not a normal provider usage receipt or proof of zero billing. Keep the 71-call known total and one unknown attempted-call receipt separately. No retry or alternative-route execution was attempted. Resuming the blocked work requires addressing the reported account-security setup, not bypassing the gate. The other arm had independently completed under its original authorized execution.

There is also a telemetry limitation: `codex_launcher.review` raises on a nonzero return code or missing answer before returning stdout/stderr to `codex_reviewer`, so the usual round logs are absent. A later isolated telemetry fix should preserve failure diagnostics before raising without changing policy handling or automatically retrying.

## Quality: useful complements, shared weaknesses

Terra native and Sol hybrid differ on 25 of 116 verdicts. The exact results are in `four-arm-claim-comparison.json`; `source-informed-disagreement-audit.json` records a deciding assessment/question for every changed ID. This is a source-informed review by an evaluator already familiar with Juice Shop, not a blinded precision benchmark.

| Area | What Sol contributes | Remaining problem / completion target |
| --- | --- | --- |
| Session lifetime | Retains unbounded cached authorization without Terra's unsupported claim that issued tokens expire after six hours | Verify the exact legacy dependency contract separately; an unchanged issue label hides this useful correction |
| Three NoSQL mechanisms | Reads repository test-source evidence for multi-review mutation, order exfiltration and executable predicate/blocking work | Tests were inspected, not run; preserve challenge/environment conditions |
| Legacy authorization | Keeps seven route negatives open when verifier/cache semantics are unresolved, while naming independent owner/password/IP gates | Avoid rediscovering missing dependency source separately in every route; provide equally available version-bound evidence |
| Public logs | Connects indexing to an unauthenticated file handler, instead of stopping at filename sensitivity | Preserve listing and content retrieval as distinct effects |
| Registration roles | Connects caller-supplied role through model and login to accounting authorization | Exact generated CRUD binding is still a contract dependency; this does not settle every generated operation |
| CAPTCHA | Both Sol arms dismiss the resource-ownership question | The package loses the adjacent answer-disclosure/reuse mechanism retained by Terra native |
| YAML fixes / RSN | Separates local filename selection from request body input | Dismissals do not settle content integrity; inspected source calls parsed `fixes.find` in both paths, and a conditional writer exists. Preserve the unresolved writer-to-consumer relationship rather than certifying it safe |
| YAML linter | Distinguishes function construction from invocation | Configuration trust and validator consumption remain unestablished; no complete exploit asserted |
| Like-review selectors | Narrows to public liking and single-record operations, with concurrency caveats | Reusing identical selector text is not proof that every check/reread/update affects the same record; resolve the actual interpreter/selection contract |
| Basket update | Preserves an ownership gap but leaves an unread local hook as a blocker | Audit of `lib/noUpdate.ts` and `models/relations.ts` shows protection of changed BasketId/ProductId, not quantity authorization. This is a concrete completion lookup |
| Tracking HTML | Retains request-to-trusted-HTML flow, but waits for effective challenge configuration | A supported conditional finding should survive without requiring deployment proof; retain configuration uncertainty separately |
| Config output / snippet path | Supplies more explicit type/producer questions and scoped filename reasoning | Distinguish content integrity, accepted key grammar and source trust from path selection |

The four like-review negatives are not labeled proven wrong here: the missing contract matters. Likewise YAML callable consumers plus a possible writer are not an established end-to-end exploit. The problem is that the package must retain consequential unresolved relationships, not silently discard them because the input is a local file or the operation is single-record.

Several Sol-hybrid improvements occur in its native-routed groups. They do not demonstrate a workspace architecture effect. The completed shared workspace group does demonstrate usable multi-claim review with separate caller/effect conclusions; its cost and lack of caching remain visible.

## Verification and limits

All 98 Sol-hybrid raw receipts reconcile with cumulative-to-turn deltas. All 98 local schema checks accepted; 426 exported source excerpts match physical bytes; its 25-bundle review package regenerates exactly. All 24 initial packets matched the frozen source/question metadata.

Sol native has 71 reconciled receipts and accepted local schema checks, plus one unknown attempt; 86 claims carry native validation records. No complete native findings export exists, so this audit does not claim an independent physical-excerpt pass over that partial arm. Eighteen of 25 initial groups were reached. The 30 remaining claims are explicit gaps.

Frozen runtime, source and immutable study hashes match. Product defaults and the completed Terra artifacts remain unchanged. `four-arm-audit.json` contains the measured pair coverage: Terra native/Sol hybrid 116, Terra hybrid/Sol hybrid 102, and Sol native/Sol hybrid 86.

## Decision and next milestone

Keep **Terra stable native as the leading first pass**. Keep **Sol as a candidate targeted flow/evidence reviewer**, not a justified full-app default: it costs more and supplies both useful corrections and consequential omissions. Preserve workspace for compatible shared investigations; it is now demonstrated to complete this eight-claim group on Sol, but its cache strategy remains unproven.

Close M1 with an explicit incomplete Sol-native arm rather than calling it a four-arm winner. Do not purchase another full first pass merely to erase the interruption. Continue M2/M3 offline preparation. A live retry of the blocked Sol work must wait for the account-security requirement to be addressed; do not route around it. Targeted completion should compare correction of the same source-backed flow obligations, including same-label improvements and unselected-negative samples. The old Sol-native economic break-even calculation remains unavailable because its complete cost is unknown.
