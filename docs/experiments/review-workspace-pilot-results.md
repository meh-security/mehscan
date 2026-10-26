# Review workspace pilot — 2026-10-26

**Decision: stop this live variant. Savings are not established.** The ordinary
arm completed the selected 12 claims. The workspace arm validated one claim,
then exhausted the login claim's 600-second allowance with an unobserved provider
turn. The single permitted protocol correction was used. Do not launch grouping,
held-out evaluation or a full-app rerun from this result.

## Frozen comparison and artifacts

The [design](review-workspace-pilot.json) remains the original evaluator-only
document, including its pre-run status. The actual manifests and results live in:

- `C:/dmitry/scan-runs/workspace-pilot-20261026-d`: ordinary control, initial
  workspace rejection, immutable package and original binding.
- `C:/dmitry/scan-runs/workspace-pilot-20261026-e`: corrected workspace attempt,
  immutable package, correction amendment and result.
- `C:/dmitry/scan-runs/workspace-pilot-20261026-results.json`: consolidated
  accounting and per-claim ordinary assessments.

Both arms used `gpt-6.1-sol`, medium effort, CLI `0.164.0-alpha.11.1`, the same
source fingerprint, matched initial source for all 12 claims, and concurrency
one within each arm. The two arms ran concurrently. Limits were 48 calls,
144 query units, 1.5M input tokens, 60K output tokens and 1,800 seconds per arm,
with native per-claim limits retained. The historical client was different;
historical counters are reference measurements only.

Preparation attempts `a`, `b` and `c` stopped before inference. They exposed
terminal EOF and AST excerpt boundary differences. The fixes preserve exact
returned text, including inline fragments; they do not expand it to invented
whole lines. Attempt `d` passed all 12 source-parity receipts. Its shared
preparation took 12,625 ms; corrected preparation took 12,697 ms. Development
and correction time must not disappear from whole-package accounting.

## Measured result

| Measurement | Fresh ordinary control | Workspace, including rejected turn |
| --- | ---: | ---: |
| Selected claims with completed native validation | 12/12 | 1/12 |
| Attempted model calls | 42 | 4 |
| Calls with reported usage | 42 | 3 |
| Input tokens | 1,073,556 | At least 32,466; total unknown |
| Cached input tokens | 0 | Total unknown |
| Output tokens | 23,198 | At least 1,160; total unknown |
| Cumulative reported model-call time | 1,298,201 ms | At least 273,024 ms |
| Execution wall time | 1,333,638 ms | Corrected attempt 622,322 ms; includes timeout |

The workspace lower bounds include the original rejected call. They are not
comparable savings: eleven claims were not completed and one attempted call has
no counters. Corrected execution time excludes the earlier rejection and the
preparation/correction interval. From the original trial start to the corrected
result write, elapsed time was 1,006,424 ms (original deadline-derived start to
result-file timestamp). This includes the rejection and correction interval;
charge the original 12,625 ms preparation separately. Failed development
preparations remain separate artifacts, not erased costs. No percentage
efficiency conclusion is valid.

Ordinary research used 98 query units, 63 native executions and 25 reported
research-cache hits. Received result JSON totaled 459,480 UTF-8 bytes under the
frozen accounting policy. Native research caching and model token caching are
different measurements; the latter was zero. Ordinary results were admitted to
the isolated experimental native store. Workspace finalization was source
validated only, with native admission false.

## Failure and the one correction

1. The first search answer identified SQL injection but put completed
   verification narratives in `checks`. The workspace correctly rejected the
   settled verdict because that field represents outstanding deciding work.
   The paid call remains in accounting: 10,510 input and 576 output tokens.
2. The correction enforced verdict-specific fields in the output schema:
   settled verdicts have no outstanding checks/blockers; `needs_review` retains
   a deciding check; diagnosis shape follows the verdict. No verdict or source
   interpretation was edited. The corrected search answer passed native source
   validation: 10,912 input and 406 output tokens.
3. Login requested `routes/login.ts:1..200` to inspect the pre-login/result-use
   relationship. That completed turn used 11,044 input and 178 output tokens,
   taking 232,129 ms. The next turn timed out within the remaining claim
   allowance and returned neither a final answer nor usage counters.

Only the workspace protocol module and pilot runner differ between the frozen
original and correction packages. Ordinary prompt/branch code and the other
package files are identical; initial evidence was rechecked for all 12 claims.
The correction preserves the paid call, original aggregate budget, first-claim
call consumption and original deadline. This is an amended attempt, not an
unchanged-package randomized comparison.

Private provider event metadata showed the long login turn had already started
its task before the delay. The timed-out turn has no completed usage event.
The cause of the delay is **unresolved**; schema compilation, backend latency
and reasoning are hypotheses, not established diagnoses. Do not replace missing
counters with estimates or zero. No further workspace calls were dispatched.

## Quality audit of the ordinary package

The 12 decisions comprise five `issue`, five `not_issue` and two `needs_review`.
Source inspection supports the two SQL interpolation findings and the two
basket ownership findings. The generated-resource review narrowed its finding
to unauthenticated Product updates instead of assigning one verdict to every
resource. This resolves a particular operation; it does not close the whole
generated API loop.

All three deluxe reviews retain the unsupported/omitted `paymentMode` fallthrough
as a separate reviewer-origin lead. The owner checks themselves can be valid:
`appendUserId` binds the subject, while `upgradeToDeluxe` checks only the named
wallet/card branches before upgrading the role. Therefore, a local ownership
`not_issue` is not automatically a lost payment-bypass mechanism. These leads
preserve the mechanism for follow-up; they are not admitted findings and must
not be counted as equivalent final closure.

Two reviews defer on the same upstream identity producer: the wallet card lookup
and deluxe card lookup ask whether `updateAuthenticatedUsers` verifies the
subject used by `appendUserId`. Another deluxe review already read that helper
and closed the ownership question. Eight source lookup requests across seven
claims target `lib/insecurity.ts`, with overlapping ranges. This is concrete
remaining duplication and inconsistent knowledge availability, even with native
query caching. It motivates scoped shared facts; this workspace attempt did
not reach a live fact-save/reuse sequence and cannot establish their benefit.

The path/YAML controls were dismissed on their local allowlist/local-data
relationships. This is a source audit of a small development slice, not an
independent recall/precision benchmark or whole-app quality claim.

## Next implementation gate

The [revised next-work plan](review-workspace-next-plan.md) now refines this
ordering into separate execution, reuse and bounded grouping experiments. The
stop decision and accounting for this completed attempt remain unchanged.

Keep the persistent evidence/proposition state and independent native decisions.
Pause strategy expansion and CLI polish. First complete these offline tasks:

1. Replay the actual completed and rejected provider envelopes through the
   controller. Preserve outstanding questions explicitly and test verdict-field
   validation without adding another layer of repeated model instructions.
2. Trace the login lookup against the local SQL deciding question. Specify the
   exact fact that could change the verdict; distinguish proving SQL grammar
   injection from establishing an additional authentication impact. Do not make
   exhaustive caller discovery the default closure requirement.
3. Turn the audited identity relationship into a source-backed, scoped fixture:
   subject producer, route ordering, overwrite behavior, effect and exclusions.
   Exercise reuse across wallet/deluxe, an incompatible caller, invalidation and
   interruption. Evaluate whether the retrieved packet actually contains the
   deciding fact, rather than only checking persistence.
4. Reconcile model time, process time and missing-usage recovery using existing
   event metadata. Prove deadline termination and retained unknown usage in
   deterministic tests. Do not infer a provider root cause from one timeout.

**Stop/defer/dig deeper:** stop paid retries for this attempt; defer batching and
AI grouping; dig deeper into these specific offline failures and repeated facts.
Any future live diagnostic needs a new frozen, narrow question and budget. A
successful diagnostic is not a pilot pass: the complete mixed slice must still
preserve mechanisms and actionable uncertainty, report all usage, and meet the
original efficiency gates before expansion.

## Implementation verification

After the live attempt, all 35 workspace/state/action/bridge/pilot tests and all
seven workspace adapter protocol tests passed without inference. The rebuilt
release CLI and nine JavaScript/TypeScript outline tests also passed during
preparation. These checks establish controller behavior and source handling;
they do not turn this failed live trial into an efficiency result.
