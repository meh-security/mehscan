# Two-application live validation — 2026-10-30

**Both live runs finished; clean unattended acceptance did not pass.** The frozen
workflow reviewed all 205 FlaskBB candidates and finalized 135/155 crAPI
candidates. One rejected native research bundle leaves 20 crAPI claims explicitly
unreviewed. Selective workspace review improved findings and closed useful local
questions, but a 17-claim form-rendering investigation exhausted its allowance
without a final judgment. Its original native uncertainty is retained.

All **191 review-provider calls** have observed usage. Total published Standard
API equivalent is **$3.843253**, including rejected work, follow-ups and the
bounded form-workspace continuation. Coordination/source-audit tokens and costs
are additional and unmetered. Cheap review-provider price is established for
these workloads; it is not evidence that the whole workflow is automated.

## Frozen scope and measurements

See the [predeclared plan](review-two-app-validation-plan-2026-10-30.md).
[FlaskBB](https://github.com/flaskbb/flaskbb) is pinned at
`737d76f14e8f8fa4a493f1424ab184c87aecc516`;
[crAPI](https://github.com/OWASP/crAPI) at
`b5fc307f3e5f875809b095b771108ef342a33724`.
Same committed runtime, Terra 6.1 medium, stable schema, line-addressed source,
native maximum bundle size 20, and unchanged guidance. Ordinary native source
preparation only; no saved final answers or expected labels. No target app
execution, builds or dependency installation. Both applications ran in parallel
with three native workers each, six simultaneous provider calls maximum.

| Measurement | FlaskBB | crAPI | Combined |
| --- | ---: | ---: | ---: |
| Selected inventory claims | 205 | 155 | 360 |
| Native bundles | 18 | 26 | 44 |
| Source-validated claims | 205 | 135 | 340 |
| Unreviewed execution failures | 0 | 20 | 20 |
| Native calls | 69 | 96 | 165 |
| Workspace calls, including rejected/continued work | 18 | 8 | 26 |
| Native provider price | $1.390622 | $1.604575 | $2.995197 |
| Workspace provider price | $0.646969 | $0.201087 | $0.848056 |
| Whole measured provider package | **$2.037591** | **$1.805662** | **$3.843253** |
| Native cache fraction | 65.59% | 66.16% | 65.90% |
| Whole-package cache fraction | 54.73% | 62.96% | 58.90% |
| Native app wall | 321.380 s | 401.999 s | 402.215 s parallel wall |

Combined input is 7,154,903 tokens, of which 4,214,400 are cached; output is
138,406 tokens. All cache-write counters are zero. Workspace cache fraction is
2.87%; its useful flow corrections do not depend on outperforming native caching.
These are API equivalents using the stored October 30 rate basis, not invoices.

The first parallel follow-up stage took 62.273 seconds; the later bounded
form continuation took 59.782 seconds. These are not end-to-end turnaround:
there was a 39m06s manual audit/staging interval after native completion and a
5m03s diagnosis interval before continuation. Native start to last follow-up
completion was 52m54s; the recorded final source-audit checkpoint was 64m43s
after native start. Most of that elapsed time was orchestration/audit, not model
execution. Do not present the roughly seven-minute native wall as the complete
review time or attribute these intervals to a PC sleep event.

All 1,568 source-file hashes remain unchanged and both checkouts are clean.
Native scan coverage reports no parse failures: FlaskBB scanned 135 files and
ignored 368; crAPI scanned 256 and ignored 282. Inventory coverage is not complete
application security coverage. Older crAPI native benchmark work exists; this
is a fresh current-workflow run, not a claim of a never-inspected codebase.

## Quality: findings and flow corrections

After normally completed follow-ups, model outcomes are:

| App | Negative | Issue sites | Uncertain | Failed/unreviewed |
| --- | ---: | ---: | ---: | ---: |
| FlaskBB | 116 | 3 | 86 | 0 |
| crAPI | 64 | 54 | 17 | 20 |

Issue sites are not distinct vulnerabilities or demonstrated deployed exploits.
Many crAPI sites share token, shell, OTP or transport mechanisms, and several are
conditional configuration/local-construction findings. Every canonical source
excerpt in the composed package matches source: **791 excerpts**. That is source
validation, not an independent semantic accuracy score.

**FlaskBB produced a substantive authorization candidate in a production app.**
For reply routes containing both `post_id` and `topic_id`, request locals derive
the permission topic/forum from the referenced post. The handler independently
loads the destination topic and persists the reply there. Source and workspace
review confirm the request-time `ForRequest` evaluation, form save and model
write. An authenticated user allowed to reply to the source post's topic can
conditionally write into a different non-hidden destination despite that
destination's access or lock policy. Two claim sites represent this one
mechanism. Valid form input, applicable permissions and normal hooks remain
conditions; no deployed exploit was executed.

The third FlaskBB site is the application 413 handler redirecting to an
unvalidated referrer. Most ordinary redirects correctly close on fixed
`url_for` destinations. The checked forum-getter control authorizes the same
route-selected forum, showing why superficially similar resource getters do
not inherit the reply-route finding.

**crAPI follow-ups improved causal correctness even when verdicts stayed issue:**

- Password reset: native reasoning relied on missing reauthentication. The
  follow-up instead traces the `ApiKey` branch extracting an unverified JWT
  subject, establishing authentication and selecting the password-write target.
  This is a concrete authentication failure, not proof that a valid credential
  always requires an additional password prompt. Diagnosis changes to the actual
  authentication mechanism.
- JWK logging: the follow-up identifies the local signing-private-key JWKS file
  selected by the entrypoint, the unrestricted file-scheme JKU read, and
  `toString(false)` reaching INFO logs. This supplies a real producer/effect
  relationship rather than merely observing that JWKs can represent private
  fields. Deployed key configuration and log-reader access remain conditions.
- Body reads: two reviewed handlers retain a conditional unbounded local read,
  but the supplied nginx templates cap proxied bodies at **50 MiB**. An unbounded
  external path is not demonstrated. Preserve that qualification.
- KID verification: the known short HS256 key closes negative because the
  configured verifier rejects its length and the exception does not enter the
  unsigned-token fallback. A known key string is not necessarily accepted.

The native benchmark run also retained unsigned-token acceptance, RSA/HMAC
confusion, JKU-selected key trust/requests, coupon SQL construction, decoded
report-path traversal and conditional shell-execution mechanisms. SQL and
NoSQL controls distinguish fixed/bound values from executable grammar. A
native transport control also recognizes that an Apache 4-to-5 client cast
fails before the selected trust-all client reaches a request; this is a scoped
negative, not a claim that the application has no other TLS weakness.

All 57 promotion summaries and all 175 native negative summaries were screened;
24 reproducible negative controls received deeper source checks. No contradicted
scoped negative was identified in that selected deeper sample. This is not a
complete independent gold audit, so there is no defensible whole-app
precision/recall percentage. Source comments and benchmark labels are not gold.

## Remaining gaps are material

The failed crAPI bundle includes the vehicle-location BOLA candidate. Its
controller accepts a vehicle ID and the service loads/returns its location
without caller ownership. It therefore illustrates consequential missing
review coverage, not harmless bookkeeping. The native coupon-selector
questions also remain uncertain despite matching a known benchmark area;
the source accepts BSON operators, but the model did not close its
query-authority/business-effect question. Neither is a negative verdict.

FlaskBB's 90 native uncertainties fell to 86 after four local rendering/quote
closures. Most remaining uncertainty is still HTML related. The 17 auth-form
cases share an actual macro/widget chain, but the workspace kept seeking the
external Flask-Themes2 rendering contract and returned no final decision. Source
and question-attempt histories are retained; inspected macros must not be
misrepresented as still unread in a future investigation.

## Failures and interventions

The native crAPI bundle returned an oversized source range, received its one
allowed protocol correction, then returned a directory as a file-only
definition filter. Batch validation reports the first error; the second error
had not been the first correction's stated reason. No query in either rejected
batch executed. The bundle stopped after two charged calls. The other 135
claims and FlaskBB continued normally. Its original deadline had elapsed by
the time manual escalation was prepared; no fresh retry or budget reset was
performed. All 20 failed IDs remain explicit.

The auth-form workspace initially returned a schema-valid lookup with a query
attributed to a claim outside that lookup's beneficiary list. It was rejected
before execution. The controller recorded exact generic protocol feedback as
non-evidence state and continued the same workspace under the original deadline
and remaining five calls. Six calls and 20 query units were used in total;
there was no budget reset or prompt/runtime change. On its final checkpoint,
the model requested more lookup work instead of exporting decisions. The runner
then stopped at the original allowance. This is an assisted continuation and
an unsuccessful finalization, not an unattended success or a safe verdict.

Seven of eight selected workspaces export normally: 11 claims, including four
FlaskBB negatives, two retained reply issues, the KID negative and four crAPI
issue/flow qualifications. Candidate fallback was not used. The original native
and follow-up failure records remain intact. No finding was admitted into native
state and no product code or guidance changed during this experiment.

## Direction after these two runs

Keep Terra medium, native for SQL and other complete local constructions, and
workspace for concrete shared implementation or authority-to-effect work. Do not
discard workspace because of low cache percentage: its price is small and its
causal corrections matter. Do not route every rule through one universal mode.

The next work is **completion correctness and HTML review usefulness**, not
cache micro-optimization or another model tournament:

1. Give bounded protocol repair complete actionable query-validation feedback,
   and retain invalid lookup attribution as controller feedback without losing
   the original budget/history. Exercise the exact saved rejected batches.
2. Make the last allowed workspace checkpoint conclude with supported decisions
   or precise uncertainty, rather than offering investigation that requires
   another unavailable model turn. Do not force negative verdicts or silently
   add a synthesis call. Replay the saved last-turn task/schema first.
3. Review the generic framework-rendering obligation at its actual API boundary.
   Separate standard renderer/macro guarantees from real caller or override
   gaps. Validate any correction on the existing FlaskBB, PyGoat and OrchardCore
   cases before buying more full-app runs or adding app-specific prompt rules.

The fixed live experiment stops here with explicit gaps. These results support
both modes and identify the next concrete defects; they do **not** establish
clean unattended rollout or complete bug-finding coverage.

Artifacts: `C:/dmitry/scan-runs/two-app-validation-20261030-cj`.
Start with `final-verification.json`, `quality-assessment.json`, the two
`combined-analysis.json` / `combined-claim-results.json` packages and
`followups/source-bound-knowledge.json`. Frozen sources/runtime/packets, all
receipts, original failures, continuation feedback and audit controls remain
available. Preparation, source/receipt checks and script compilation do not
constitute another paid run.
