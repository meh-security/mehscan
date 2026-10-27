# Matched native-bucket comparison — safety wave

Status: **closed after a failed safety gate**. Eight selected claims were reviewed
in both arms, with all sixteen dispositions source-validated and all 62 provider
calls accounted for. Sixteen prepared main-wave claims and eight reserved claims
received no model review. There were no paid repairs, unknown usage or controller
execution failures. Ordinary completion admitted records only to fresh private
study stores; nothing was written to an application or production/shared store.

The tested workspace package reduces input substantially but loses a classified
conditional finding and takes longer in active execution. It does not pass the
package-quality/operational gate. This does not refute selective grouping or
persistent state: the safety wave's native buckets are all singleton, and an
important semantic-policy delivery difference was discovered after the run.

## Frozen conditions

The [plan](review-workspace-batch-plan.md) and [selection](review-workspace-batch-cases.json)
were bound at commit `ba6e559`. Run:
`C:/dmitry/scan-runs/workspace-batch-comparison-20261026-r`. Each application/wave
has independently frozen code/skill/scanner/provider inputs, native state and
source-parity receipts. `study-freeze.json` also binds the evaluator expectations
before dispatch. No previous finding, notebook, answer or proposition entered a
reviewer task. These cases are outside both workspace tuning slices but are not
globally unseen: earlier source/policy audits include some of them.

Native bundle generation used its default maximum of 20 reviews, preserving its
rule buckets. Treatment work items matched each generated bundle exactly. Both
arms had the same six-call, 24-query-unit, 512 KiB received-result and 900-second
bundle limits, with serial execution. Native continuation and workspace fresh
context/state behavior differ. Source and lookup availability match; prompt
format/semantic-policy delivery and response contracts are package differences.
The intended common API-policy parity was not achieved, as detailed below.

Native safety-wave buckets each contain one claim. Thus the safety data test
execution, source quality and context/state handling, not multi-claim batching.
The unrun main-wave buckets contain groups of two and three claims; no inference
about their benefit follows from this stopped wave.

## Observed cost and time

| Measurement | Native control | Workspace |
| --- | ---: | ---: |
| Reviewed claims / validated dispositions | 8 / 8 | 8 / 8 |
| Provider calls | 32 | 30 |
| Input tokens | 787,876 | 424,093 |
| Cached input tokens | 0 | 0 |
| Output tokens | 13,778 | 11,397 |
| Measured review-call time | 454.735 s | 407.905 s |
| Active execution | 500.741 s | 534.391 s |
| Time outside measured review calls | 46.006 s | 126.486 s |
| Classified findings / scoped negatives / unresolved | 5 / 3 / 0 | 4 / 3 / 1 |

Input is 46.2% lower, but that is not an acceptance gate. Two fewer calls and
46.830 seconds less measured review-call time do not compensate for quality loss
and 33.650 seconds more active execution (6.7%). This is one small counterbalanced
development comparison, not a latency distribution or whole-app estimate.

By application, native Juice used 15 calls / 239.268 active seconds; workspace
used 14 / 230.097. Native Directus used 17 / 261.473; workspace used 16 / 304.294.
No cache hits explain those differences. Both arms used all six slots for the
NoSQL claim and the outbound scope claim. NoSQL closed as a conditional finding;
the workspace outbound question remained unresolved at its call ceiling. Its
final "no lookup queries remain" reflects the final-turn lookup prohibition,
not exhaustion of all 24 query units: it consumed twelve units.

Actual study spend: **62 calls, 1,211,969 input, 25,175 output, zero cached input
and 862.640 seconds of measured review-call time**. Active execution totals
1,035.132 seconds. Recorded automated-preparation intervals total 135.780 seconds
for all four datasets, including 38.999 seconds preparing the unused main wave.
Those intervals run from directory creation to binding creation and exclude
pre-directory validation/final write and implementation/evaluator labor. They
are not complete end-to-end wall time. All costs remain in the ledger.

## Source quality gate

| Selected relationship | Native | Workspace | Source audit |
| --- | --- | --- | --- |
| Embedded JWT signing key | Finding | Finding | Source key/signing use retained; downstream acceptance qualified |
| Filename transformation after extension validation | Finding | Finding | Restricted extension bypass, not unrestricted filesystem traversal |
| Substring URL allowlist | Finding | Finding | External redirect mechanism retained |
| Executable NoSQL predicate | Finding | Finding | Enablement conditions retained; no unproved host-code execution |
| Default YAML parser | Scoped negative | Scoped negative | Actual import/version/default-schema inference, not whole-operation safety |
| Sanitized detached-DOM assignment | Scoped negative | Scoped negative | Same-value sanitizer/browser context; not full-feature safety |
| Account-bound password reset | Scoped negative | Scoped negative | Signature/issuer/expiry, scope, current-password hash and selected user checked |
| Sandbox request redirect scope | Finding | `needs_review` | Supported conditional mechanism not retained as a classified finding |

No wrong safe dismissal was identified. Workspace retains an actionable question
for the last case; it did not call it safe or erase it. Nevertheless, an unresolved
concern is not equivalent to the supported conditional finding that the package
was required to retain. NoSQL severity differs (native high/workspace medium), so
matching verdicts also do not mean identical risk classification.

The native outbound finding verifies that `instantiateSandboxSdk` passes the
requested scopes to the request generator and exposes it in the isolate. The
generator checks the initial URL, then uses the application's Axios factory.
Under established Node Axios semantics, automatic redirects remain enabled;
the installed agents enforce an IP denylist rather than the sandbox URL scopes.
The finding explicitly requires an allowed endpoint with a usable redirect and
a destination passing IP policy. It does not assert unrestricted private-IP SSRF.

The workspace inspected the generator, factory, IP guards and scope declaration,
then reached the SDK registry. It stopped before following the registry consumer
(`getSdk` -> `instantiateSandboxSdk`) that establishes the caller binding. Its
final blocker also demanded an installed Axios contract despite an earlier saved
attempt explicitly stating default redirect behavior. Both the available next
edge and the epistemic backtracking are visible in the retained question/receipt
history. Do not treat a reread of the registry as proof of the consumer binding,
or declare that binding globally unavailable.

## Contract-delivery difference and offline correction

Native prompt sources include the common runtime policy allowing established API
semantics when actual import, relevant version/options and runtime fit, while
preserving genuinely unknown contracts and inspecting custom wrappers/hooks.
Workspace v2 replaced the native procedural envelope but also omitted that common
semantic policy. Category guidance remained available, but the canonical common
paragraph was not delivered in the compact prompt. This violates the intended
semantic-policy parity. It is a plausible contributor, not proof of the sole
cause: the two arms also chose different navigation paths.

After closing the study, the shared API paragraph was delimited in
`references/runtime-review.md` and reused directly by the compact prompt from its
bound trusted skill. The provider packet records that same section. Native common
semantics remain unchanged; the compact path still omits procedural bookkeeping.
No Axios-specific instruction or forced verdict was added. Missing/duplicated
policy fails closed. Tests verify canonical delivery, wrapper/unknown-contract
safeguards and exclusion of the old procedural envelope.

This correction was **not** applied to the frozen run, and no recovery inference
was made. It needs a fresh bounded check including the affected mechanism and
unsafe/unknown controls. Restoring the paragraph does not itself prove that the
reviewer will follow the missing registry-consumer edge or recover the finding.

## Measured controller overhead

`workspace-overhead-profile.json` counts native commands during treatment execution,
excluding preparation. Only non-overlapping native-operation trace entries are
summed, not their enclosing operations:

| Workspace dataset | `state/work` calls | Measured validation time |
| --- | ---: | ---: |
| Juice Shop / 14 provider turns | 121 | 22.097 s |
| Directus / 16 provider turns | 134 | 69.544 s |
| Total | 255 | 91.641 s |

These calls explain much of the workspace's 126.486 seconds outside measured
review calls. The remainder also includes other native work, local preparation,
provider startup and persistence. This trace does not prove a particular cache
or SQLite redesign will help. Profile and remove duplicate validation under the
same owned boundary while retaining generation/owner, runtime, packet and source
freshness checks before/after paid work. Do not trade source correctness for speed.

## Decision and next work

The failed gate is recorded in `quality-gate.json` and `study-closed.json`, with
`expand_main: false`. All sixteen prepared main claims and eight reserved claims
remain unreviewed. Unused ceilings do not authorize another run, and the old study
must not resume under the corrected code. Its original packages/answers/usage
remain unchanged.

1. Verify the shared semantic-policy correction and exact missing caller edge in
   a fresh small regression package, with unsafe and genuinely unknown controls.
   Keep the same budgets; do not recover by increasing turns or preloading a verdict.
2. Reduce measured redundant boundary-validation overhead without weakening
   source/ownership protections. Then refreeze the still-unreviewed mixed batches
   for the actual batch-size comparison if the quality check passes.

Do not build more generic memory, helper discovery or an interface as a substitute
for these checks. Keep the native default workflow as the operational reference.
The earlier selective SQL/deluxe grouping evidence remains valid within scope;
this failed singleton safety wave neither establishes nor disproves its broader
multi-claim benefit. No full-app review follows this result.

Validation after the offline correction: 99 workspace tests pass in 70.556 seconds;
46 adapter tests run successfully with one platform skip. New checks exercise
actual provider-packet policy delivery and canonical prompt parity. These are
delivery/correctness tests, not a live quality-recovery result. No Rust code changed.
