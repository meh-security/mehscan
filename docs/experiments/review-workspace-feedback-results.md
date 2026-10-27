# Bounded lookup feedback: aligned comparison X

Status: **partial confirmation, not package acceptance**. All 34 actual model calls
have observed usage. Sol workspace completes four verdicts matching the source
expectations, but misses a predeclared effective sanitizer-configuration check.
Terra 6.1 medium completes three dispositions and stops on a conflicting-filter
request after receiving two directory-filter feedback receipts. No wrong safe
dismissal was identified in the completed cases; neither matching labels nor native
source validation establishes the missing semantic basis.

The [frozen plan](review-workspace-feedback-plan.md) and original expectations are
unchanged. No paid repair, retry, resumed workspace or unused-ceiling dispatch
follows this study. The sixteen mixed main and eight reserved claims remain
unreviewed; there is no full-app run.

## Implementation and comparison conditions

Implementation `1cf16b1` turns known file/directory filter mistakes into typed
workspace feedback. The controller retains the exact query and deciding question,
returns only alternatives supported by that tool, executes no native query for the
rejected request, and attaches no source evidence. Valid independent requests in
the same fully prevalidated batch still execute. Correcting a request requires an
explicit later model action within the existing call/query/byte ceilings. Feedback
cannot settle a question without source proof or become a cached native result.

Query reservations and received JSON bytes remain charged. Source/runtime/owner
freshness still guards publication; escaping paths, unsupported arguments/limits
and unknown paid usage remain fatal. Ordinary worker behavior remains fatal for
these rejected requests. Tests cover mixed valid/feedback batches, limits,
source changes before publication, unknown usage and rejection before partial
actions. Initial verification: 127 workspace tests, 46 adapter tests with one
existing skip, and seven common-validator checks. Historical V/VT query shapes
were checked offline with zero model/native calls and no workspace/answer replay.

Study X was frozen at `8d1877c` under
`C:/dmitry/scan-runs/workspace-feedback-20261027-x`. Its runtime packages retain the
initial feedback implementation. Sol native-default review versus Sol workspace is
the primary comparison. The requested `gpt-6.1-terra` workspace arm is additional
model evidence, not an isolated workflow effect. Both models use medium effort and
CLI `0.164.0-alpha.11.1`. Independent stores, exact native membership and canonical
initial source parity were frozen before inference. Native bundle maximum stays
20; actual bundle sizes are one, one and two claims.

Each bundle has six calls, 24 query units, 512 KiB received JSON and 900 seconds;
dataset/arm ceiling is 1,800 seconds. Total effective call ceiling is 54. Execution
is serial. The predeclared policy closes a failed run without repair, while allowing
already frozen independent runs to continue if global bindings remain unchanged.
Unknown usage blocks subsequent datasets in that model/workflow arm. No global
binding changed during execution. Native admission affects only private study
stores; workspace uses native finalization without admission.

## Actual cost and completed work

| Arm | Final dispositions | Calls | Input | Cached input | Output | Model-call time | Active execution |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Sol native | 4/4 | 12 | 307,516 | 0 | 5,333 | 182.280 s | 200.347 s |
| Sol workspace | 4/4; source-basis gap | 10 | 131,464 | 0 | 4,219 | 149.222 s | 173.702 s |
| Terra workspace | 3/4; Directus incomplete | 12 | 170,317 | 0 | 3,438 | 100.622 s | 147.453 s |
| Total | 11 final dispositions | 34 | 609,297 | 0 | 12,990 | 432.124 s | 521.502 s |

All eleven final dispositions pass native source validation. The source audit below
is the additional quality check. No usage is unknown. Input/output amounts are
reported costs, not acceptance thresholds. Outside-model execution totals 89.378
seconds. Preparation totals 81.406 seconds across six prepared datasets, including
unused Terra native preparations. These are measured intervals, not end-to-end
wall time including implementation/evaluator labor.

| Dataset | Sol native calls / active | Sol workspace calls / active | Terra workspace calls / active |
| --- | --- | --- | --- |
| Directus protected HTML | 3 / 53.976 s | 2 / 43.289 s | 4 / 51.028 s, incomplete |
| Juice owned-address deletion | 5 / 81.852 s | 4 / 63.371 s | 4 / 52.440 s |
| Two HTML contract controls | 4 / 64.519 s | 4 / 67.042 s | 4 / 43.985 s |

The whole primary comparison is twelve versus ten calls, but the source-basis gap
prevents treating it as equivalent completed review work. On the three claims whose
source basis passes in both primary arms, native uses nine calls/146.371 active
seconds and workspace eight calls/130.413 seconds. That modest one-call/15.958-second
development result does not establish general latency savings. Terra's different
model and incomplete fourth case prevent an overall workflow/model ranking.

Workspace native state/work checks, restricted to each run's execution interval,
remain measurable: Sol Directus 16/8.124 s, Juice 30/5.387 s, controls 30/1.597 s;
Terra Directus 26/13.403 s, Juice 30/17.353 s, controls 35/1.833 s. Parent checks
between independent runs are excluded from these per-run profiles.

## Source audit and closure scope

These are known development cases, not unseen accuracy data. This audit is by the
implementation agent, not independent human ground truth. The selected native
properties and expected source mechanisms were frozen before calls. No SAML scope
dispute or unsupported candidate was carried into X.

**Protected HTML, Directus.** The actual selected assignment at
`app/src/composables/use-comparison-diff.ts:226` passes the result of
`dompurify.sanitize(incomingValue || '')` directly into a detached element's
`innerHTML`. The actual root catalog uses DOMPurify 3.4.16. The shared application
hook in `app/src/utils/md.ts` adds fixed protective `rel` values. This supports a
scoped negative for the selected assignment, without certifying downstream feature
transformations or all callers.

Native inspects the import, package/catalog and shared hook. Sol workspace inspects
the actual import and direct sanitize-result-to-sink chain, then closes under the
standard default API contract. It does not inspect the shared hook or package
catalog. Its local default conclusion agrees with actual safe source; this is not
a demonstrated wrong dismissal. However, the predeclared effective-configuration
basis is incomplete. Mutable shared instance hooks can materially change a control;
do not waive that gap after seeing the verdict. Version lookup is not universally
mandatory, nor is exhaustive caller or deployment discovery justified here.

**Owned address deletion, Juice Shop.** All three arms inspect the DELETE
registration at `server.ts:451`, `security.appendUserId()` before the handler,
the helper's overwrite of `req.body.UserId` from server authentication state and
its rejection without `next`, and `routes/address.ts:29` combining the object ID
with that same owner in `destroy`. Their scoped negatives are supported. This
does not certify separate token/key/login weaknesses. Native's wider authentication
exploration produces an unreviewed SQL-injection lead, not another selected finding.

**Local identity sanitizer.** The relative import resolves to the actual local
helper returning its input unchanged before `innerHTML`. All three arms retain the
conditional HTML issue under ordinary module/browser binding and mounted feature
conditions. Terra assigns high severity versus medium in Sol/native; the basic
mechanism agrees, but label agreement alone does not settle severity calibration.

**Unknown external sanitizer.** All three preserve actionable uncertainty about
the implementation/resolution of `@workspace/output-policy`. The package
declaration does not establish the implementation; a similarly named local helper
has a different binding. Its behavior is not transferred. Sol workspace additionally
repeats the already classified local identity-sanitizer concern as an unreviewed
lead; record it as duplication, not a second finding.

## What live feedback did and did not recover

Terra Directus naturally exercises the new path twice for the question about the
sanitizer's effective context:

1. Call two requests `references(symbol="dompurify", path="app/src", limit=100)`.
   It receives `file_filter_is_directory`, the offered `path_prefix` alternative,
   zero source evidence and zero native queries. An independently requested valid
   `addHook` prefix lookup in the same response executes and locates the shared hook.
2. Call three reads that hook but repeats the invalid directory-valued file filter.
   It receives another receipt; a valid same-batch `setConfig` lookup also executes.
3. Call four requests `references` with both `path="app/src/utils/md.ts"` and
   `path_prefix="app/src"`. This was outside the initial recovery class. Complete
   batch validation fails with `choose one research path filter`; no new query in
   that rejected batch executes and no Directus verdict is fabricated.

The two feedback attempts charge two query units and 874 received JSON bytes, with
zero native commands for those attempts. Every paid turn remains counted. The
question stays open. Same-batch valid requests were planned before feedback arrived;
they are not evidence that the model learned a correction. Transport and isolation
work; successful recovery of the whole case is not demonstrated.

## Post-study correction and next stopping rules

Subsequent user direction changes the **next evaluation scope**:
[retain supported work and correct only the affected boundary](review-workspace-surgical-plan.md).
The three non-Directus cases and useful partial Directus evidence remain retained.
Use targeted recovery/proof-completion follow-ups before another mixed comparison;
the earlier four-case-repeat recommendation below is superseded. This does not
change X's frozen expectations, costs, source audit or incomplete package gate.

After X closed, the common validator was extended offline to classify safe
conflicting filters as `conflicting_path_filters`. It asks the reviewer to choose
one explicitly; it never chooses or broadens scope. Both paths' lexical scope,
argument names, limits and journal binding are validated first, so a conflict cannot
mask an escape or invalid limit. Unknown/unsupported shapes remain fatal.

Two added tests cover an explicit later correction with all costs retained and
fatal scope/limit priority. Final verification is 129 workspace tests and seven
common-validator checks. A validator-only check of X's exact rejected request
returns the new feedback with zero provider/native calls and no replay of the paid
answer into a workspace. This extension has no new live recovery result. X's
archived code, paid traces, missing verdict and quality gate remain unchanged.

The next two practical directions remain narrow:

1. **Finish API error recovery as a bounded family.** File/directory and conflicting
   filter cases now have deterministic coverage. Verify the offered tools' remaining
   validation classes before freezing another run. Keep authority/ownership/source
   failures fatal and retain original requests, costs and deciding questions. Stop
   if recovery requires silent scope changes, unbounded retry or broader tool power.
2. **Make effective-control closure explicit in existing state.** When an imported
   control uses mutable shared application state, retain the deciding question about
   that configuration alongside the local sink proof. Use source-supported answers
   and existing category guidance. Check a direct default control, an unsafe shared
   hook and unresolved binding offline before a fresh small confirmation. Do not
   add a universal package/caller checklist or accept an `answered` flag as semantic
   proof. Stop if this only adds procedural records or unrelated exploration.

The original recommendation was to keep X's four-case full source gate for a fresh
confirmation with new frozen state and the supplementary Terra medium arm; the
targeted follow-up policy linked above now governs the next step. No more paid
calls were made after X's closure in this implementation turn.
Only consider wider experiments once all selected mechanisms/negatives/uncertainty
pass and routine tool errors recover within unchanged budgets. Generic memory,
an interactive CLI, a planning-model pass or wider grouping is not the next fix for
the two concrete failures measured here; those remain later hypotheses.

Raw evidence is under the X root: `study-freeze.json`, `execution.json`,
`collected-results.json`, per-dataset `workspace-question-trace.json`,
`evaluator-source-audit.json`, `source-audit.json`, `quality-gate.json` and
`study-closed.json`. Read-only closure verification checks 393 frozen artifacts,
deduplicates all 34 provider calls and confirms their exact models/medium effort;
`closed-verification.json` records the unchanged gate/audit hashes. Offline checks/logs are under
`C:/dmitry/scan-runs/workspace-filter-feedback-20261027-w`.
