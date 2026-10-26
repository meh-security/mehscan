# Revised workspace experiment plan — 2026-10-26

**Superseded execution direction:** the user requested an expanded comparison
and clarified that input is cheap and output currently negligible. Follow the
[completed four-arm, twelve-claim comparison](review-workspace-expanded-results.md). The two-consumer
result below is useful trace evidence, not a sufficient basis to select or stop
the overall workflow. Its allowances remain closed; the expansion has a separate
frozen manifest. Historical 30%/50% input gates below are retired as selection
criteria; supported mechanisms, uncertainty, repeated work and time take priority.

Status: the [consumer comparison](review-workspace-consumer-results.md) is closed.
The notebook avoided helper lookups but saved no model turns: input increased
11.70%, and both arms retained the same unresolved basket effect. The original
14 charged-call allowance is exhausted. Next is offline deciding-work/source
analysis and a narrowly scoped same-caller grouping design; no paid repeat or
automatic notebook expansion follows this result.

M0 passed the [one-call smoke check](review-workspace-smoke-results.md).
The M1 notebook handoff is implemented; its [live producer attempt](review-workspace-notebook-results.md)
stopped with actionable uncertainty before producing a notebook. No consumers ran.
The attempt is closed. [Offline route-source preparation and version-2 question
rendering](review-workspace-v2-offline-results.md) now pass native packet and
controller tests with zero provider calls. The [subsequent producer-only
test](review-workspace-producer-v2-results.md) completed in two calls and exported
one bounded, wallet-scoped note. The consumer comparison used that unchanged
notebook and is now closed with the result above. This supersedes
the next-work ordering in the [pilot result](review-workspace-pilot-results.md),
while preserving the failed experiment, its manifests and all paid costs.

That consumer step has now run. The live handoff preserved scope and avoided two
definition requests, but the consumers still needed unique handler/effect reads
in the same turns. Source-backed case delivery is therefore implemented, not
economically validated. Follow the new offline stop decision above rather than
reopening any of the historical phase allowances described below.

The second review reproduced a context-loss defect and reduced the work required
before a useful reuse experiment. The subsequent implementation fixed receipt
delivery and restart/accounting guards; a single login replay completed in
28.4 seconds with observed usage and passed offline action/source audit. This is
execution and local closure evidence, not a live reuse or cost-saving result.

| Area | Established | Still missing |
| --- | --- | --- |
| Persistent state and native integration | Deterministic recovery/provenance and multiple live source-finalized responses, including explicit uncertainty | Complete mixed package with all supported mechanisms closed or precisely limited |
| Context assembly | Fresh packets omit conversation-history replay; open questions retain distinct lookup receipts | Useful session policy and measured repeated-work reduction |
| Knowledge | Live notebook delivered safely to both consumer contexts; helper rereads avoided | A complete review package with lower total input/calls/time |
| Rule strategies and grouping | Design only | A measured small SQL batch and guard-to-effect investigation |
| Economics | Full consumer accounting: four calls per arm, input regression with notebook | A quality-preserving package that passes the efficiency gate |

M1 implementation now also has bounded export/import, preserved source provenance,
revision mapping and interrupted handoff tests. Its failed producer is not evidence
that supplied facts are useless: the model had not yet read the route source, and
a local pre-dispatch abort consumed one producer reservation. Operation context
and native `checks` rendering were corrected before the later producer and
consumer runs; those implementation fixes did not establish a memory saving.

That correction is implemented: native-reference windows expose the three route
declarations in matched packets, and the controller renders outstanding checks
and blockers from question state under `workspace-actions-v2`. The source still
does not certify guard semantics or caller applicability. A future producer test
must include preparation queries/source bytes/time in its finite allowance, use
fresh version-2 bindings, and stop if it fails to produce a complete bounded fact.
No M1 consumer phase or old expired allowance has been reopened.

The subsequent [producer-only test](review-workspace-producer-v2-results.md)
completed in two model calls and exported a 3,503-byte notebook. Native source
validation and source audit passed for the selected wallet relationship. The
note remains explicitly wallet-scoped and excludes token-map integrity and other
routes; it must not become a universal ownership verdict. Next is a separately
frozen consumer-only comparison using that unchanged case/source notebook, with
the compatible deluxe context and incompatible basket route-ID effect. No
consumer has yet used the live-produced notebook.

## What needs correction

The persistent state, independent drafts, actual source receipts, usage
reservations and native finalization are useful implemented foundations. Their
tests establish integration. They do not yet show that a reviewer reconstructs
less context or spends less time.

The first paid trial combined a new action contract, on-demand guidance,
fresh-per-turn sessions and optional memory. Its ordered cases began with two
different SQL implementations, then stopped before the related identity cases.
The corrected search answer saved no proposition. There was no producer/consumer
sequence and no live test of memory. Calling this a failed memory architecture
would overstate the evidence; calling it successful because its first prompt
was smaller would also overstate it.

The original rejected search answer was semantically useful but violated a wire
field rule. The schema correction is appropriate to retain, but duplicating
verdict variants is not evidence that provider latency was fixed or caused.
Reconstruction from saved tasks/packets measures the corrected schema at
13,095–13,183 UTF-8 JSON bytes, and the review prompt at 9,411 bytes for search,
9,700 for initial login and 15,918 after the login lookup. These are bytes, not
token estimates or exact captures of the invoked prompt: the runner also adds
remaining case allowances at dispatch.
Schema cost and inherited/provider instructions are not explained by source
window size alone. Preserve exact hashes in subsequent measurements.

Login's question about `verifyPreLoginChallenges(req)` was reasonable: that
helper executes before email is read into the query and could mutate input or
stop execution. The returned file shows challenge checks, not SQL protection.
Result handling can bound authentication impact separately. The correction is
to close the requested relationship once that evidence arrives, rather than
forbid the lookup or require discovery of every caller. The timed-out turn
provides no completed response from which to diagnose a reasoning failure.

The strongest reuse target in the observed baseline is concrete: overlapping
identity-helper reads across seven claims, with two unresolved producer questions
that another review already answered. Delivering that fact requires retrieval
and scope selection, not just SQLite persistence and a model-initiated literal
search. This is the next semantic experiment.

The second code review found a separate defect in `Workspace._view`: receipts
are keyed only by question ID, so a later navigation result replaces an earlier
result for the same question. An offline reproduction stored two distinct path
lookups and exposed only the second to the next reviewer. Source excerpts are
retained separately, but navigation-only results can be lost before inspection.
This is not an explanation for the single-source login timeout. It is a concrete
reason to fix context delivery before testing multi-lookup investigations.

Implemented in M0: receipts are now keyed by lookup identity, and regression
coverage retains both navigation answers and rejects context overflow. Existing
frozen experiments were not rebound to the changed controller.

## M0: bounded completion diagnostic

First, without inference:

1. Replay the rejected search envelope and accepted envelopes through current
   validation. Preserve the rejection; do not silently discard nonempty checks.
   Verify the corrected wire constraints and native finalization separately.
2. Capture prompt/schema hashes and byte counts, provider-task start, completion
   or timeout, returned counters and controller duration. Use event metadata;
   never export authentication or private reasoning. Test timeout termination
   and the unknown-usage stop gate deterministically.
3. Make the experiment runner refuse accidental restart into an existing result
   directory. Persist call/deadline accounting before dispatch and distinguish
   attempted, observed, rejected and validated turns in every summary. The
   original control completed, but its summary helper reports observed metrics;
   future incomplete summaries must not imply those are total attempted costs.
4. Preserve every newly returned lookup in a question's response batch until the
   next model turn can inspect it. Retain distinct unresolved facts from earlier
   batches with explicit evidence selection; compact redundant history only
   after it has been presented. Source text can remain deduplicated. Include
   result identity, completeness/truncation and outstanding question status.
   If the batch cannot fit, report a context limit instead of silently dropping
   a result. Test two different navigation answers under one question, not only
   a source/navigation/guidance mix.

Then a small rerun is justified: replay the saved **post-lookup login task** from
attempt `e` in a newly bound diagnostic run. Its source, open question and
available evidence are already known. Use the current corrected action schema,
same model/effort and the same private isolation policy. Do not add the old
answer, evaluator labels or a hinted verdict. Rebind conversation/artifact
identities and record the changes; never mutate or redispatch the original
unknown call.

Allow **one** fresh attempt, at most 180 seconds. This is a completion smoke
test, not a latency experiment. Repeating the same successful task twice would
not identify the cause of the previous stall, so remove that mandatory repeat.
Stop at a timeout, execution/protocol failure or unknown usage. A completed but
still uncertain answer receives a separate source audit; execution success does
not establish correct closure. The 180-second cutoff is an experiment spending
limit, not evidence that slower answers are incorrect.

**Pass:** the call completes within its bound with observed usage and valid
actions. Audit its disposition of the deciding question before interpreting its
review quality. **Stop:** failure pauses paid review experiments. Inspect existing
event metadata and offline protocol complexity before changing one named variable
in a newly budgeted diagnostic. Do not automatically lower effort, increase
timeouts or rerun all 12 claims. Success does not establish a provider latency
cause or production reliability.

## M1: make fact delivery real, then test three related claims

Use the existing proposition and work-item focus APIs for a bounded notebook.
Deliver the producer's available source-backed propositions to the two later
claims, with conditions, exclusions, revision, decisive source and remaining
caller obligations. For this three-claim fixture, cap the notebook at four
propositions and 8 KiB total for serialized propositions and supporting excerpts.
Deliver all within that bound; do not select only facts known by the evaluator
to produce the desired verdict. If it exceeds the bound, stop preparation and
inspect scope rather than silently truncate. Offer evidence without asserting
applicability or assigning verdicts.

A general relation index is deferred until useful live reuse is demonstrated.
This deliberately tests whether a small supplied notebook saves investigation,
not whether automatic retrieval scales to an application. Avoid new retrieval,
embedding, routing or summarizer subsystems for this milestone.

Use the same pinned real source and native IDs:

| Order | Selected claim | Purpose |
| --- | --- | --- |
| 1 | `observation-review-d3ddaeb3c0f97e31` — wallet balance lookup | Produce the subject-binding implementation fact |
| 2 | `observation-review-8b646b5eb87d733e` — deluxe customer lookup | Reuse with compatible subject binding; preserve the separate payment prerequisite lead |
| 3 | `observation-review-9bdb9475c1030df9` — basket item lookup | Detect the exception: binding body.UserId does not constrain an item loaded by route ID |

Keep each claim's verdict separate. The same helper is relevant to all three,
but it is insufficient to establish basket ownership. Do not grade deluxe as an
ownership positive because a different payment mechanism exists. Report local
closure, supported adjacent leads and admitted findings separately.

Before paid execution, extend the existing deterministic native integration
fixture to these relationships. Verify delivery to the next work item without
a discovery call, caller applicability, incompatible effect, a retrieval miss,
proposition revision/invalidation and interrupted resume. Assert what the
consumer packet actually contains. Include a missing caller relationship that
must remain unresolved despite the shared implementation fact. These tests supplement existing generic
safe/unsafe fixtures; they are not evidence of model savings.

Run the wallet producer once, then freeze its actual answer, propositions and
source receipts. Use isolated consumer workspaces for the same deluxe and basket
claims: one receives the bounded notebook and one receives no cross-claim
interpretations. Both retain ordinary source lookup and identical initial native
claim windows before notebook delivery. The additional fact/excerpt bytes are
part of the measured reuse treatment. Use the same model/effort, compact contract,
schema and fresh-session policy. Freeze consumer-arm order before dispatch and
run serially. No manual evaluator-authored proposition may be inserted.

Replay the producer's source-bound receipts through existing state operations
to prepare the consumer contexts; preserve origin and hashes. Do not build a
general workspace-fork service or copy provider conversations/authentication.
If the producer does not establish/save a useful fact, stop and inspect that
gap rather than run consumers against an empty notebook.

Allow at most three producer calls and five pooled calls for each two-consumer
arm, with the native four-call per-claim ceiling retained. This replaces the
arbitrary two-call limit on every claim: a material caller question may need an
extra turn. If a limit prevents closure, preserve uncertainty and mark the
comparison incomplete. Do not claim savings from the cheaper incomplete arm.

Report two cost views. Actual experimental spend is diagnostic + producer +
both consumer arms + preparation. For the paired reuse comparison, charge the
same measured producer/preparation cost to each alternative: `P + C_off` versus
`P + C_on`. Clearly label that shared allocation; do not sum the two alternatives
as actual spend. This isolates consumer reuse of a fixed learned fact and does
not measure the reliability of independently producing that fact on every run.
The ordinary product baseline remains a descriptive reference.

Measure total input/output/time including production, fact delivery and repair;
source delivered repeatedly; proposition IDs/revisions offered and used; remaining
caller checks; repeated helper reads; and any mechanism lost through reuse.
Audit read avoidance against the deciding evidence, not a counter of tool calls.

**Proceed:** the producer and consumer deciding relationships close from source,
the supported basket mechanism and deluxe payment lead survive, no unsupported
applicability transfer occurs, and consumers demonstrably avoid reconstructing
the shared fact with enough saved input to cover producing/delivering it.
Report exact savings even if below the later 30% mixed-package gate. **Dig
deeper:** fact saved but not delivered, delivered but inapplicable, or delivered
without enough deciding source. **Stop this approach:** unsafe verdict transfer,
lost supported mechanism, or no avoided investigation in a complete comparison.
A repair/repeat would require a new explicit hypothesis and budget, not an
implicit extra allowance. This three-claim test is feasibility evidence,
not a statistically reliable whole-app estimate. More unresolved claims or less
coverage cannot count as a reuse efficiency improvement.

## Shared allowance for M0 and M1

Before any new call, freeze a new manifest and separate stores with exact package,
provider and source hashes. The proposed combined ceiling is **14 attempted
calls, 200,000 observed input tokens, 14,000 observed output tokens and 1,200
seconds elapsed**, including both arms, diagnostic calls, preparation and any
rejected work. M0 consumes at most one call; M1 consumes at most thirteen
(three producer calls + five consumer calls per arm). No
automatic extra correction/repeat allowance is added. Token gates use actual
counters; a final call can overshoot an observed-token threshold, and that
overspend must be reported. Unknown usage stops dispatch immediately and remains
unknown in the whole experiment total. Run arms serially to avoid cross-arm
provider contention. Use 180 seconds for M0, 240 seconds for the producer and
360 seconds for each consumer pair, all clipped by the whole-run deadline.
Allow twelve query units and 128 KiB of received result JSON for the producer
and for each consumer pair (36 units and 384 KiB total). Every call is also
bounded by its phase's remaining allowance. Record preparation within the
whole-run time; these limits do not grant extra time when preparation is slow.

The old control is a useful source/quality and descriptive cost reference. Do
not rerun it now, and do not present comparison with it as isolated memory
savings after changing the review package. This new allowance is a proposed
separate experiment, not a reset of the failed pilot's budget.

## M2 and later: test the other hypotheses separately

After M0, a bounded SQL grouping diagnostic can be prepared independently of M1
achieving a large savings percentage. Compare the two real SQL constructions
as singletons versus one small construction-review work item. Keep per-claim
verdicts, independent source chains and a shared total allowance. These are
similar construction questions, not a shared implementation fact. Do not claim
clean-control coverage from two positives; a later mixed slice must include real
bound-query controls and dynamic-fragment exceptions. Freeze a separate budget
before M2; it is not included in or authorized by the proposed M0/M1 allowance.

Choose source windows by deciding relationship, applying the same preparation
policy in both compared arms. Broader operation review should be reserved for
guard-to-effect, credential and workflow questions. Do not preload known answers
to eliminate lookups selectively. Consider bounded dependent continuation only
as a separate measured session-policy change.

Defer AI grouping until deterministic batches show useful savings and splitting
behavior. Its input should be a compact claim/dependency index, and its cost
must be counted. Keep the operator interface sufficient to inspect state,
questions, evidence and resume; postpone a rich interactive UI until review
behavior earns further investment.

Only after the promising components are identified should the complete mixed
slice be repeated, with unresolved cases and complex mechanisms preserved and
all results accounted for. Apply the existing 30% promising / 50% strong input
gates, quality requirements and time/output review there, then use reserved
held-out cases. No full-app rerun before those gates pass.
