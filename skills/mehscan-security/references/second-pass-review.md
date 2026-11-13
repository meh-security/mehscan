# Optional second-pass review

Use only when the user requests Fast or Full second-pass review. The default is
off; this option is independent of Value/Comprehensive. Keep exact claim IDs and
their actor, operand, branch, selected property and effect separate.

A work-plan first pass can add `--second-pass fast|full` directly. Its prepared
source and assessments enter this same audit pipeline under the remaining shared
allowance. For a later audit, use the native-phase first-pass workflow below;
the bound work-plan handoff preserves the parent allowance and reports the
original case checks as historical coverage. See
[work-goal continuation](work-goals.md#choose-the-goal) for compatibility and
native-finalization recovery.

## Automatic Fast selection

First-pass assessments can return a nullable `followup` scheduling note with a
typed reason and one deciding question. Native and source-discovered claims use
the same mechanism. These notes are hypotheses, separate from native verdicts.
An AI-only source first pass needs no scanner candidate to enable follow-up:
its admitted source-discovered claims carry the same scheduling notes and cited
facts. With no claims, Fast has nothing to audit; scoped threat review can still
examine a source-backed flow or coverage gap without inventing a claim.
The controller selects exact nominations for conflicting evidence, uncertain
control applicability or named missing local evidence. Explicit claim_context
can also nominate a positive proof check: unresolved/dormant activation asserted
as an application path, unresolved impact, or severe local/optional claims whose
reaching conditions need checking. These signals question the proof, not the
verdict; a conditional library defect can remain a valid severe finding.
Positive proof signals rank first, then nomination reason and assessed severity.
Prefer one representative per cited repair point to repeated checks of the same
failure. Unselected siblings remain unaudited; no verdict is propagated.
Confidence or a pending label alone does not select a claim. External/human-only
blockers do not enter Fast without changed evidence.

Fast selects at most 25% of the eligible claim pool (rounded up), capped at 20
claims. `--fast-max-claims N` can lower that cap. These are workload limits, not
coverage guarantees. Every selected claim has its question/reason and selection
source in `review-options.json`; cap/shared-root deferred and unselected claims
retain their first results. Selection makes no additional model call. Legacy results without notes or context
produce an empty Fast queue; never fall back to all claims. Full has no automatic
narrowing and retains its independent-assessment/comparison behavior.

Fast checks the selected claim's proof and repairs actionable gaps. It can
follow a relevant cross-file producer, guard or consumer; it does not perform
fresh application-wide threat discovery. Use ordinary source/lead review for a
distinct new mechanism. Keep a locally effective control separate from an
upstream weakness and group effects under their actual repair point.
Fast has a bounded research allowance, not a guaranteed latency or cost saving.
The user or calling agent chooses Fast/Full and the eligible work package; the
controller owns Fast's exact selected subset. Use Full for an all-claim audit.

## Run with the local worker

Add `--second-pass fast` or `--second-pass full` to the normal worker command.
The worker retains the first source-validated responses before reviewing them.
Choose the eligible IDs with the normal work package/bundles, then optionally
narrow their verdict classes with the scope filter below. Fast still applies
automatic selection inside that pool; Full checks every member of it.
Use `--second-pass-scope issues|dismissals|pending` or comma-separated combinations
to narrow eligible first-pass decisions. Default: `all` eligible verdict classes,
not an all-claim Fast audit. Scope and automatic selection filter before
rebundling, so other claims consume no second-pass calls and retain their original
result marked outside scope. TP/FP aliases refer to the first labels, not truth.
To check an already admitted attempt, refresh `state work` for the chosen IDs,
pass that current work package, and add `--first-pass OLD_ATTEMPT --supersede`.
Use the current source/runtime/provider binding and a new output directory.
`--validate-only` produces source-validated reports without changing native state.
Select scope with the normal work package/bundles, including clean and pending
claims. A partial second pass never becomes complete coverage.

Fast records an audit checkpoint against the first result and its actual evidence,
then resolves concrete objections in the same conversation when necessary.
It uses the normal bounded research allowance and can finish immediately when
the evidence already settles the question. Full additionally performs a blind
independent investigation and a separate comparison; use it for deeper audits,
evaluation and training-data review. Neither mode approves training labels.

Read `second-pass.md` and `second-pass.json`: first/final decisions, confirmed,
corrected, reopened, unresolved and not-checked outcomes, objections and receipts.
`findings.json` is the native final report. `finding-groups.md/json` proposes
causal families while retaining every claim and its conditions; it does not
deduplicate native decisions or certify unique vulnerability totals. First-pass
annotations remain explicitly historical after a later proof change.
First responses remain in `first-pass/`;
original completed attempts are unchanged. A failed check retains the original
decision marked not checked. Native state is authoritative after admission.

`training-labels.json` separates verdict, proof/investigation assessment and label
authority. Model-reviewed candidates are not automatically approved training
examples. `training-turns/` preserves actual task/fact/response snapshots and
their context links. Train only on approved assistant actions; source/controller
tokens must be loss-masked. Do not invent missing turns, hidden reasoning, or a
corrected first-pass history using evidence retrieved in the second pass.

<!-- runtime:second_pass_fast -->
Audit stage_context.baseline against supplied actual source and the compact
lookup_trace. Treat its verdict and rationale as hypotheses. Before keeping a
result, identify the invariant that decides this exact question and challenge
its weakest material premise against the actual source. Agreement with the
baseline, repeated citations or a complete lookup is not a counter-check.

The controller supplies fast_phase. In audit, return a provisional draft and
review_checks for all selected IDs using supplied evidence, without new research.
Name the exact failing premise or deciding missing fact. Proposed corrections
are hypotheses at this checkpoint. Use missing_available_evidence for a decisive
unread implementation and external_blocker only for a genuinely unavailable fact.
Keep supported local closures and justified external uncertainty. The controller
finishes those cases or opens recovery for actionable objections; a full draft
at the audit checkpoint does not mean that the investigation is complete.

In recovery, research only the recorded actionable objections and test their
applicability. The audit may be wrong: reject an inapplicable objection rather
than promote it. Keep settled sibling IDs stable, return every final review_check,
and assess actions against the original baseline. In repair_check, challenge the
proposed replacement proof before admitting a closed correction. All phases use
one bounded conversation allowance, separate from the first investigation.

For authority or persisted-state claims, separate a correct local predicate from
the integrity of the value it trusts. Reading a session, cached subject, tenant
key or workflow flag does not prove who can change it. A legitimate issuer is
one producer, not coverage of alternate writers. Use supplied registrations or
returned references to inspect a relevant write/acceptance path when it could
change the selected effect; do not enumerate every caller. An earlier request
or lifecycle transition that changes the same relied-on state belongs to this
claim even when its weakness has another category. Check persistence and actual
read/write order; an independently captured value need not change with the state.
Keep unrelated effects as separate source leads.

For a locally complete grammar, transformation or numeric control, test the
actual operands and API sequence. Do not invent an identity or caller audit that
cannot change that property. If the evidence settles the counter-check, finish
immediately. Otherwise name the deciding fact, retrieve it through the offered
API and follow the result to a supported correction or precise remaining gap.
Keep settled IDs stable; reuse facts and do not repeat the entire investigation.
Do not stop merely because you found a repairable gap.
Before installing a closed repair the controller may request a counter-check in
this same conversation. Test the replacement proof against active code, earlier
guards and contrary evidence; comments or disabled alternatives do not establish
the invoked behavior. Confirm, amend or reopen the proposal using the remaining
allowance. A new unproved premise is a question, not a replacement finding.

Refuting one proposed source of a trusted value does not refute alternate
producers already supported by the supplied source. Match a negative's scope to
the property actually established. Helper names, sample/repository labels and
configuration intent cannot replace a deciding implementation or contents check.
Reuse relevant source facts from sibling reviews without adopting their verdicts
or transferring their caller conditions. Local closure still needs no caller hunt.

The recovery budget reserves an existing call for repair validation. When no
research rounds remain, finish from inspected evidence or name the actual gap;
do not spend the validation slot on another lookup. If a closed repair is deferred,
distinguish its pending validation from source questions the recovery answered.

During research return review_checks=[]; on the final draft cover every ID once.
action=keep retains the original material proof, including justified uncertainty,
with proof_status=supported and no error_codes. action=repair with
proof_status=supported can correct a verdict, proof, conditions or severity,
including closing pending. Name the old claim that fails and the evidence that
settles it. Confidence alone cannot support an opposite verdict.
If the deciding fact remains unavailable or the actual allowance is exhausted,
return needs_review with that question; action=reopen preserves uncertainty.
An unread necessary implementation is missing_available_evidence; an unavailable
contract is external_blocker. action=insufficient with proof_status=undetermined
means the check did not complete, not that the first result was refuted. Use
targeted lookups first when they can recover an available fact. Missing trace
history alone need not block a source-backed assessment. Preserve actual caller,
platform, activation and effect conditions and give source-supported error_codes.
<!-- /runtime:second_pass_fast -->

<!-- runtime:second_pass_compare -->
Compare stage_context.baseline and the independently saved assessment against
actual deciding source and the original lookup_trace. Neither reviewer is
authority; labels/confidence are not votes. Same-label agreement with a wrong
mechanism or omitted condition is still a proof defect. Check concrete disputed
inputs through the actual API sequence and earlier successful caller checks.
Use only supplied evidence in this final-only comparison; do not request another
research loop. Missing deciding evidence leaves a precise pending question.
Return an ordinary draft plus review_checks for exactly the assigned IDs.
action=keep retains the baseline label AND material proof (proof_status=supported,
no error_codes). action=repair with proof_status=supported proposes a correction
to label, explanation or conditions; name the specific old claim that fails and
why the returned draft follows from the source. This includes a pending-to-closed
result only when its exact missing fact has been settled. Other repair/reopen
actions retain needs_review. action=insufficient with proof_status=undetermined
means comparison is incomplete and cannot override the baseline. Different
assertions unsupported by deciding evidence remain pending, not silently settled.
Keep actual deployment/target prerequisites, safe caller invariants and valid
uncertainty. Preserve supported adjacent mechanisms as source leads without
changing the selected question. Byte-exact source and agreement do not make
training labels ground truth. Return concise claims, not investigation narratives.
<!-- /runtime:second_pass_compare -->
