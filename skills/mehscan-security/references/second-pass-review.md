# Optional second-pass review

Use only when the user requests Fast or Full second-pass review. The default is
off; this option is independent of Value/Comprehensive. Keep exact claim IDs and
their actor, operand, branch, selected property and effect separate.

## Run with the local worker

Add `--second-pass fast` or `--second-pass full` to the normal worker command.
The worker retains the first source-validated responses before reviewing them.
Use `--second-pass-scope issues|dismissals|pending` or comma-separated combinations
to narrow the first-pass decisions checked. Default: `all`. Scope filters before
rebundling, so other claims consume no second-pass calls and retain their original
result marked outside scope. TP/FP aliases refer to the first labels, not truth.
To check an already admitted attempt, refresh `state work` for the chosen IDs,
pass that current work package, and add `--first-pass OLD_ATTEMPT --supersede`.
Use the current source/runtime/provider binding and a new output directory.
`--validate-only` produces source-validated reports without changing native state.
Select scope with the normal work package/bundles, including clean and pending
claims. A partial second pass never becomes complete coverage.

Read `second-pass.md` and `second-pass.json`: first/final decisions, confirmed,
corrected, reopened, unresolved and not-checked outcomes, objections and receipts.
`findings.json` is the native final report. First responses remain in `first-pass/`;
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
lookup_trace. Check whether decisive questions were answered by the returned
evidence, whether the relied-on guard was read, and whether the claimed caller,
platform, condition and effect actually match. A loaded guide, complete range,
successful lookup or valid citation does not establish a correct proof.
This is one final-only assessment. Do not request new research. For each assigned
ID return the baseline decision or a needs_review draft with decisive source.
You cannot promote, dismiss or close a pending claim. Do not repair prose into a
new accepted conclusion: the controller retains the baseline or reopens it.
Return review_checks covering every ID exactly once. action=keep means the
original material claims are supported, including justified uncertainty; use
proof_status=supported and no error_codes. action=repair or reopen needs a
specific contradicted claim or missing decisive relationship in claim. An
unread necessary implementation is missing_available_evidence; a genuine
unavailable contract is external_blocker. Do not invent caller searches for
locally complete SQL grammar or numeric-count checks. action=insufficient with
proof_status=undetermined means this audit packet cannot check the conclusion;
it does not refute the first result. Missing trace history alone need not block
a source-backed assessment. Give only source-supported error_codes.
For each proposed bypass, follow a concrete input through the actual transforms
and API semantics; a prefix alone does not prove base replacement. For helper
findings check earlier successful application constraints. Preserve relevant
read/write ordering and conditional prerequisites. Adjacent concerns belong in
separate source leads, not a substituted verdict for this property.
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
