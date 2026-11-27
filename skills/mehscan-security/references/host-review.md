# Review in the invoking session

The agent uses its active model and host-managed authentication for planning,
source investigation, triage, Comprehensive follow-up and audit. Use native
Mehscan commands to pin the source, validate the evidence and save the work.
For unattended automation, see the [review worker](../../../docs/review-worker.md).

## Prepare and authorize

Keep the trusted CLI, private claims and run directory outside the target source.
Use the project reference returned by `project prepare`, or bind an existing
review inventory. Build Changed or Impact inventories with their original
comparison and scope. [Staged source](../../../docs/standalone-source.md) ·
[Changed review](changed-review.md)

```sh
mehscan project bind --source-root "$ROOT" --inventory "$INVENTORY" --stream "$STREAM"
PROJECT="$INVENTORY/project-run.json"
mehscan state status --project-run "$PROJECT"
(umask 077 && mehscan state claim --project-run "$PROJECT" \
  --expected-generation "$GENERATION" --attempt-id value-1 \
  --operation-key claim-value-1 > "$PRIVATE/claim.json")
mehscan state plan-template --project-run "$PROJECT" --policy value \
  --selection policy > "$RUN/plan.json"
```

Use generation 0 for a new stream. Read the current generation for an existing
stream. Use `--retry true` for a deliberate fresh attempt on a finished snapshot.
To resume an interrupted attempt you own, use its original claim and work.
Leave another reviewer's active generation in place.
Keep operation keys stable on transaction retry. Claims authorize local journal
writes and stay private. They carry no model credentials.

Use the template to account for every native ID. Rank by credible effect, actor
exposure, deciding evidence and check cost. Record a reason for every deferred
ID. For Changed or Impact, complete the native change pass for every required
path, including deletions and zero-candidate files. Keep unsupported, unread
or unassessed work visible. [Review planning](review-planning.md) ·
[Change-pass schema](../../../docs/review-worker.md#prepare-review-work)

Save a short list of selected source checks with stable IDs, owner ranges,
actor, protected effect, deciding questions and completion criteria. Keep
deferred and unresolved checks visible. A useful Value plan can have named
checks and zero native IDs. Within the user's allowance, review the strongest
work first. Respect the host's usage data and leave unknown usage unestimated.

```sh
CLAIM="$PRIVATE/claim.json"
mehscan state plan --project-run "$PROJECT" --claim "$CLAIM" \
  --input "$RUN/plan.json" --operation-key plan-value-1
mehscan state work --project-run "$PROJECT" --claim "$CLAIM" > "$RUN/work.json"
```

## Investigate and admit

Use `work.json` for authorized IDs, pending questions, evidence updates, saved
knowledge and expected parents. Read the deciding source in the active session.
When delegating with guaranteed model and account inheritance, give a subagent
an exact ID or named check, its source fingerprint and bounded read scope.
Collect source references and proposed answers. The invoking agent validates
them and writes the plan, assessments and state.

```sh
IDS=$(jq -r '.payload.review_ids | join(",")' "$RUN/work.json")
mehscan investigate source-review-plan "$ROOT" --inventory "$INVENTORY" \
  --review-ids "$IDS" > "$RUN/source-plan.json"
```

Use the source plan as an index. Read the selected operations and specific
supporting facts, including source checks with no native ID. Keep the original
source plan unchanged. For new consequential claims, prepare an admission JSON
object with `proposals`, `inspected` and optional `assessment_evidence`.
Each proposal needs `key`, `assignment_id`, `capability`, `cwes`, `question`,
`mechanism`, `consequence`, `priority` (`value` or `comprehensive`),
`anchor` and `evidence`. A citation uses `path`, inclusive `start_line` and
`end_line`, and the exact line `quote`. Its anchor must be in the named
assignment. Supporting windows outside it go in `inspected` with the same
shape as a plan window, including the source file hash and exact window text.
Use source bytes for both. [Source review](source-review.md)

```sh
mehscan investigate source-review-check "$ROOT" --inventory "$INVENTORY" \
  --source-plan "$RUN/source-plan.json" --input "$RUN/admission.json"
mehscan investigate source-review-admit "$ROOT" --inventory "$INVENTORY" \
  --source-plan "$RUN/source-plan.json" --input "$RUN/admission.json" \
  --output "$RUN/effective-inventory" > "$RUN/source-admission.json"
```

Run admission when there are new source questions to register. A validated
proposal creates a question ID, which still needs an evidence-backed verdict.
If admission produces an effective inventory, use the returned ID mapping,
bind that inventory with the same stream, state and memory, and claim its
generation. Refresh the plan and work package, carrying the original selection
and change-pass accounting into the new inventory. Complete this handoff
before finalizing bundles. Keep the earlier reference and its history.

```sh
IDS=$(jq -r '.payload.review_ids | join(",")' "$RUN/work.json")
mehscan investigate review-bundles "$ROOT" --inventory "$INVENTORY" \
  --review-ids "$IDS" --output "$RUN/bundles"
mehscan investigate review-bundle-finalize --bundle "$REQUEST" --draft "$DRAFT" \
  --journal-dir "$RUN/journals" --source-root "$ROOT" --output "$RESPONSE"
```

Finalize each reviewed request to `bundles/responses/` using the request's
filename. Consult [bundle review](review-workflow.md) and [finalize and report](finish-review.md).
Keep missing responses visible. To freeze named checks in the report, validate
their exact inspected citations with `source-review-check` and save them in
`bundles/manifest.json` under `source_review_cases`. Each case has `id`,
`owner_path`, `actor`, `conditions`, `status`, `next_deciding_facts` and
`checks`. Each check has `id`, `question`, and `status` of `satisfied`,
`violated`, `unresolved` or `not_checked`. Include the summary and exact
path/line citations for answered checks and the deciding fact for unresolved
ones. This also works with an empty native bundle manifest.

## Close and report

```sh
mehscan state record --project-run "$PROJECT" --claim "$CLAIM" \
  --work-package "$RUN/work.json" --run "$RUN/bundles" \
  --reviewer "$REVIEWER" --operation-key record-value-1 > "$RUN/record.json"
ADMITTED=$(jq -r '.project_run' "$RUN/record.json")
mehscan state end --project-run "$ADMITTED" --claim "$CLAIM" \
  --status finished --operation-key close-value-1 > "$RUN/close.json"
mehscan report --close-receipt "$RUN/close.json" --format markdown
```

Set `REVIEWER` to the host model label when available. Use `--allow-partial true`
on `state record` for missing response files and `--status incomplete` for an
interrupted execution. A present response must account for all IDs in its bundle.
Use native status and the named-check list to report reviewed, pending, skipped
and deferred work. Check the close receipt's memory status before publishing.
Keep earlier close receipts and their frozen findings.

## Continue Value into Comprehensive

For an open attempt, bind a revised native plan with the current
`--expected-plan-id`. For a closed Full-repository Value attempt with a manual
plan, claim its exact close receipt with `--policy comprehensive`.

```sh
(umask 077 && mehscan state claim --close-receipt "$VALUE_CLOSE" \
  --policy comprehensive --attempt-id comprehensive-1 \
  --operation-key claim-comprehensive-1 > "$PRIVATE/comprehensive.json")
```

Use the `project_run` from the close receipt and the new private claim to obtain
current work from `state work`. Broaden the named checklist and work through
new, missing or changed deciding facts under the remaining allowance. The
Comprehensive native plan selects all eligible IDs in that scope. For Changed
or Impact, revise the open plan or claim a fresh attempt and build a
Comprehensive plan on the same scoped inventory, keeping the change pass.

Use the frozen report and prior bundles as input to continuation. Re-admit
unchanged responses with matching requests, current parents, valid premises and
the original reviewer label. If a request changed, revalidate its deciding facts
and finalize against the current request. If the answer changes, use the exact
supersession procedure below. A new generation requires current admission.
Carry forward unresolved facts and source limitations. Reuse evidence where
it still applies and account for every selected ID and required check before
reporting the effort complete.

## Audit

Read the baseline through the exact close receipt. For Fast, select bounded
nominations under the [Fast rules](second-pass-review.md#automatic-fast-selection).
If there are no nominations, report an empty audit queue. For Full, check every
admitted decision in the requested scope. Stage a source-first assessment
before comparing it with the baseline. Use a fresh, blind host context only
when it guarantees the same model and account. If the active context already
knows the baseline, label the result a same-session recheck and state the
independence limit.

Use `state claim --close-receipt` with a fresh attempt ID and the new private
claim to get current work from a manual baseline. For a baseline bound to an
automated runtime, start a fresh native claim on the exact inventory and bind a
manual plan. Read the baseline using its receipt and verify that its decisions
are still current heads before using it. This approach also supports an
invoking-session Comprehensive review of a prior automated Value result.
Eligibility and current ownership still apply.

For a changed decision, first render `mehscan report --run "$RUN/bundles"
--source-root "$ROOT" --reviewer "$REVIEWER"` with the same options as admission
to obtain the incoming decision ID. Supply `--supersessions FILE` to
`state record` with entries of
`{"decision_id":"NEW_ID","parents":["EXACT_CURRENT_HEAD"],"reason":"Deciding evidence"}`.
Use all exact heads for the subject from the current work package. Preserve
unchanged decisions, mark unaudited claims explicitly, and refresh work if a
parent changed. Close and report the resulting generation. Keep the original
receipt available for comparison. [Decision lineage](../../../docs/review-state.md#supersede-explicitly)
