# Budget and coverage goals

Use a source-bound work plan when the user chooses a spending allowance or a
specific set of checks to finish. Both goals use the same impact-prioritized
backlog and controller-owned work ledger. Value prioritizes the strongest credible
impact; a coverage target names the required subset. Existing native/exact-ID,
domain, SQL, compiler and workspace/hybrid workflows retain their own routing.

## Choose the goal

Add these flags to the usual fresh `review_worker.py --phase all` invocation:

```text
--work-plan RUN/work-plan.json --review-goal budget
```

Budget mode ranks ready work by potential impact, actor exposure, evidence strength
and estimated next work. The default allowance is 40 managed calls, 1.5M observed
input tokens and a 20-minute new-call admission window, with three reviewers.
These are safety ceilings, not spending targets or a fixed number of items.
There is no default monetary cap. Lead progress reports with items and checks
completed versus remaining, followed by potential-impact gaps and unknown scope.

Use configured rates to keep cost information without a financial stopping rule:

```text
--work-plan RUN/work-plan.json --review-goal budget --cost-rates TRUSTED/rates.json
```

Only add a monetary allowance when the user explicitly requests it:

```text
--work-plan RUN/work-plan.json --review-goal budget --cost-budget 5 --cost-rates TRUSTED/rates.json
```

For an explicit completion target:

```text
--work-plan RUN/work-plan.json --review-goal coverage --coverage-target login-auth,profile-execution
```

Coverage defaults to all declared work items when no target IDs are supplied.
It retains the same safety allowances; configure `--max-calls`,
`--input-token-budget` and `--admission-seconds` before starting when the authorized
target needs more work. A cost allowance can also guard coverage work. Reaching
any allowance leaves the target incomplete. Blocked or unresolved required checks
also leave it incomplete. A completed target never clears out-of-target risks.

This path supports Value or Comprehensive native plans, including an explicitly
requested Fast/Full audit after the source pass. It cannot combine with
source/domain selection, source-result reuse, operation grouping, native-only
profiles or native-share overrides. Work items use isolated provider sessions
and a single ranked queue.

Use `--resume-from OLD_ATTEMPT` with the original work-plan invocation and a new
output directory to recover saved source results or native finalization. Keep the
manifest, source, provider/controller configuration and allowance options unchanged.
Before handoff, a bound `source-recovery.json` is required: completed case and
factual results survive, and saved final drafts go through the ordinary proof
checks without another model call, including when the allowance is exhausted.
Unstarted cases or an unstarted owner can use the original remaining allowance;
unstarted optional factual work in an interrupted case is skipped in favor of its
owner. Interrupted research conversations stay incomplete with their collected
facts; they are not automatically replayed or resumed. Unknown dispatches fence
new calls. Recovery retains the original receipts, assertion versions, conversation
identities and budget ledger; it does not add checks or reset time, usage or holds.
Keep the original attempt available: recovered attempts can reference its allowance.
Continue from the latest recovery attempt; an older parent cannot be forked again.
Pre-handoff recovery also requires the original native work to remain current.

For a later audit, use the ordinary native-phase `--first-pass OLD_ATTEMPT`,
`--second-pass fast|full` and `--supersede` workflow with current native work.
Do not pass `--work-plan` to that native invocation. A bound work-plan parent
automatically supplies its original budget; counters and limits are not reset.
Use the summary's effective owner reviewer/provider configuration, without the
source-only `--question-routing` flag.
The audit reports historical first-pass case coverage separately from its native
claim results. Partial coverage targets can supply an admitted native subset,
but every selected audit ID must exist in the validated first report.

## Prepare the work plan

Start with the ordinary zero-AI planning checkpoint. Copy the original source
plan ID, source fingerprint and source assignment IDs. Combine native lead
summaries with bounded source orientation to identify consequential operations,
including operations without native candidates. Planning is part of the review;
record host work separately when it is outside the managed provider ledger.

Group candidate instances around an actual suspected failure or control check.
Preserve caller/configuration differences and different repair points. A hundred
generic SQL operations are not a hundred equally funded investigations. Native
facts support reasoning; ordinary markers guide selection without becoming safe
verdicts. Supplied exact-ID triage still requires the selected dispositions.

One item names an actor, protected effect, conditions, supported priority basis,
next deciding fact and one or a few required checks. Priority impact is a host
scheduling hypothesis, not the finding's severity. Leave genuinely unknown
importance unknown. Do not assign high impact solely from an API name or CWE.
The controller validates source bindings and membership, not the truth of the
host's impact judgment.

```json
{
  "schema_version": "mehscanWorkPlan/v1",
  "source_plan_id": "SOURCE_PLAN_ID",
  "source_fingerprint": "SOURCE_FINGERPRINT",
  "coverage_limits": ["Runtime plugin bindings are not established."],
  "items": [{
    "id": "login-auth",
    "assignment_id": "SOURCE_ASSIGNMENT_ID",
    "owner_path": "routes/login.ts",
    "start_line": 20,
    "end_line": 80,
    "question": "Can the email operand alter the authentication query?",
    "protected_effect": "Issue an account session",
    "area": "authentication",
    "actor": "Unauthenticated caller",
    "conditions": "The registered login route and its supported authentication branches.",
    "reason": "The inspected body inserts the email into query grammar.",
    "next_deciding_fact": "Whether the actual execution and session consumer preserve the boundary.",
    "signal": {
      "kind": "source_relationship",
      "evidence": [{"path": "routes/login.ts", "start_line": 30, "end_line": 35}]
    },
    "priority": {
      "impact": "high",
      "exposure": "unauthenticated",
      "evidence": "strong",
      "basis": "The posted email reaches SQL grammar before account selection."
    },
    "checks": [
      {"id": "query-binding", "question": "Is the email kept outside executable query grammar?"},
      {"id": "session-effect", "question": "Does a changed query result reach session issuance under supported conditions?"}
    ],
    "review_roles": {"verify": ["NATIVE_REVIEW_ID"], "cover": [], "context": []},
    "estimate": {"calls": [1, 4], "input_tokens": [10000, 150000], "output_tokens": [500, 4000]}
  }]
}
```

Replace all binding placeholders with current native values and use actual source
ranges and evidence. Each native ID belongs to one item/role in its original
assignment. Verify IDs receive their own assessments; Cover/Context do not inherit
a negative verdict. AI-only items use empty role arrays and the same source-backed
question/check contract. Multiple independent items may share a physical source
assignment without sharing sessions, verdicts or job files.

Potential impact is `critical`, `high`, `unknown`, `medium` or `low`. Exposure is
`unauthenticated`, `authenticated`, `unknown`, `privileged` or `deployment`.
Evidence strength is `strong`, `moderate`, `weak` or `unknown`. Unknown importance
is reported separately. Equal-priority work uses the estimated call upper bound,
then plan order; missing effort estimates do not assert cheapness.

Optional `readiness` is `ready` (default), `blocked` or `deferred`; the latter two
require `blocked_reason`. They remain visible and make a required target incomplete.
Optional effort ranges are rough host estimates, not enforced limits. Missing
estimates remain unknown. `shared_facts` can cite up to sixteen existing source
ranges as initial evidence, using the same path/start/end form as domain review;
these are facts, never prior verdicts. The plan permits up to 2,000 grouped items
and four MiB of metadata. Source bodies are delivered only for started work.
Source-backed signal excerpts outside an item's primary packet are registered
as cited initial evidence when it starts, so they do not require a duplicate lookup.

## Question delegation

Use this optional layer when specific factual questions can reduce the owner's
research. Bind the routine and expert provider descriptors through the existing
native `--review-orchestration` plan contract, then add `--question-routing` and
`--expert-command FILE` to the work-goal worker invocation. Luna medium is suitable
for the routine question role; keep the user's chosen capable review model as
expert owner. Use stable schemas and separate trusted provider configurations/private directories.
Without this flag, the ordinary configured-model workflow remains unchanged.
Prepare the work plan from the ordinary zero-AI checkpoint before binding the
two profiles, or use read-only `investigate source-review-plan` for the same
inventory and selected IDs. Refresh the native work package after admitting the
bound two-profile plan; never hand-edit its runtime.

Checks default to `security_decision` and go to the owner. Only explicitly scoped
`source_fact` checks are delegated.
Select `task_kind: extraction` or `task_kind: bounded_proposition` and provide
`usefulness`: the specific owner decision this factual answer prepares. Security
judgment uses `task_kind: security_decision`. Missing kind/usefulness keeps the
check with the owner, including older plans. These labels express the planner's
selection; the controller enforces the fields and source readiness, not semantic
difficulty. No extra classifier call or delegation quota is required.
Each delegated check also declares `source_ranges` and/or `source_definitions`.
`source_ranges` contains one to eight original-source
ranges with `path`, `start_line` and `end_line`, each spanning at most 400 lines.
Use actual deciding ranges from the bound source plan, including a helper or type
when needed. `source_definitions` contains one to four objects with `path` and
`name`: the exact declaration file and reported symbol name. The controller uses
the existing definition collector to read one unique declaration, up to 120 lines.
Multiple declarations, parser gaps, missing files and clipped bodies keep the
question unprepared; a symbol location alone is insufficient. A unique declaration
does not establish effective dispatch, authorization or caller applicability.

Preparation begins only for admitted work with remaining question capacity.
Definition lookups consume two research units and their observed response bytes
from the shared case/run allowance, including bounded units for reused lookups.
The run-local broker shares identical lookups; source hashes are checked again
before delivery. Original lookup results remain under `source-review/preparation/`,
linked from each question's preparation record. Only explicitly named source is
collected, including supporting/queryable-only implementations when needed.

Prepared source is delivered as cited evidence. The controller records preparation
readiness and skips the question worker
if no source prerequisites are declared or a prerequisite is unavailable. Existing plans without these
fields retain their checks with the owner; a factual-only item remains incomplete
when its preparation cannot start. Readiness checks declared source availability,
not whether the planner identified every premise or the interpretation is correct.
Use a named definition when the body is absent from the plan but its declaration
file is known. Other missing bindings remain with the owner for normal targeted
research. This is bounded preparation, without an autonomous navigation pass.
Useful prepared source is also given to the owner when another prerequisite
remains unresolved; a failed preparation does not establish a negative verdict.

When using delegation, the agent preparing the work plan selects questions
automatically during its existing source orientation; the user need not author
them. Keep this in the same planning step, using the configured profiles rather
than buying a separate model call to classify each check. For each selected
control or suspected failure:

- Reuse deciding facts already available in cited source or native/compiler
  context. Do not create a paid question just to repeat them.
- Choose a remaining factual proposition only if its answer changes the owner's
  next decision. Name its actual producer, consumer or registration edge, bounded
  scope and deciding evidence. Prefer one useful preparation question per item;
  combine repeated caller questions when they share the deciding implementation,
  preserving different caller conditions and repair points.
- Keep authorization policy, conflicting effective bindings, deployment assumptions,
  dependency guarantees, actor/victim impact and dismissal decisions with the
  owner. Split a factual prerequisite from that decision only when it saves
  research; retain the security check rather than replacing it with the fact.
- If a useful proposition cannot be bounded from the available orientation,
  leave the check with the owner. Native/AI origin, file count, API category and
  confidence alone do not select the route. No quota requires a Luna question.

For example, a source question about the registered middleware and identity
assignment can prepare an owner decision about unauthorized record access. The
factual answer alone cannot close that security decision. Conversely, if the
effective assignment is already shown, give it directly to the owner and omit
the extra question. Apply the same selection to AI-only items and native leads;
Verify IDs keep their owner assessments regardless of preparation.

The controller enforces explicit routes, bounded fields and evidence admission;
it does not certify that the planner's question is easy or semantically correct.
Inspect the declared fact/owner split before dispatch, and report actual question
calls separately from planned checks. For example:

```json
{
  "id": "subject_binding",
  "route": "source_fact",
  "task_kind": "bounded_proposition",
  "usefulness": "Prepares the owner decision about which identity the resource selector trusts.",
  "question": "Before this handler executes, is UserId overwritten from token-backed identity?",
  "scope": "The declared route, its middleware order and this handler's selector.",
  "acceptance": "Cite the registered middleware, the identity-to-field assignment and the selector consuming that field.",
  "source_ranges": [
    {"path": "middleware/identity.ts", "start_line": 10, "end_line": 35},
    {"path": "routes/account.ts", "start_line": 20, "end_line": 55}
  ]
}
```

The paths/ranges above illustrate the shape; replace them with the actual
registration, producer and consumer evidence in the current plan.
For a known declaration file, a check can additionally or alternatively specify
`"source_definitions": [{"path": "middleware/identity.ts", "name": "attachIdentity"}]`.
Select the reported declaration name; do not invent a qualified name or assume
that an import, method name or directory proves the runtime binding.

Keep one proposition per delegated check. Suitable work includes locating an
implementation, extracting an input or guard, and binding a specific producer
to a consumer. The worker receives the named owner range, cited signals and
supporting native/compiler facts; other source remains queryable. It has one
focused lookup batch and a final answer, within the shared allowances. If that
cannot settle the proposition, retain its concrete missing fact. Do not assign
open-ended caller searches, deployment decisions, dependency-security guarantees,
attacker-to-victim reasoning, severity or broad negative verdicts as source facts.
A rule name or API category cannot establish an appropriate delegation.

Question workers return cited `work_checks`, never native verdicts, proposals,
severity or audited coverage. `satisfied` means the explicit proposition is
supported; `violated` means contradicted. Unresolved answers do not close a
coverage target. Purely factual items without Verify IDs can finish with the
question worker alone; closed then means facts answered, not security clearance.
Items with security decisions or Verify IDs retain an expert owner. The owner
receives attributed answers and their validated original source, checks the
remaining security inference, and avoids re-searching evidence already supplied.
No model answer becomes an established security fact merely by being cited.

The controller owns routing, budgets, state and byte-proof validation. Before
starting each security case, it protects an owner completion allowance in ranked
queue order. It uses the optional `estimate.owner_calls` upper bound, or two calls when
unknown, bounded by the existing per-case research limit and available headroom.
A one-call budget can still admit one owner turn. Optional question work and new
cases cannot consume active owners' protected calls or their estimated input/cost
headroom. The owner consumes its reservation as it runs; unused headroom returns
to the queue. Reservations are not provider calls or spending. They do not
guarantee completion or extend deadlines, usage fences or authorized scope.
Owner turns beyond the protected allowance can use remaining shared capacity.
Specify `owner_calls` as an ordered integer range like other effort estimates
when useful. It is part of the total `calls` estimate and is not added to it;
preparation and owner effort should not be counted twice.

Question-mode admission uses the smaller of the configured managed-call ceiling
and the bound orchestration run ceiling, preserving both existing limits.
Per-case limits still apply. Preparation keeps its existing bounded time share.
Only `--workers` controls this mode's total case concurrency. Native bundle
audits, quality/revalidation, `--expert-review-ids`, `--expert-workers` overrides
and native source-collector settings remain separate; they are not silently
applied to question mode. Native/AI origin roles and SQL/compiler facts retain
their existing meaning. Generic markers do not become extra paid questions.

With cost accounting, supply a USD `models` map keyed by both exact bound model
names instead of the single-model `model`/`rates` pair. Each model entry contains
`input_per_million`, `cached_input_per_million` and `output_per_million`.
Reservations conservatively use the highest configured rates; observed receipts
use their actual model's rates. Without an explicit monetary cap these remain
informational. An unknown paid turn is retained and fences further calls rather
than being replayed. See `source-review/question-budget.json`, the job receipts
and the work ledger for spend and unanswered work.
The ledger's routing summary separates declared fact/owner checks, question-worker
calls, owner calls and provisional answers. Item `question_work` records link to
the exact provider, conversation and result directory. Provisional answers and
accepted item closure are different counts.
Requested questions skipped during execution have `status: skipped`, zero calls,
a reason and no conversation/result directory. The routing summary counts these
as `skipped_question_checks`; they do not imply that the owner left the check
unanswered. Unstarted items remain visible in the ordinary work ledger.

Missing implementations first need source collection, not automatic expert
escalation. Group repeated caller questions by control and repair point, retaining
their conditions. A useful later layer may add new work items for consequential
remaining gaps; this flag does not launch a general orchestrator or extra pass.

## Optional factual audits

`--fact-audit-policy FILE` adds a bounded check of selected factual answers during
question routing, after the factual worker and before its security owner. It is
off by default and separate from Fast/Full claim review. Use it for a named
suspected error, a consequential task pattern, or a reproducible sample. Selection
uses the declared task pattern and potential consequence, not model confidence.

```json
{
  "schema_version": "mehscanFactAuditPolicy/v1",
  "max_audits": 8,
  "seed": "review-facts-v1",
  "sample_percent": 0,
  "checks": [
    {"case_id": "login-binding", "check_id": "input-use", "reason": "Check the omitted early-return branch."}
  ]
}
```

Optional `impacts` selects declared potential-impact classes; `patterns` selects
explicit check `routing_pattern` strings. Patterns describe a repeated reasoning
task, such as `guard-return`, rather than a whole application domain. The controller
does not invent patterns or add new checks. Explicit checks rank before pattern
matches, then consequence/sample selection, retaining case priority within those
groups. The plan records candidates beyond `max_audits` separately. A selected
check without a completed factual assertion buys no audit call.

The auditor uses the bound expert profile and original cited source, with at most
one focused lookup batch. It checks the earlier answer's actual scope and
conditions. A source-backed challenge disputes that assertion version and reopens
only recorded consumers. Unresolved source or mere uncertainty does not establish
an error. Support does not certify correctness, security safety or unselected
answers. The owner receives the audit note and deciding source and must still
review applicability and impact. Earlier answers and native history are retained;
a corrected assertion requires an explicit new source-backed answer, and reopened
security checks still require owner resolution.

With `suspend_patterns: true`, a challenge stops unsent factual delegation for that
exact named pattern during this run, retaining those checks with their owners.
Factual-only items without an owner remain incomplete when their pattern is suspended.
Already dispatched work can finish; unrelated patterns and domains stay eligible.
No fixed sampling percentage is recommended by default.

Audit calls, tokens and configured-rate cost use the original case/run allowance,
including owner completion protection. Audit work can be deferred when that
allowance is unavailable; non-selection or deferral never closes a security check.
The ledger separates factual audit calls/outcomes from factual-worker and owner
calls, retains original receipts and audit provenance, and links the bounded
selection under `source-review/factual-audit-plan.json`. Recovery reuses completed
or saved audit work without replaying inference; unstarted optional audits in an
interrupted case are skipped. Keep the original policy unchanged during recovery.

## Evidence and completion

Comprehensive keeps failed native obligations selected. Successful siblings may
be finalized and exported while unanswered IDs remain unreviewed and execution
remains incomplete. A partial export does not create a verdict for missing work
or authorize replacement inference. Present native responses still require
normal validation.

The reviewer returns `draft.work_checks` with exactly one answer per controller
check ID. Each answer contains `check_id`, `status`, `summary`, `evidence` and
`next_deciding_fact`. Use ordinary controller citation handles; paths and original
source bytes are validated before the result is admitted.

* `satisfied` or `violated` requires deciding evidence and a null remaining fact.
* `unresolved` or `not_checked` requires the concrete next deciding fact.

A native `needs_review` assessment also leaves its work item unresolved, even if
other property answers are closed. A complete packet, supplied source window or
incorporated marker does not prove completion of the declared checks. Cited
conclusions remain AI judgments; source validation does not establish correctness.

New source proposals are reported alongside the fixed target without automatically
enlarging it. Completed findings survive budget stops. Unstarted work, failed
answers and unknown usage are never marked safe or silently replayed.

## Read the ledger

The controller writes these artifacts under `source-review/` before dispatch and
updates them as work starts and completes:

| Artifact | Meaning |
| --- | --- |
| `work-plan.json` | Normalized source-bound backlog and fixed target membership |
| `case-state.sqlite` | Transactional case state, assertion revisions, source bindings and explicit check dependencies |
| `work-handoff.json` | Bound source results, case state, owner work package and original allowance policy |
| `source-recovery.json`, `jobs/*/recovery.json` | Bound pre-handoff recovery, saved answers/facts and original usage floors; no replay permission |
| `work-ledger.json` | Required checks, cited answers, blockers, potential impact, observed usage and remaining estimates |
| `remaining-work.md` | Human-readable residual work and cost/coverage limits |
| `lead-accounting.json` | Native IDs mapped to roles, including unclassified IDs |

Each item records `routing` with the policy version, requested/effective route,
task kind, reason and selected provider, plus `completion_reservation` with
requested/granted, consumed and released slots. These describe dispatch and
capacity, not semantic correctness. Routing summaries distinguish declared fact
checks from actual worker calls and owner fallback. A fact worker that returns
incomplete work remains an attempted factual route; it does not become a closure.

The case store saves source-validated question answers before the owner runs.
Their original result artifacts and provider attribution survive an owner failure.
Ledger JSON and Markdown are projections of this state; native decision history
and the execution budget remain under their existing authorities.

When attributed factual assertions are offered, the owner returns
`assertion_dependencies` on every required check: exact `assertion_id` and
`version` pairs for interpretations used, or an empty array for an independent
source proof or rejected suggestion. Inspect the deciding original evidence and
caller conditions. These declarations track recorded reliance; they cannot prove
that an interpretation is correct or expose every influence on a model's answer.

A controller dispute or replacement retains assertion history and reopens only
checks that recorded reliance on it. Reopened checks lose completed-coverage
status and name the reason for reconsideration. Independent checks retain their
results. Previously admitted native verdicts remain historical until explicitly
superseded through normal admission. An unresolved replacement cannot clear a
dependent security conclusion. Models do not directly edit the store.

The store rejects altered result artifacts, stale assertion versions and changed
deciding source. The handoff rejects changed artifacts, larger allowances, rate
changes and reset usage/fences before inference. Older work-plan attempts without
a bound handoff do not silently receive a fresh follow-up allowance.

An immediate Fast/Full correction or reopening of a required Verify claim marks
the affected case for native proof reconciliation. Additional proposal audits
do not enlarge a fixed target. Original property answers and factual assertions remain
historical; a changed native proof cannot silently keep the case target complete.
A later native audit leaves the original attempt unchanged and writes
`work-followup.json` with the parent and shared allowance. Neither route
automatically schedules another source investigation.

The ledger separates unresolved planned high-impact work, lower-priority work,
out-of-target work and unclassified material with unknown importance. It also
lists source windows with no named owner; no native candidates does not imply
that all source was mapped. Owner ranges are not a line-coverage metric, and
queried helpers do not acquire reviewed status.

For a coverage goal, `target_complete` is true only when all required checks and
verification assessments have closed conclusions. The CLI returns incomplete for
an unfinished target even if native finding import succeeded. Keep native subject
completion distinct from work-goal completion. Reports retain out-of-target risks
even when the selected target is complete.

## Configured-rate allowance

Keep the rate file outside the reviewed source root. For ordinary single-profile
work, its model must exactly match the admitted provider contract; no prices are
assumed automatically. Question delegation uses the per-model map described
above instead:

```json
{
  "model": "CONFIGURED_PROVIDER_MODEL",
  "currency": "USD",
  "rates": {
    "input_per_million": 1,
    "cached_input_per_million": 0.1,
    "output_per_million": 5
  }
}
```

The numbers illustrate the file shape, not current provider prices. Choose rates
appropriate to the model/context band. When a monetary allowance is requested,
admissions reserve estimated cost for a
250k input turn at the higher input rate plus 16k output tokens per in-flight call,
then settle observed input/cache/output counters. Missing cost counters or an
observed overrun fence new work while active calls drain. The 100k token reservation
is separate from this cost estimate. Preparation counts against this path's
admission clock; local finalization can extend elapsed time.

This is an estimated managed-work allowance. A call can exceed its reservation;
actual invoice charges, unreported cache-write categories and host-agent work are
not guaranteed by these counters. Remaining cost ranges use supplied effort
estimates and configured input/output rates; missing estimates remain visible.
Do not claim that a USD allowance establishes security coverage or a hard bill cap.
With `--cost-rates` alone, monetary counters are informational: missing cost
counters remain unknown and do not stop otherwise admissible work. Existing
input/call/time and unknown-input protections still apply.


### Completion kinds and source regions

New plans should set each item's `case_kind` to `security` or `factual`.
Security items require an explicit security-decision check. Factual items require
eligible source-fact checks and cannot own Verify IDs. Older plans retain their
inferred behavior, recorded as `case_kind_basis: legacy_inference` in the normalized
plan. The ledger reports settled security and factual items separately; factual
completion establishes no security conclusion. A factual target can settle only
its declared factual obligations.

Execution finished means dispatch has stopped. Target settled means every
required conclusion has closed. Investigated but missing a deciding fact remains
unresolved. Completed factual siblings remain visible in `partial_fact_checks`
when the parent fails; they do not close the parent security case.

Source regions without named checks are calculated by subtracting declared owner
intervals from original windows. Neither ownership nor source delivery establishes
line-level review coverage.

Ordinary owners challenge consequential supplied interpretations during their
existing investigation. Keep separate factual audits optional for suspected
recurring errors, consequential reuse or reproducible quality samples. An audit
challenge is provisional disagreement, not an owner-confirmed error count.
