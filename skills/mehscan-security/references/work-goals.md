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

This path supports fresh Value or Comprehensive native plans. It cannot combine
with source/domain selection, source-result reuse, resume, grouping, native-only
profiles, first-pass handoff, a second pass or native-share overrides. Work items
use isolated provider sessions and a single ranked queue. The controller does not
automatically resume interrupted work or import prior work-ledger conclusions.
Existing source/native reuse routes remain available separately.

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

## Evidence and completion

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
| `work-ledger.json` | Required checks, cited answers, blockers, potential impact, observed usage and remaining estimates |
| `remaining-work.md` | Human-readable residual work and cost/coverage limits |
| `lead-accounting.json` | Native IDs mapped to roles, including unclassified IDs |

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

Keep the rate file outside the reviewed source root. Its model must exactly match
the admitted provider contract; no prices are assumed automatically:

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
