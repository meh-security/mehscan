# Local AI review worker

The release package includes `scripts/review_worker.py`, a provider-neutral local
controller. It uses the same inventory, bundle finalizer, report importer and
[state journal](review-state.md) as manual review. It does not publish to GitHub.
The advisory Action defaults to native preparation. Its optional Value/Comprehensive
mode prepares an active private [review handoff](github-action.md#active-review-handoff-local-integration-preview).
Supplying `provider-config` explicitly enables the bundled reviewer; without it,
a trusted local consumer can execute the handoff.

## Ordinary review profile

The default worker phase (`all`) reviews the requested production-source scope.
It supplies bounded original-source assignments alongside relevant native questions,
including files with no scanner candidates. The reviewer can assess known questions
and propose additional consequential relationships in the same conversation.
The controller validates original paths, hashes, ranges and inspected citations,
assigns identities and applies the ordinary finalizer. Source validation establishes
the cited bytes, not a vulnerability or a native flow proof.

With zero selected scanner candidates, this same default phase runs an AI-only
source first pass over the requested scope. AI-discovered claims receive normal
source-bound IDs and can enter automatic Fast or Full follow-up. The options
report records `ai_source_only` origin and source-coverage context; scoped threat
review can use those flows/gaps even when no AI claims are retained. No fake
candidate is needed. An empty Fast queue makes no model call. Explicit native-only
or candidate-scan requests retain their narrower scope.

New questions and source assessments are retained under `source-review/`. The
controller derives a new native state generation for the augmented inventory;
its private claim stays in the state store. Completed assessments are finalized
without another first-pass model call. Optional Fast/Full passes can reuse the
original source facts, keeping their attribution. Existing native local facts
settle only their own relationship; they do not clear unrelated authority or
workflow questions.

Seed/performance tooling and declaration-only C# interfaces/enums are omitted
from standalone source assignments by default, including their native questions.
They remain available for targeted cross-file queries. `excluded_sources` records
paths, reasons and affected native IDs separately from examined coverage. Add
`--include-supporting-source` to explicitly review these files as assignments.
Files with executable interface bodies or other implementation remain eligible.

Schema-only database migrations, generated migration snapshots/designers and SQL
files are queryable only. Custom SQL/resource calls and executable or uncertain
migration bodies remain eligible; SQL definitions are read with the relevant
callers rather than queued separately. The supporting-source opt-in above applies
to seed/performance code and declaration-only C# contracts.

The controller's `excluded_sources` registry contains only paths, reasons, affected
native IDs, file hashes and line counts. It contains no file bodies and is not
preloaded into reviewer packets. A scope check prevents these paths from becoming
assignment windows. A reviewer can explicitly request a source range, definition
or scoped search to settle a concrete question; only returned lookup evidence
enters its context and counts against its research budget. Source reads are bounded
to 400 lines and 64 KiB per range. Queryable-only source is not examined coverage.

`source-review.json` records examined, context-limited and deferred ranges, failed
assignments and source-stage call counts. Canonical report scope includes a coverage
summary. Empty results do not certify a file safe. A failed assignment remains
incomplete while successful siblings are retained; it does not trigger a replacement
native model call. Source-stage usage contributes to total input, cache and output
accounting. A source-stage interruption before handoff is retained for diagnosis;
automatic continuation of those interrupted source conversations is not yet supported.

The bundled reviewer reports coverage using controller-owned `window_ref` identities
from `research.coverage_windows`. The adapter supplies their original paths and
ranges before native admission. Lookup ranges belong in evidence; they cannot be
added as assignment coverage. Coverage handles must be complete and unique.

Source citations use `source_ref` and `line` from `research.citation_windows`.
An original line number selects that single line; null selects the complete
delivered evidence extent. Proposal anchors require a specific line in an assigned
`s` reference. Fetched `f` references supply evidence only. The adapter expands
these into native paths/ranges; separate snippets stay separate, even across a
blank unread line. Legacy tasks without this catalog retain path/range citations.
The reviewer prefers deciding lines from source already inspected and keeps full
extents when a claim needs their context, such as checking a complete body for a
missing guard. It avoids additional lookups solely to shorten quotations.

Use `--phase native` for an explicitly bounded, exact-ID review without discovery,
or `--phase change-pass` for only the existing Changed comparison. Experimental
tiered orchestration currently requires `--phase native`. SDK-assisted Razor/Blazor
generation remains optional; ordinary AI source review needs no source generator.

For an opt-in Python ORM operation pilot, add `--group-operations` with
`--phase native`. Two to six selected IDs in the same exact native callable
share its complete bounded source; the bundled adapter references duplicate
excerpts instead of repeating them in the prompt. Each ID still requires its
own result. Split jobs, ambiguous ranges and oversized callables keep ordinary
review. Groups do not establish authorization, equivalent effects or complete
caller coverage. The option is bound into recovery and cannot change on resume.
This groups context within existing bundles; it does not defer candidates or
guarantee fewer model calls or lower cost.

Use `--policy value --selection policy` for ordinary AI review. Comprehensive
selects every admitted ID. Both use five research rounds (six total model calls),
24 query units, 512 KiB and 900 seconds per investigation, with native-bound
overrides available. Finish settled relationships early; deferrals remain unreviewed.

The [bundled adapter](codex-reviewer.md) defaults to stable schema and addressed
source. Execution traces, source validation and usage/cache accounting are part
of ordinary review. Detailed boundary tables require `"boundary_checks": true`;
they are diagnostic observations, not an independent second reviewer. Automatic
selective follow-up, broad workspace routing and dependency preloading remain
experimental. Manual skill use runs in the host agent and does not require this adapter.

See [Prepare review work](#prepare-review-work) for the ordinary setup.
[Source preparation](#optional-source-preparation) is an optional experiment.

Use one configured capable model with direct source lookups and native
finalization. Start with `--workers 4 --query-workers 2` and small source-bound
jobs. Group claims only when they share the actual operation and implementation;
a shared file or CWE alone is insufficient. The profile allowances are ceilings:
finish settled relationships early and keep an essential unresolved fact pending.

## Optional second pass

Add `--second-pass fast` or `--second-pass full` to the normal worker command.
The default is `off`, independently of Value or Comprehensive. These are Python
worker options, not flags on `mehscan scan` or `mehscan report`.

| Mode | Work performed | Possible result |
| --- | --- | --- |
| `off` | Ordinary first-pass review. | No additional reviewer calls. |
| `fast` | Automatically selects a capped queue from first-pass proof questions, then audits and resolves actionable objections with targeted lookups. | Keep or correct selected claims; other first-pass results remain unchanged. |
| `full` | Reviews every claim in the chosen scope through a fresh source-backed assessment without the original verdict, followed by a final-only comparison. | Keep or correct a result; unresolved disagreements stay pending. |

Fast first records an audit checkpoint using the first investigation's evidence
and trace. Supported proofs can finish in that call. Concrete objections move
to targeted recovery in the same conversation, where an incorrect objection can
also be rejected. These phases share the normal Fast allowance, separately from
the first investigation. A proposed closed repair receives a
counter-check in the same conversation within its original allowance; a repair
that cannot be checked before the allowance is exhausted stays pending. Unchanged
results need no extra confirmation call. Full adds an independent investigation for
deeper audits, evaluation and training-data review. Both preserve the first results
and use source validation; neither establishes semantic ground truth.

Fast reserves a call within its existing allowance to validate a proposed repair.
If validation cannot finish, the report separates that deferred check from source
questions already answered. Relevant source results from sibling investigations
in the same first attempt may be reused with their original attribution; their
verdicts and caller conditions are not shared as facts.

Fast is useful for checking an existing proof. Full is useful when the selected
claim needs another investigation. Both add model cost and can make mistakes;
agreement and source-valid citations do not establish correctness. They use an
ordinary single-profile plan and can use the same configured model for both
passes. Experimental tiered/multi-model orchestration is separate.

Fast records its original per-claim audit under `audit` in `second-pass.json`,
including whether recovery was requested. These are model hypotheses, distinct
from the final outcome. Checkpoints and execution traces retain the current phase,
objections and remaining allowance for recovery after interruption. Budget-limited
results keep the deciding question alongside the reason work stopped.

### Choose which results to check

During existing first-pass calls, the bundled adapter offers nullable `followup`
metadata: a typed reason and one exact deciding question. The controller keeps
it outside native verdict/evidence schemas. The same calls offer nullable
`claim_context`: a cited repair point/property, applicability and binding basis,
claim kind, impact basis and conditions. Its root must also be in the ordinary
validated evidence. Metadata is retained in bound job checkpoints and never
enters native verdict schemas. Source proposals receive the same metadata
after their keys map to admitted IDs.
An invalid advisory annotation is omitted and recorded in job checkpoints and
the grouped report; it does not discard otherwise source-valid review work.

Fast prioritizes positive proof signals from explicit activation/impact conflicts
or severe conditional local/optional claims, then concrete conflicting-evidence,
control-applicability and missing-local-evidence nominations, then assessed
severity. These are targeted audit questions, not inferred false-positive labels.
It selects one representative per explicit repair point before repeated claims;
unselected siblings remain unaudited. Pending status or low confidence alone is insufficient. External/human
blockers are excluded. These are scheduling hypotheses, not detected proof errors.

Fast selects at most 25% of eligible claims, rounded up, with a maximum of 20.
Lower the maximum with `--fast-max-claims N` (1–20). It makes no selection-model
call, never expands an empty queue to all claims and records cap/shared-root deferrals.
Full applies no automatic cap. Older/custom reviewers without nomination or claim-context metadata
remain supported; they produce no automatic Fast targets.

`--second-pass-scope` selects decisions from the first pass, within the chosen
work package. This defines Fast's eligible pool; automatic selection then narrows
it. Full checks all members of the pool:

| Scope | First-pass decision |
| --- | --- |
| `all` (default) | All verdict classes are eligible, including dismissals and unresolved items. |
| `issues` | Reported findings (`issue`). |
| `dismissals` | Dismissed candidates (`not_issue`). |
| `pending` | Unresolved claims (`needs_review`). |

Combine scopes with commas, for example `--second-pass-scope issues,pending`.
`tp`/`fp` aliases mean first-pass issue/dismissal, not established ground truth.
Filtering happens before new bundles and reviewer packets are formed, reducing
calls and context. Unselected claims retain their first result and are marked
not checked / outside scope; they are not counted as second-pass confirmations.
The summary separates all first-pass claims, targeted claims and checked claims.
An empty target scope makes no second-pass model call. Completion applies to the
requested scope, not every candidate in the application.

For a first review followed immediately by automatic Fast selection among findings, add these
options to the [normal worker invocation](#run-the-worker):

```text
--second-pass fast --second-pass-scope issues
```

After first pass, `review-options.json` and `review-options.md` show label counts,
the proposed Fast queue with reasons, deferrals and the broader Full scope.
`finding-groups.md/json` presents proposed families by explicit shared repair
locator/property and verdict, with every claim's conditions retained. Missing
context stays singleton; grouping changes no native verdict and certifies no
unique vulnerability count. First-pass metadata remains explicitly historical
after a later proof repair. Scoped threat suggestions contain at most three
named leads, preserve the total/deferred leads and use the remaining authorized
budget; they do not start another model phase automatically.
Selection itself costs no model call. With the default `--second-pass off`, the
worker finishes first pass and exits; the calling agent presents results and asks
which follow-up scope to run. Explicit Fast/Full requests execute directly. An
explicit threat-model request is handled by the skill's scoped source-review
workflow; it is not a new CLI second-pass mode. Follow-ups inherit the requested
scope/budget; they do not create authorization for another full scan.

### Recheck a completed attempt

Reuse the completed first pass instead of paying for it again. Keep its source,
inventory, runtime, provider binding and original attempt directory unchanged.
The generation must still be owned and active. Refresh `state work` and save its
JSON output as `RUN/work-second-pass.json`:

```text
mehscan state work --store STATE --stream pr:24 --inventory RUN/inventory --source-root ROOT --generation GENERATION --owner OWNER --skill-root TRUSTED/mehscan-security
```

Then check pending claims with Full in a new output directory:

```text
python scripts/review_worker.py --scanner TRUSTED/mehscan --source-root ROOT --inventory RUN/inventory --store STATE --stream pr:24 --claim PRIVATE/claim.json --work-package RUN/work-second-pass.json --reviewer-command TRUSTED/reviewer-command.json --reviewer-label configured-reviewer --skill-root TRUSTED/mehscan-security --run RUN/bundles --output RUN/second-pass-1 --phase native --first-pass RUN/attempt-1 --second-pass full --second-pass-scope pending --supersede
```

Use the generation and owner from the current claim receipt. Keep any configured
`--provider-contract FILE` on the state and worker commands. The bundles must match
the chosen work IDs; the worker creates narrower second-pass bundles itself.
`--supersede` links the new admitted results to their exact prior decisions,
preserving history. To produce source-validated reports without admission, replace
`--supersede` with `--validate-only` and keep `--phase native`.

### Read the results

| Artifact | Contents |
| --- | --- |
| `findings.json` | Canonical native final findings and decisions. |
| `second-pass.md` | Human-readable first/final comparison and outcome counts. |
| `second-pass.json` | Per-claim objections, scope, stage receipts and first/second/combined usage. |
| `first-pass/` | Original responses retained before second-pass changes. |
| `training-labels.json` | Verdict, proof assessment, investigation status and label provenance. |
| `training-turns/` | Actual input/fact/response snapshots linked to native context. |

Outcomes are `confirmed`, `corrected`, `reopened`, `unresolved` or `not_checked`.
Confirmed means this check supported the first proof; it is not a correctness
certificate. A second-pass execution failure keeps the original result marked
not checked while other bundles continue, and the second-pass summary is partial.
Outside-scope items are also not checked, with an explicit `outside_scope` reason.

Training labels remain candidates or excluded and are never automatically
approved. Checked labels identify `model_reviewed` authority; unchecked labels
remain `first_pass_only`. Review candidates separately before training, and
loss-mask source/controller tokens. A corrected trajectory does not rewrite the
first one. See the [output contract](output-contract.md#second-pass-review-artifacts)
for the distinction between final decisions and supplemental review labels.

Optional `--second-pass-rates RATES.json` prices recorded calls using your explicit
rate basis. Without rates, costs are unknown rather than assumed free. Format:

```json
{"models":{"your-model":{"input_per_million":1,"cached_input_per_million":0.1,"output_per_million":5}}}
```

Rates are per model and currency unit; these example numbers are not vendor prices.
An optional `long_context` object supports `threshold_tokens`, `input_multiplier`
and `output_multiplier`. Unmatched models or unknown token counters leave cost
unavailable. Provider elapsed totals are sums of calls, not parallel wall time;
the second-pass summary records its own wall time separately. See
[usage and cache accounting](#usage-and-cache-accounting) for receipt handling.

## Prepare review work

Keep source, trusted tools and review artifacts in separate directories. Create
a pinned Changed inventory with a stable repository namespace, claim a generation
and save its receipt privately. Create a completion template:

```text
mehscan state plan-template --inventory RUN/inventory --source-root ROOT --policy value --selection policy --skill-root TRUSTED/mehscan-security
```

The AI worker requires this native runtime-bound plan. The native contract records
the exact executable, trusted skill-package digest, worker protocol and effective
profile limits. Keep the skill outside ROOT. Manual CLI plans without a runtime
remain supported, but the worker rejects them before model execution.

Save the JSON as `RUN/plan.json`. Comprehensive selects every eligible native ID
and retains native conservative exclusions in `excluded_review_ids`. Value allows
selection, but every other native ID must have an explicit reason in
`deferred_review_ids`. Exclusions and deferrals are not dismissals; see
[completion accounting](review-state.md#account-for-planned-review-and-pending-evidence).
Every changed path starts `unassessed`; an empty native queue still needs a change
pass. Admit the plan and export the work package:

For initial Value priority selection, use `--policy value --selection policy`
on the template. Existing native hints become explicit unreviewed deferrals;
they do not become safe decisions. Omitting `--selection` preserves the all-ID
template default for Value manual/full-coverage audits. Comprehensive still
applies native conservative eligibility. The advisory Action uses
`--selection policy` for its configured policy. Research limits and selection
are independent; lowering lookup budgets does not improve scope selection.

For Python, Value can defer fixed SQL grammar questions and fixed Flask `.html`
renders whose supplied bindings appear only as ordinary escaped text expressions
in their discovered templates, or are unused there.
Comprehensive retains these operations. Custom renderer settings, raw markup,
script/style/attribute contexts and unresolved templates retain Value review.
These scope hints do not certify application safety. Regenerate older inventories
before reuse. ORM review packets can include bounded effect and import-bound
caller excerpts; `review-inventory-list --group-by implementation` groups located
Python ORM callables for source reading while preserving each review ID and its
independent authorization decision. Value can defer additional selectors on the
same direct Django filter chain to one retained review with the complete chain
excerpt and an explicit dependency. Separate operations and nested queries keep
their own questions; no safe verdict transfers between IDs. Fixed or empty,
import-bound Django `HttpResponse` bodies can also be deferred when local uses
only return the response or assign fixed content. Dynamic bodies, aliases,
unknown response uses and unknown query transforms retain Value review.

Python mutation packets can also include import-bound class/base declarations,
`Meta.permissions`, permission helpers, `mutate` and `check_permissions`
implementations, field construction and alternate direct callers. These are
source contexts, not verified runtime dispatch, guard ordering or authorization
controls. Missing policy, overrides and unresolved bases remain review work.

For direct ORM receiver chains, packets can follow declared Django
`Manager.from_queryset` and `QuerySet.as_manager` bindings to custom queryset
methods, inherited delegates and supplied argument producers. A method may
preserve, replace or clear filtering. These bounded source excerpts do not
establish actor authority or effective scoping; dynamic managers and queries
passed through local aliases still require source review.

ORM packets can also show a selection's assigned name, direct local aliases,
selector input bindings and later writes or helper calls that reference those
names. Observed rebinding stops navigation of that name. Branch alternatives,
record identity, batch membership, query correlation and transaction freshness
remain unverified; these excerpts do not establish authorization or taint flow.

For queries using directly imported Django `Exists`, `Subquery` and `OuterRef`,
packets retain separate expression inputs, nested references, negation and
bounded local query bindings. Separate existence predicates do not establish
that one related row satisfies both. SQL scope and correlation still require
review, including when no outer reference appears in the delivered excerpts.
These Python excerpts also reach `review-card` and `review-sweep`, the compact
views used by the ordinary worker, with their source-only qualification retained.

```text
mehscan state plan --store STATE --stream pr:24 --inventory RUN/inventory --source-root ROOT --generation 1 --owner OWNER --input RUN/plan.json --operation-key plan-1 --skill-root TRUSTED/mehscan-security
mehscan state work --store STATE --stream pr:24 --inventory RUN/inventory --source-root ROOT --generation 1 --owner OWNER --skill-root TRUSTED/mehscan-security
```

Save the work JSON as `RUN/work.json`. Create bundles for exactly its `review_ids`
using `review-bundles --inventory ... --review-ids ... --output RUN/bundles`.
No bundle run is needed when that array is empty. `--review-ids ""` explicitly
exports source-only work. The exported package contains no ownership token.
When the entire native inventory is empty, `review-bundles --inventory ...
--review-ids ""` can also create a bound zero-bundle run for canonical JSON/SARIF
export. Its source freshness and comparison checks still apply. This does not
turn source-only questions into findings; retain the completion/state artifact.
Empty bundle selection remains rejected for a nonempty native inventory.

The package binds the generation, source snapshot, plan, selection, unresolved
decision parents, pending questions and source-backed evidence updates. Pass
`--work-package FILE` to `state plan` or `state record` to reject stale handoffs.
Updating a plan, admitting another answer or adding facts requires a fresh package.
Runtime-bound `state plan`, `work` and `record` require `--skill-root` and verify
the actual trusted package against the admitted digest. The worker supplies it
automatically. A changed skill or executable requires a new native contract and
plan; existing history remains readable.

## Configure a reviewer

Create a trusted JSON argv file outside ROOT, for example:

```json
["/absolute/path/to/python", "/absolute/path/to/reviewer_adapter.py"]
```

The controller sends one JSON task on stdin and reads one JSON result on stdout.
The adapter applies the [security skill](../skills/mehscan-security/SKILL.md).
The ordinary investigation includes a concise final proof check using its current
context and remaining allowance; it does not require an extra model call.
The controller prepares a bound `evidence_packet` with a versioned runtime
contract compiled from trusted skill references, the selected work and native
questions. `--skill-root` defaults to the installed security skill and must stay
outside ROOT. Adapters apply this contract without resending operator guides.

Tasks identify `kind`, `source_root`, `scanner`, `inventory`, `work_package` and
`journal_dir`; a native task additionally includes `bundle` and `review_ids`.
A change-pass task returns only `{ "change_pass": [...] }`. A native task returns
a brief or full response draft supported by `review-bundle-finalize`.

Instead of returning a final draft immediately, an adapter can request the next
missing source fact through the controller:

```json
{"research":[{"tool":"source","review_id":"EXACT_BUNDLE_ID","purpose":"Inspect the input and rejection before the selected operation.","arguments":{"path":"src/entry.js","start_line":1,"end_line":20}}]}
```

The next task contains `research.results` with the actual queries and native
outputs, plus remaining budgets. Return either a nonempty research batch or the
normal final draft, never both. Native queries name their prompting ID from this
bundle; change-pass queries use `review_id: null` and are audited separately.
The controller journals newly executed native queries under that ID for finalization. Shared
facts can inform sibling IDs without fabricating a query for each one.

Order independent lookups by deciding priority. The controller validates every
request before running any lookup. It then reserves whole requests that fit the
remaining query units in that order, skipping requests that cannot fit. Budget
deferrals appear in `research.feedback` and the execution trace; they have no
source result or evidence handle. A definition costs two units and is never
split into a locator-only query to fit a single unit. Malformed arguments still
reject the entire batch. Deferrals do not grant extra calls or increase limits.

The [worker API reference](../skills/mehscan-security/references/worker-api.md)
is generated from the same catalog as the runtime schema and argument validator.
Basic tools are `source`, `base_source`, `outline`, `symbol`, `definition`,
`references`, `paths` and `guidance`. The API also offers `import-targets` and
`export-target` for explicit JavaScript/TypeScript navigation. `guidance` loads an allowlisted trusted category
guide when needed; it never supplies application evidence. Paths use relative forward-slash
syntax within the authorized root; traversal, Git metadata and symlink escapes
are rejected. Source windows are at most 400 lines and discovery limits at most
100 results. `source` reads current bytes; `base_source` reads the pinned merge base or direct
base, including deleted and renamed old paths. The controller prepares independent
old/new hunk windows and bounded enclosing units rather than always reading the
first 400 lines. Small files carry complete-file evidence; clipping and missing
coverage remain explicit.
References are bounded identifier text matches, not resolved calls; a
`path_prefix` must name a directory. Symbol and definition queries accept either
`path` for a declaration file or `path_prefix` for a directory. A confirmed
in-root directory supplied as `path` keeps that exact scope with recorded
normalization; conflicting filters are rejected. Definition reads only a unique,
unclipped discovery result and does not establish caller applicability.
Path discovery uses a literal substring,
not a glob, and searches the investigation index. Empty or clipped results do
not prove a caller or runtime file cannot exist. Inspect provenance and actual
source before using navigation results as proof.
No model-supplied commands, roots, journal paths, state mutations or network
operations are accepted by this protocol.

Queries may include a bounded `purpose` naming the missing edge. The version-2
protocol also supports `{ "draft": NORMAL_DRAFT, "working_chain": "...",
"progress": [...] }` or a research envelope with the same progress. Each edge
has `edge`, `status` (`open`, `inspected`, `blocked`), `cause` and `artifacts`.
Inspected edges cite supplied stable short handles; the audit saves their full
source-bound IDs. Blockers use `search_limited`, `not_found_in_scope`,
`unsupported`, `external_required`, `human_required` or `budget_exhausted`.
Final drafts cannot leave an available decisive local edge open. These notes
remain reviewer hypotheses, not a mechanically verified dependency closure.

One conditional protocol correction may use a remaining round for invalid
evidence handles, tool argument shapes or progress. `research.feedback` identifies
the rejection; `review-feedback.jsonl` preserves it. The draft is not admitted.
Repeated errors, exhausted budgets and freshness failures remain incomplete.
Legacy plain final-draft adapters stay compatible.

Inspect execution with `python TRUSTED/scripts/review_trace.py --run ATTEMPT`
(optionally `--review-id ID` or `--format json`). New attempts retain per-turn
responses/progress in `review-trace.jsonl`; older attempts reconstruct the available
query/checkpoint history and explicitly report its limits. Progress checkpoints
survive recovery. See [trace interpretation](../skills/mehscan-security/references/execution-trace.md)
for mechanical completion, disappearing relationships, ineffective lookups and
semantic review. Flags identify work to inspect; they never certify or change a verdict.

## Parallel execution and recovery

The controller runs up to three independent source assignments or native bundle investigations at once.
Use `--workers N` (1–16) to set the reviewer cap and `--query-workers N` (1–8,
default 2) for model-requested source queries. Set both to 1 for serial execution.
Existing bundle boundaries, review policy and admitted conversation limits stay
in effect. The change pass finishes before native jobs begin. Optional
[tiered review](#tiered-review) adds stronger-model routing and verification.

Each job has an atomic checkpoint under `jobs/`, a distinct provider conversation
and its own evidence view. Independent reads in a validated query batch can run
concurrently. Identical in-flight requests share one execution and retain its
original attribution; the controller does not invent sibling journal activity.
Appends to the same native query journal are serialized. Only the controller
finalizes responses and admits the complete native set. If a job fails, other
jobs can finish and their drafts remain available; the attempt is incomplete,
and no partial set is admitted as a completed run.

An incomplete attempt also writes `partial-results.json`, indexing already
finalized responses and explicitly listing the missing IDs. This index does not
establish current source freshness or admission. It makes saved independent work
reviewable without inventing a verdict for an unfinished job.

A stable-schema reply rejected solely for an auxiliary proof handle can use one
correction in the same conversation, within the original call/query/byte allowance
and absolute deadline. The adapter requires the remaining reply, existing valid
references and reference-list structure to remain unchanged. It retains the exact
rejected reply privately and both usage receipts. Other provider/account errors
and untyped failures receive no automatic retry. Unknown usage stops that job;
independent native jobs can still finish.

To recover an interrupted investigation, keep the original `--work-package` and
claim and use the normal invocation with a **new** `--output` plus
`--resume-from PRIOR_ATTEMPT`. Source, runtime, reviewer configuration and bundle
bindings must still match. Keep the same `--phase` and original bundle layout; regrouping
requires separate work, not a reset recovery budget. A completed change pass need
not be repeated. Completed drafts
are revalidated natively without another model call. Unfinished jobs start fresh
provider conversations with previous query results and remaining turn/query/byte/
time budgets. The persisted absolute deadline also spans downtime between
attempts. Recovery never silently changes model or resets consumed limits.
An unknown provider turn must have an exact late receipt before that job can
make another call. Its original metrics location remains recorded through
recovery attempts; reconciled counters are included once in the aggregate.
A recovery chain cannot fork from an already continued attempt; follow its
`continued-to.json` to the latest attempt. One OS lock fences controllers for the
same local state stream and releases when the controller exits.

Recovery also covers native plan, decision and pending-question writes. Before
writing, the controller saves a typed batch under `native-writes/`, with the
original operation keys and input hashes. A retry checks native source/runtime
and ownership, verifies those exact inputs and replays the original transactions.
The native journal returns existing receipts rather than admitting duplicates.
A committed decision batch resumes without calling reviewers or regenerating
its responses. For second-pass attempts, recovery also retains the first responses,
captured contexts and stage records, and regenerates the summary and training-label
exports without repeating completed reviewer calls. Keep the same second-pass
mode, scope, rates and first-pass inputs on recovery. Interrupted change-pass
writes complete before native reviews.
Changed inputs or superseded ownership stop recovery; they do not authorize a
new verdict. Keep all earlier attempt directories: replay references their
original artifacts. The checkpoints contain no ownership credential and are
not a second findings database. This is process-crash recovery on one host,
not a distributed workflow service or a machine power-loss guarantee.

A hard crash may leave a remote model call unobserved; active unobserved time is charged
conservatively, and `unknown_provider_calls` marks incomplete usage accounting.
No exactly-once remote execution or cross-attempt total token cap is promised.

Provider usage is written per conversation, then consolidated after jobs stop.
Recovery retains previous reported usage. Canonical Action usage exposes
`usage_complete` and `unobserved_provider_calls`; missing usage is never zero or
an estimate. Pool overlap is not evidence of live model speed or token savings.

`source-facts.json` retains actual lookups and original attribution. Repeated
queries reuse results within the same bound source and explicit recovery chain.
Covered source reads use prepared bytes without inventing native journal activity.
Freshness checks still surround each lookup, including cache hits. No verdict
or fact reuse across revisions is implemented. Metrics distinguish native
execution, preparation reads, pinned-base reads and cache hits.

Adapters may keep one provider session per `conversation_id` and send subsequent
query results as deltas. Resume the exact session, retain the same contract and
schema, and reject changed evidence packets. The controller stays provider neutral;
model authentication and session management belong to the trusted adapter.

Native defaults per conversation for both Value and Comprehensive are five
research rounds (six total model calls), 24 query units, 512 KiB and 900 seconds.
Value uses policy selection; Comprehensive selects every admitted ID.
Configure `--research-rounds`, `--research-queries`, `--research-bytes` and
`--timeout` on `state plan-template --skill-root ...`; zero rounds disables research.
The worker reads those admitted values. Explicit worker overrides must match exactly.
Changing effective limits or policy requires a new plan and fresh work package;
changing the engine or skill also requires a new runtime binding. These are work
limits, not a total PR token/currency budget or a promise of conclusive decisions.
The effective timeout bounds the entire conversation, including its lookups and freshness
checks, and separately bounds other native commands. The controller validates
the whole batch before executing it and rechecks the exact work package before
and after each lookup and reviewer response. Stale work, invalid requests,
query failure or exhausted budgets leave an incomplete attempt without inventing
a verdict. A reviewer with remaining work should return an explicit needs_review
draft when its advertised budget reaches zero. Retain `research.jsonl` with the
native journals: it records source-only queries too, without attributing them
to a nonexistent native finding.

Change-pass entries contain `path`, `status`, `summary`, `questions`,
`native_review_ids` and `evidence`. Status is `reviewed`, `needs_review`,
`deferred` or `coverage_gap`. Reviewed requires no questions; needs_review requires
specific questions. Evidence contains `side` (`current` or `base`), relative
`path`, `start_line` and inclusive `end_line`. Assessed modifications and renames
need old primary evidence and current primary evidence; deletions need old
evidence. Base means the pinned merge base, otherwise the direct base commit.
The CLI reads the actual excerpts and rejects invalid ranges or source changes.
An assessed effect without a native ID remains a source-only lead/question.

## Run the worker

Configure model, explicit authentication and supported analysis-only provider
settings in the adapter. Runner isolation belongs to the operator. The controller is not a sandbox. The adapter must treat target source
and comments as data, avoid target builds/hooks/installations and repository
instructions, and keep queries within the authorized source boundary. Its task
receives no claim token. Environment credentials are not an isolation boundary:
the operator must give the reviewer process only appropriate credentials and
filesystem access. Reviewer labels are recorded assertions, not authentication.

```text
python scripts/review_worker.py --scanner TRUSTED/mehscan --source-root ROOT --inventory RUN/inventory --store STATE --stream pr:24 --claim PRIVATE/claim.json --work-package RUN/work.json --reviewer-command TRUSTED/reviewer-command.json --reviewer-label configured-reviewer --run RUN/bundles --output RUN/attempt-1
```

Use Python 3.11+. All control/artifact paths stay outside ROOT. The output
directory must be new. `--phase change-pass` or `--phase native` permits staged
work. Successful native finalization and report
validation precede admission. The worker registers pending checks, investigation
blockers and change-pass questions;
`--supersede` explicitly links fresh native decisions to all exact prior heads.
Runtime-bound native admission requires the exact work package; the contract is
also retained as admission provenance. Scanner and skill bytes are checked around
lookups and model responses. This detects drift, not the correctness of reasoning
or authenticity of an operator-provided tool package.
Ownership stays active for later chunks; ending execution is a separate command.

Retain `worker.json`, `state.json`, finalized responses, the copied run binding,
work package and query journals together. `findings.json` is the canonical native
finding report; completion accounting is in the separate source-bound state
artifact. An `admitted` worker result means its data was admitted, not that review
is complete. A timeout, malformed result, stale handoff or admission error leaves
an incomplete attempt. Earlier successful journal transactions remain intact;
there is no rollback or synthetic verdict. Refresh work before retrying.

## Usage and cache accounting

After an attempt stops, `worker.json` contains `provider_usage`, `usage_complete`
and `unknown_provider_calls`. Unknown usage stays unknown; an admitted result is
not proof that every remote call was observed. The bundled adapter reports actual
input, cached input and output tokens when the provider supplies them.

Use the consolidated `provider-metrics.jsonl` for per-call analysis. The separate
`provider-metrics-<conversation>.jsonl` files contain the same receipts; summing
both forms double-counts calls. Across recovery attempts, deduplicate by
`conversation_id` and `round` and retain failed-attempt usage. Compare initial
calls (`round: 0`) with continuations separately when assessing cache behavior.
The cached fraction is cached input divided by total input, not a discount on
output tokens. Cache hits depend on the configured provider and actual requests.

For price estimates, apply the configured model's applicable rates and context
multipliers to uncached input, cached input, output and any reported cache writes.
Include retries and follow-ups. Provider elapsed times can overlap in parallel;
use attempt start/end times for wall time instead of summing call durations.
The controller does not turn these counters into a provider invoice.

## Resume missing facts

Register a question against an exact current needs_review decision/check or a
current needs_review change-pass question with `state pending`. Use a typed kind
such as `source_authority`, `control_coverage`, `caller_reachability`,
`configuration` or `other`. Save a source-backed update:

```json
{
  "schema_version": "1",
  "question_id": "EXACT_CURRENT_QUESTION_ID",
  "answer": "The named boundary is defined in this current source range.",
  "evidence": [{"side":"current","path":"src/boundary.ts","start_line":12,"end_line":20}]
}
```

```text
mehscan state fact --store STATE --stream pr:24 --inventory RUN/inventory --source-root ROOT --generation 1 --owner OWNER --input RUN/fact.json --operation-key fact-1
mehscan state work --store STATE --stream pr:24 --inventory RUN/inventory --source-root ROOT --generation 1 --owner OWNER --resume-only true
```

Facts do not change verdicts. The resume package narrows native IDs to questions
with evidence not yet submitted for revalidation, while retaining other pending
questions for those IDs. Source-only questions stay in the change pass. Create
matching bundles, review the package and use `--phase native --supersede` when
explicit native adjudication is intended. Conflicting answers require adjudication.
An unchanged pending answer can be admitted with its consumed evidence metadata;
it stays pending without requeueing the same update forever.

New generations do not inherit facts or verdicts automatically. Old proof remains
in history. A plan revision also replaces exact change-pass question origins;
same-worded questions require current registration, and old facts are not silently
remapped. Native pending questions retain their origin until supersession.
External/deployment attestations, authenticated fact producers,
semantic question matching and cross-revision reuse are not implemented.

## Prepared ASP.NET policy source

Native authorization/credential cards include same-project `Program.cs` and
`Startup.cs` navigation, plus one unique lexical base class where available.
Project scope follows the nearest `.csproj`. Ambiguous, generic and qualified
base classes still require targeted research; these leads do not prove effective
policy, inheritance semantics or runtime activation.

The worker prepares actual current source before the model starts. Startup
windows take priority over inherited-controller windows. Preparation is bounded
to four windows per bundle, 400 lines and 16 KiB per window, and 64 KiB total.
Clipping and omitted windows remain explicit limits. Source windows are cached
within the current snapshot only and can satisfy later source requests without
a duplicate native query. Fresh source/runtime/ownership validation is retained.

Credential and authorization review distinguishes actual state changes or
authority issuance from logs, generated demo tokens and success responses.
ZIP extraction keeps its own sink/location/identity; a nearby cleanup operation
must not inherit an extraction verdict. Simulated-effect and inferred-archive
fixtures accompany the paired engine and skill changes.

This increment does not add full Razor/C# parsing, cross-revision verdict reuse,
or a token-saving guarantee. Corpus and live model acceptance are separate from
deterministic evidence/preparation tests.

## Optional source preparation

An opt-in preparation experiment can build an ordinary `--source-profile` from
native sweep helper/context leads. Save the selected bundles' `review-sweep`
objects as one JSON array, then run:

```powershell
python scripts/review_source_profile.py --scanner C:/tools/mehscan.exe --source-root C:/src/app --work-package C:/review/work.json --sweeps C:/review/sweeps.json --output C:/review/source-profile.json --trace C:/review/preparation-trace.json
```

Pass the resulting profile through the worker's existing `--source-profile`
option. The builder prepares up to eight complete bounded windows per bundle,
using exact native source leads and unambiguous named declarations. It records
ambiguity, missing source and size limits instead of selecting an arbitrary
declaration or silently clipping a body. Expanded context ranges may end at the
actual file end; the trace records both requested and returned ranges.
Declaration uniqueness does not establish import, dispatch or caller applicability.
Profiles retain exact bundle IDs, inventory binding and whole-file hashes; changed
source fails normal profile validation. The trace contains navigation/provenance,
not verdicts. A no-window result exits with code 2 and leaves the trace available;
continue with ordinary preparation. This experiment does not change default
preparation or enable a model call.

Add `--dependencies` to opt into JS/TS explicit-import navigation. It follows
the anchored operation's declared constructor dependencies and literal Nest
Passport guard/strategy keys, including import aliases. Invoked dependencies
precede passive type imports within the same window budget. Duplicate strategy
registrations remain candidates; dynamic keys and missing modules are not guessed.
The trace distinguishes module resolution, registration candidates, lookup
failures and budget omissions. This is source navigation, not proof that an
exported member, injected provider or registration is active at runtime.

The underlying read-only command is
`mehscan investigate import-targets ROOT --path relative/file.ts`. It returns
actual static import statements with `source`, `external` or `unresolved` module
targets using the existing resolver. It does not infer CommonJS bindings or
follow arbitrary recursive imports. Preparation caches navigation queries within
a work package, caps new dependency queries at 80, and retains normal source
hash checks. Both the builder and this query remain opt-in.

`--dependency-chains` is a further opt-in experiment and implies `--dependencies`.
It schedules each discovered dependency chain as a unit under the same eight-window
and 64-KiB limits. One same-named operation delegate per claim receives priority,
followed by shared credential-registration candidates, remaining declared receivers
and other imports. If a chain cannot fit, the trace records the omitted chain and
reason; independent source can still be prepared. No member is silently preferred
from an oversized ambiguous registration set.

Each chain trace records its caller, navigation question, requested windows,
delivered source/hash bindings or omission reason, and source reuse. Delivery does
not answer the security question or establish active provider registration. Shared
bytes never transfer a caller's verdict to another claim. This option does not yet
follow re-export chains or replace reviewer-directed deciding lookups; the older
`--dependencies` behavior remains available unchanged.

For one known exported name, the read-only native CLI now supports:

```powershell
mehscan investigate export-target C:/src/app --path src/helpers/index.ts --name sanitizeUrl --journal C:/review/queries.jsonl
```

Use `import-targets` first when the question concerns a caller's import; an
explicit source path is not a substitute for a missing package/build binding.
`export-target` follows named aliases and star exports using the native module
resolver, returning a unique static source candidate or explicit ambiguity/gaps.
The result includes visited nodes, successfully summarized files, parsed bytes
and bounds. Missing modules, parse errors, namespace objects, erased imports,
reassigned bindings and incomplete branches cannot establish a unique target.
Inspected nodes remain available as leads when the overall answer is incomplete.

Traversal is bounded to eight levels, 128 nodes/edges, 32 summarized files,
256 KiB per file and 1 MiB of parsed source. Repository discovery/source loading
still occurs outside these graph limits. Only the traversed modules receive export
AST summaries; unrelated imports inside an implementation are not recursively
loaded into the graph. Read the candidate's source with `outline`/`source` before
assessing its behavior. Runtime provider selection, build conditions and caller
applicability remain separate questions. The command accepts simple ASCII export
identifiers or `default`.

Both `import-targets(path)` and `export-target(path, name)` are available in the
worker's typed research API, at one query unit each. Both require a bounded
`purpose` stating the deciding question. The broker shares identical lookups
within the pinned snapshot while recording each requesting claim and purpose;
cache hits still consume recipient query/byte budgets and pass freshness checks.
Navigation facts are not source-body proof handles. Use `definition` or `source`
to inspect behavior after locating an implementation. Missing files and unsupported
import-navigation languages return explicit non-source lookup results; unrelated
execution errors still fail normally. Automatic source-profile preparation does
not yet follow these export chains.

For experimental routed execution, `--validate-only --phase native` performs
ordinary review/finalization/report checks without recording decisions or pending
questions. It returns `source_validated`; supersession and change-pass modes are
rejected. This mode can assemble complete original bundles from native and
workspace results. Ordinary admission remains the default.

## Explicit source profiles

`--source-profile RUN/source-profile.json` supplies already selected source through
a channel separate from automatic policy leads. Keep the JSON outside the source
root. It contains source locations and hashes, not conclusions or instructions:

```json
{
  "schema_version": "mehscanSourceProfile/v1",
  "repository": {"repository_key": "EXACT_KEY", "path_prefix": ""},
  "inventory_input_fingerprint": "EXACT_WORK_PACKAGE_FINGERPRINT",
  "targets": [{
    "review_ids": ["EXACT_NATIVE_BUNDLE_REVIEW_ID"],
    "windows": [{
      "path": "src/handler.ts",
      "start_line": 1,
      "end_line": 80,
      "file_sha256": "EXACT_64_CHARACTER_LOWERCASE_SHA256"
    }]
  }]
}
```

Copy the repository and inventory fields from the exported work package. Each
target must match an entire generated native bundle, with no overlapping target
IDs. Unprofiled bundles retain ordinary preparation. A target permits eight
windows of up to 400 inclusive lines each, 16 KiB per window and 64 KiB total.
Out-of-range, stale, oversized or mismatched input is rejected rather than clipped.
The automatic policy-lead limit remains four windows; native batching remains 20
by default. The profile adds no model calls or research allowance.

Both reviewer paths use the same reader. Workspace initialization accepts the same
`--source-profile` option and freezes the manifest in its binding; supply a changed
profile to fresh state. The ordinary worker checks the manifest during review and
includes its digest in recovery configuration. Source/runtime drift still rejects
stale results while retaining attempted model usage. Exact duplicate source is
reused, including prepared-source lookups; pinned-base source stays separate.

Profiles do not establish caller applicability or authorize an effect. Their
selection and acquisition costs belong in a comparison. The experimental paired
preparer accepts the manifest as `source_profile` in its design, derives required
coverage automatically and checks actual source equality before dispatch.

## Bound provider adapter

The [BYOK Codex adapter](codex-reviewer.md) supplies a provider descriptor via
`--provider-contract FILE`. The worker compares its actual bundled argv/config
with the admitted native provider/model/effort/client version before execution.
The public adapter requires that binding and exact start/resume; no mandatory
Mehscan process sandbox or executable SHA is added. Generic trusted local test
adapters without provider binding remain supported.

Use `--artifact-root DIR` when the worker output is only a child of the complete
upload root. The Action supplies this automatically. Private config/auth/session
stores cannot live in an exported sibling. Provider metadata is compatibility,
not authentication. Opt-in Action model execution and advisory artifact packaging
are implemented and tested with a deterministic provider on Ubuntu; live/hosted
acceptance remains pending. See [Action exports](github-action.md#opt-in-byok-action-execution)
for canonical JSON, SARIF, completion, usage and the hash manifest.

## Tiered review

Tiered review is an opt-in local controller mode. The native runtime pins a
routine provider, a different expert model, shared limits and an audit policy.
Existing single-profile runs remain available. No agent SDK is required.

Prepare two private adapter configurations/argv files as above. Export the expert
descriptor with the adapter's `--config EXPERT_CONFIG --contract` command and use
that exact object as `expert` in a trusted orchestration JSON outside source.
For example, replace the illustrative expert descriptor below with that export:

```json
{
  "expert": {
    "schema_version": "1",
    "provider": "codex-cli",
    "executable_version": "YOUR_CLIENT_VERSION",
    "model": "gpt-6-sol",
    "reasoning_effort": "medium"
  },
  "case_limits": {"model_calls": 8, "queries": 24, "bytes": 524288, "timeout_seconds": 1200},
  "run_limits": {"model_calls": 200, "queries": 500, "bytes": 20971520, "timeout_seconds": 3600},
  "max_reviews_per_job": 5,
  "audit_percent": 10,
  "audit_seed": "review-2026-10"
}
```

Pass `--review-orchestration FILE` when creating the native runtime/plan template,
with the usual primary `--provider-contract FILE`. Admit the resulting plan
normally. Prepare small related bundles, for example with `--max-reviews 5`, then
add `--expert-command EXPERT_ARGV_JSON` to the normal worker invocation.
`--expert-workers N` defaults to one. `--expert-review-ids ID,ID` sends the
containing bundles directly to the expert. These settings are explicit choices,
not a measured optimal model or pool configuration.

The controller routes a bounded bundle as a unit to reuse its source context;
a trigger on one ID causes an independent assessment of all IDs in that bundle.
It does not yet create a smaller expert-only subset. The second stage starts as
slots become available, without waiting for the whole first queue. Routine
issues receive expert verification. Direct expert issues receive a fresh
assessment by the routine model. Clear closures may finish after one assessment;
typed risk/reasoning requests and a seeded sample of dismissals require another.
An actually missing external/human fact remains pending rather than receiving
an automatic expensive retry. Routing never uses a numeric confidence threshold.

The independent assessor receives the original source question and normal facts,
with prior verdicts/confidence and change-pass conclusions withheld. It can
research through the same broker. Same verdicts do not certify correctness;
both assessments must satisfy the source-evidence contract. Conflicting verdicts
or a remaining question from the second assessor produce `needs_review`, retain
both stage artifacts and register native pending work unless optional source-backed
adjudication resolves the exact disagreement.

A case is one bounded bundle. Its call/query/byte/time limits span both profiles
and explicit recovery attempts. Run call/query/byte limits span all cases; the
run timeout measures elapsed wall time, while a case timeout sums its active
assessment time. Conversation limits also remain in force. Model calls and
queries are reserved before dispatch; received bytes are charged even when an
oversized result stops work. Cache hits still consume the recipient's research
allowance. These are not hard token/currency limits. Budget exhaustion or provider
failure leaves the run incomplete and cannot admit an unverified issue.
Byte limits count requested research results; prepared packets and provider
tokens are measured separately rather than charged to that research allowance.

Keep `review-execution.json` together with `assessments/`, checkpoints and native
query journals. The receipt identifies each question's assessments, configured
providers and artifact hashes. Tiered `state record` requires `--review-execution`
and checks both stage artifacts against their original bundle and actual source.
A reported issue needs two distinct configured-model assessments; sampled
closures need a second assessment. Contrary assessments remain pending unless
the explicit quality policy below admits a source-backed adjudication. These are trusted-controller provenance assertions, not authenticated
proof that a remote provider ran or that its reasoning is correct. Canonical
usage groups actual reported counters by provider and role.

Add `"quality": {"adjudicate_disagreements": true, "final_qa": true}` to the
orchestration policy to enable quality stages. Provision shared limits for the
routine review, independent verification, optional expert adjudication and expert
QA, including research turns. Each stage starts a fresh conversation; none resets
the case/run budget. The default policy adds no quality-stage calls.

Adjudication sees both prior assessments and resolves a named claim with cited
source. Native admission checks that its explanation occurs in the pinned source
assessment. It can resolve a contrary pair toward a verdict supported by one of
the earlier assessments; a newly proposed verdict remains pending for independent
assessment. This is explicit source resolution, not majority voting. External,
human or exhausted-budget facts remain pending. Original assessments are retained.

QA reviews the finalized baseline in bounded original bundles, with capped
same-file peer summaries for navigation. It can preserve decisions or reopen
exact assigned IDs. It cannot dismiss an issue, promote a new issue, close pending
work or rewrite approved prose. Entirely pending bundles skip this stage; native
admission requires a real expert QA receipt for a closed verdict when enabled.
An available newly proposed verdict or QA reopening can enter one fresh blind
routine/expert pair over recovered source. These are final-only calls, not a new
research loop. Closed revalidated verdicts receive a new expert QA check. The
controller keeps the original assessments and QA, does not reset shared spend,
and leaves disagreements or insufficient capacity pending. No repair loop runs.
`quality-summary.json` records QA, revalidation, adjudication and reopening
counts; omitted peer context remains a coverage limit.
The QA response explicitly distinguishes keeping the baseline claim, repairing
its conditions/impact, and reopening an unresolved question. A repair stays
pending even when the underlying issue label still holds; corrected QA prose
is never silently treated as approval of the older wording.
This is not an exhaustive comparison of every finding across the application.

Validated stage responses and pre-QA baselines are frozen and hash checked during
recovery. Interrupted research preserves its remaining budgets; completed quality
drafts need no repeated model call. Native admission and canonical reports remain
authoritative. The automatic Action setup still configures a single profile;
automatic tiered Action configuration and live quality/efficiency acceptance
remain separate.
