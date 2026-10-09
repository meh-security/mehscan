# Plan a repository review

## Modes and queue

For membership and rationale, use [review scope policy](review-scope.md).
Current queue assignments can be broader than that policy; inspect concentrated
lanes with real snippets and record useful refinements in the existing plan.

For a supplied manifest with exact IDs, review those IDs directly. Otherwise,
before opening many requests, follow this planning guide.
Pre-assess the source and requested scope: identify the stack and deployed
surfaces, map inventory concentrations, and use prior same-revision verdicts
to rank review lanes. A bounded small review can use full
bundles; a large or uncertain one uses an inventory and small selected chunks.
If parallel review is authorized, assign disjoint IDs with one shared whole-run
plan. Start with a small pool (three reviewers is a useful initial setting),
refilling a slot when its independent package completes. Keep a shared producer
and its caller/effect checks in one job; split different producers or controls.
Do not launch one reviewer per occurrence. Queue status is ready, running,
completed, or blocked on a named fact; unstarted IDs remain unreviewed.
Default to Value review: map the attack surface, then cover distinct security
relationships across relevant lanes, including access, output, data exposure,
and state changes without a hard severity cutoff. Review distinct consequential
relationships; an occurrence count is not a target for Value coverage. Keep
stronger signals, clearly justified fixes and promising high-impact leads in Value.
Ordinary directory setup/listing, normal data decoding, syntax-only unsafe/extern,
nonsecurity hashes, positive controls and generic log formatting are supporting
facts, not standalone jobs in either mode. Comprehensive needs a plausible
medium-or-higher mechanism, such as sensitive disclosure, meaningful log forgery
or a cookie-authenticated sensitive state change. Input alone does not turn a
low-effect operation into mandatory review. File-content, unsafe interpretation
and consequential export/permission relationships remain useful. In a large queue, keep the unselected work
visible and call the review partial until every relevant lane is assessed.
Comprehensive review gives every admitted ID a verdict within the user's scope.
Value excludes source-proven build tooling, vendor distributions and generated
copies from its application queue by default; keep their exact IDs and ownership
evidence in the plan. Comprehensive includes these as separate lanes. Keep
application wrappers and consequential build/dependency leads. See
[scope lanes](#scope-lanes) before excluding them.
For inventory selection in Value mode, use `--selection value` and record
`deferred_count`. See planning for the trusted-source assumption and overrides;
deferred IDs have explicit effort assumptions or shared dependencies, not safe
verdicts. Ordinary PHP output/loading occurrences are conditional surface
inventory: inspect producers and reopen consequential sites. Review
`dependency_review_ids` first; unsafe or unresolved shared
behavior reopens its dependent sites with the rebuilt ledger. Value can expand
to Comprehensive when the source warrants it.
For shared C# destinations or path producers, inspect the exact shared field,
helper and hooks, then check site-specific inputs, guards and effects. Different
options, raw URI suffixes and replaced selectors retain separate work. An
unresolved representative reopens its dependents; keep their exact IDs visible.
Honor a requested category. Build a same-fingerprint review ledger from prior
run roots with `review-ledger`; pass it to inventory listing and selected bundle
creation so finalized IDs are not selected again. For a large queue, use short source reads to rank a few inventory IDs
before materializing their requests. Materialize a selected chunk with
`mehscan investigate review-bundles ROOT --inventory RUN/inventory --review-ids ID,ID --output RUN/chunk-1`.
Keep `RUN/review-plan.md` current with included, conditional, and deferred
scope, progress, and a short ranked queue of review lanes. Read it first when
resuming; choose a ready in-scope lane, then select exact IDs with small
previews. In auto mode, continue
the next authorized chunk without waiting for a new instruction; report the
queue and progress so the user can redirect or stop. Re-rank when source checks
change the picture. For one supplied review or a quick candidate scan, skip
this planning step.

After each chunk report, add consequential `reviewer_origin_leads` to the
ranked plan as separate, unreviewed source questions. Follow
[lead follow-up](#follow-up-on-reviewer-origin-leads)
for their independent evidence check. Keep the originating ID's verdict intact.

## Time and workload

Before launching triage, put the active/deferred counts and a short lane table
in the review plan: area/category, active IDs, shared question or representative,
status, and next action. IDs are workload anchors, not independent research jobs.
Use `review-inventory-list --selection value --group-by implementation --limit 12`
to find source neighborhoods with exact IDs, without creating bundles. Combine
with component/category and ledger filters. These file/reported-symbol groups
are reading opportunities, not verified callable identities or shared verdicts.
Use source-supported implementation groups and scope exclusions before packaging
many requests; keep SQL construction, raw/stored interpretation and sensitive
effects visible. A large sink-only lane warrants producer/implementation research
first, rather than one model invocation per occurrence.
Reuse supplied compiler facts first. When a missing symbol/producer warrants
fresh collection, use `csharp-semantic` or `typescript-semantic` with the current
`--inventory` and selected `--evidence-ids` from card `anchor.id`. This avoids a
Rust rescan and limits requested operands; keep whole project/caller source scope.
The result is scoped follow-up evidence, not a replacement for other languages'
or unselected inventory facts. Do not run it per ID when one collection can
cover the selected implementation chunk.

Start with a small coherent chunk spanning useful relationships. Measure elapsed
preparation and review time separately. After it, update the remaining queue and
use the observed pace for similar lanes to give a rough remaining-time range;
label untested lanes unknown. Do not infer hours from ID counts alone. If the
projection is impractical, reduce the next Value pass to distinct consequential
relationships, defer evidenced repeats, or recommend a narrower area/category.
Explain the coverage tradeoff. Comprehensive still owes all in-scope IDs.

For parallel work, measure completion through the last validated report,
longest package, aggregate tokens and duplicated research as well as individual
job times. Put independent expensive jobs first when their cost is known. A
hundred-second package resolving many related operations may be worthwhile;
repeated small jobs reopening the same policy question need one shared follow-up.
Reuse bound inventories and prepared evidence; count bundle export in preparation
and avoid rebuilding native evidence for each reviewer. Shared facts do not
transfer verdicts across different effects or output contexts.

Honor the user's time budget. At its end, finalize completed decisions and save
exact unreviewed/deferred IDs, missing facts, and the next recommended chunk.
Budget exhaustion leaves work unreviewed; it does not establish `not_issue` or
`needs_review`. In auto mode, continue within the stated pass/budget and re-rank
after chunks. With no supplied budget, state a bounded initial pass and its
coverage before starting; do not silently commit to reviewing the whole backlog.

## Inventory and history

For a new large review without an enriched inventory, start with a source-only
inventory, choose Value lanes and implementation chunks, then collect compiler
facts only for relevant unresolved operands. Available compiler contexts do not
require immediate whole-repository semantic collection. Selected collection
returns compact `selected_observations`; use those facts for the chunk while
keeping its original review IDs and source binding. It does not update the
inventory's admission or deferrals automatically. Reuse already enriched
inventories when available; avoid discarding facts or repeating collection.

For a mixed stack, preserve every supplied native context when regenerating the
whole-repository enriched inventory. A language-specific experiment can leave the other
language's closures and deferrals unapplied. Compare modes on the same enriched
inventory. The final Value queue excludes both CLI `--selection deferred` IDs
and confirmed scope-deferred IDs, without double counting their overlap. Persist
their exact IDs/reasons separately and report the resulting active count;
Comprehensive includes admitted deferred IDs within the user's scope.

First inspect the requested scope, existing run artifacts, main manifests, and
repository layout. Build a ledger with `mehscan investigate review-ledger
--inventory RUN/inventory --history OLD_RUN_ROOT,RUN --output RUN/review-ledger.json`.
Each history root needs a matching `inventory/overview.json`; only validated
final responses count. Pass `--ledger RUN/review-ledger.json` to inventory
listing and selected bundle creation. Rebuild the ledger after each chunk;
`needs_review` remains a completed investigation with a separate follow-up.
History without a source fingerprint needs an explicit source check before reuse.
If the source and review queue are small enough to handle
as a few bundles, use `review-bundles` directly. For a large or uncertain
queue, run `mehscan investigate review-inventory ROOT --output RUN/inventory`
once for the current source. Read `overview.json` first. Filter the queue with
`mehscan investigate review-inventory-list --inventory RUN/inventory --cwe CWE`
or `--capability NAME`, `--path-prefix PATH`, `--operand-kind KIND`, and `--limit N` as needed.
`inventory.json` holds the full queue; `scan-cache.json` is for Mehscan, not
an AI review package. The inventory lists exact IDs, operation locations,
capabilities, CWE candidates, evidence strength, and scan coverage without
source excerpts. A source change invalidates the cache; regenerate it then.

In Value mode, use `review-inventory-list --selection value`; Comprehensive
uses `--selection all` (the CLI default). `--selection deferred` lists the exact
IDs and `value_hint` reasons omitted by Value, including with component/CWE or
contract filters. Count these as deferred, never as `not_issue` or scanner
closures. `scope_count` is the filtered, unreviewed population before selection;
`matching_count` is the selected population and `deferred_count` its heuristic
deferral population. Contract queues use `matching_review_count`.

## Scope lanes

Value focuses on authored application behavior. Before selecting bundles, separate
source-proven build/CI tooling, vendor distributions and generated copies into
recorded lanes. Use manifests, source/output mappings, imports and ownership
headers; directory names alone do not establish ownership or deployment.
Use `mehscan investigate provenance ROOT --inventory RUN/inventory --limit 200`
once when lanes are unclear. Inventory paths limit header reads and candidate output;
this query does not validate/reuse inventory verdicts. Omit inventory for a broader
assessment only when needed.
It supplies candidates from package entry/scripts, source maps and generated/
distribution headers without requiring a compiler. Match paths to inventory IDs.
Confirm the evidence before deferring: headers can belong to authored code, build
entry points can also run in production, and source maps may lack local originals.
Keep conflicting roles and unresolved mappings active. Follow a mapped original
with source lookups; the mapping does not establish output/source equivalence.
Classify tooling at the component/entry-point level when manifests and inspected
code establish its role; do not require each sink to be proved unreachable.
An executable CLI or a tool launching a development host is not by itself a
runtime conflict. Keep exceptions supported by observed cross-boundary inputs,
production use or a concrete dependency lead; hypothetical inputs do not reopen
every build operation. Shipped generated runtime code still needs its original
implementation or a separate runtime review.
Check `excluded_subtrees` and skipped/truncated inputs for coverage boundaries.
When truncated, query relevant component prefixes rather than dumping everything.
Review the authored source instead of its mapped output. Keep exact excluded IDs,
reasons and representative source locations in `RUN/review-plan.md`. Apply these
scope exclusions after `--selection value`; that CLI filter knows operand hints,
not the agent's repository assessment.

`package_build_tooling_inventory` hints already defer ordinary sinks reached
through literal package build entries/imports. The scanner preserves observed
runtime/export/shared-import conflicts and strong relationships. Inspect the
manifest named by the hint when deployment scope is uncertain; reopen IDs for
deployed tooling or concrete untrusted build inputs. This is conditional scope,
not a safe verdict. Additional vendor/generated scope still needs assessment.

Comprehensive reopens these lanes and accounts for each admitted ID within the
requested scope. An explicit application-only scope remains application-only.
Dependency/build exclusions never become `not_issue` verdicts. Report both the
application queue and the total omitted IDs. Keep unmapped outputs, application
wrappers, dangerous build inputs and observed dependency weaknesses in Value;
reopen a lane when source or user knowledge makes its trust assumption invalid.

With supplied Roslyn inputs, add `--csharp-context CONTEXT
--csharp-backend BACKEND` to inventory creation. Scan and enrich once, then
reuse that inventory for selected bundles.

With supplied TypeScript inputs, use
`--typescript-context CONTEXT --typescript-backend SCRIPT` for inventory creation.
Prepare only relevant projects and their source dependencies. Declare
`runtime: "browser"` only with actual browser entry/build evidence; Node/SSR/shared
code stays unspecified or separate. Types and missing implementations do not
prove safe values. Reuse the resulting inventory; never start a compiler per ID.

Exclude standalone requests resolved to DOM
fetch in an explicitly supplied browser context, using default GET or literal
GET/HEAD options without other options from both queues. This settles no URL trust, application
authorization or state effect. Browser fetch is not server-side SSRF. Explicit
credentials, headers/body, mutation methods, unknown options, replaced fetch,
Node/SSR scope and connected input relationships remain active. Investigate
browser destinations when evidence shows those consequential effects; ordinary
requests do not need per-occurrence Comprehensive verdicts.

## Operand selection hints

`shared_csharp_filesystem_selection` defers repeated sink-only CWE-22 operations
using the same compiler-bound unchanged string slot and capability in one
callable. Review its dependency first; unsafe or unresolved root authority
reopens dependents. Different effects still need their own guard checks. No
dependent gets a safe verdict; Comprehensive retains all exact IDs. Native
closed-selector exclusions are separate and already removed from admission.

Proven fixed node-postgres query objects leave both queues, including request
values in separate binding slots. Unknown driver identity, method replacement,
object mutation/escape/overrides and dynamic text remain reviewable. An injection
closure does not settle an independently identified record-authority question.
See [database scope](review-scope.md#database-exclusions-and-remaining-cleanup).

PHP queue conditions and their limits are in [review scope](review-scope.md).
Inventory schema 10 requires a fresh scan; do not reuse an older inventory or its
ledger. Use `--selection all` for `php_relationship_research`. Verify its bounded
producer navigation against the actual writes, transformations, writer and actor.
Same-file/rule `issue`, `needs_review` or conflicting verdicts reopen retained
research in Value. Excluded locations have no review IDs to reopen: use
source/symbol/references and record consequential discoveries as reviewer-origin
leads. Inspect shared renderers/loaders through the attack-surface map; a known
cross-file/framework gap can justify a category sweep.

The overview's `deterministic_operand_closures` counts exact output anchors
already closed by the scanner. `inventory.json`'s `admission_audit.closed_operands`
retains their locations and proofs. These include complete native numeric PHP
outputs with no unresolved CWE-79 operand check and complete Roslyn fixed
filesystem selectors closing only CWE-22. Account for them separately
from AI verdicts; they are not deferred work or a claim that the handler is safe.
Independent command, file, access and disclosure questions still need review.

Use `overview.json`'s `by_operand_fact` to see cheap operand properties before
selecting a chunk. `fixed_code_relative_path` resolves a code-directory include
target; its remaining question is target existence/content trust (writers and
deployment changes), not where an HTTP path parameter originates.
Use the checked-out application as the baseline. Follow writable/generated
targets when source or configuration suggests that boundary; hypothetical
filesystem tampering alone is not a reason to demand deployment research.
`repository_code_target` resolves a source-default code target with runtime
override and content-trust checks still open. `output_context` describes static
template position, including embedded script/style and active attributes;
dynamic markup can invalidate it. These contexts cover plain raw output as
well as whole encoder calls.
`configured_root_path` fixes only the suffix: inspect the root definition and
overrides. `encoding_call` covers the whole captured output operand, not a
later concatenation: inspect actual text/attribute/URL/script context, encoding
options, and the callable contract including filters. These shadow facts do
not suppress IDs or prove safety. `unclassified` means no supported fact,
not an absent input source. Combine them with the surface map and selected
mode; comprehensive still covers every admitted ID. Read the remaining checks
from the selected evidence/card and query only facts that can change its verdict.
`source_sink_cooccurrence` means a source and sink share an enclosing group;
it does not establish value propagation. Actual security paths remain separate.

For a concentrated queue, use `review-inventory-list --inventory RUN/inventory
--ledger RUN/review-ledger.json --group-by contract --limit 12`. It ranks repeated
operand questions by count, not risk. `--contract KEY` returns exact members
and combines with the usual surface filters. Verify the shared definition/root
once, then use [pattern sweeps](pattern-sweep.md) for each member's context,
options, target and producer exceptions. Groups are unverified lookup queues:
one helper name does not bind every call to one implementation. Keep the
ungrouped count visible and use ordinary review for those IDs. Record useful
shared facts and assumptions against the queue's source fingerprint in the
existing review plan; reopen them when the source or policy changes.

## Choose how to run the review

Choose after this brief assessment; do not impose one package size or one
agent layout on every repository:

| Workload | Working approach |
| --- | --- |
| Small, bounded queue | Build the ordinary complete bundles. Review them directly, or give disjoint bundles to available agents. |
| Large repository, narrow request | Filter the inventory, then materialize small exact-ID bundles for the relevant cases. |
| Large, broad request with one reviewer | Keep the inventory as the map. Select a small chunk, inspect it, and request further source only when its question needs it. Replan after each chunk. |
| Large, broad request with multiple agents | Share one inventory and whole-run plan. Assign disjoint IDs by useful component or question, materialize a bounded bundle for each worker, and merge their validated outcomes into the plan. |

Consider the admitted count, category concentrations, component boundaries,
estimated request size from a small pilot, and available agents. Use AI judgment
to choose the shape; path count alone is insufficient. Selected bundles are
currently self-contained requests. A smaller seed card with optional evidence
loading is a proposed experiment, not a command available in the CLI.

## Map the surface and define scope

Inspect main manifests, entrypoints, route registration, and a few relevant
files. Cross the largest inventory categories with those surfaces; top-level
directory counts alone do not show exposure. Record only roles that change
review order: public or authenticated request handler, background job or event
consumer, CLI, renderer, persistence producer, bootstrap, extension point,
shipped library, test/generated, or unknown. For each role, keep one
source-backed entry or dispatch clue and any access condition; a folder or
entrypoint-looking basename alone does not establish deployment or
reachability. Do not attempt a
complete architecture map. A shared helper may serve public and admin callers;
map its actual call paths rather than inheriting the helper directory's role.
For output or state-changing operations, look for earlier writers or producers
of stored data as well as direct request input.
Check whether a framework's stated security requirement is enforced or only
reported as a warning. Use this small map as a prior for sink-only IDs, then
verify the exact caller, operand, and guard during triage.

Choose a review mode:

| Mode | Scope |
| --- | --- |
| **Focused** | Review the user's CWE, capability, component, or question. State the filter and account for matching IDs. |
| **Value (default; one level below Comprehensive)** | Prioritize distinct stronger signals, clearly justified fixes and promising high-impact relationships across relevant surfaces. Useful medium issues can qualify. Keep unsafe SQL, shell, executable object loading and code construction despite uncertain reachability. Account for genuine medium-impact deferred relationships; do not make occurrence coverage a target. |
| **Comprehensive** | Review every admitted plausible medium-or-higher issue within scope, including weaker consequential leads and relevant build/dependency/generated lanes. Ordinary low-effect observations remain context, not pending verdict jobs. |

Pre-assessment must state the review scope before building bundles. Its inputs
are the source tree (manifests, framework configuration, entrypoints, routes,
and relevant files), the Mehscan inventory, and same-fingerprint review history.
Output a compact stack/deployment summary, a source-backed map of entrypoints,
dispatch and access boundaries, and a heat map of inventory concentrations by
capability/CWE, evidence strength, and component. A hot count shows review
cost or concentration, not risk by itself. If a consequential source-observed
operation has no inventory ID, record a coverage lead separately; do not
invent a scanner finding. Use observed pilot yield and known
shared controls to adjust rank; cross-repository lessons are hypotheses, not
verdicts. Then rank **in now**, **conditional after preview**, and **deferred**
lanes. Give each lane a selection test, reason, and rough count. Account for
the whole inventory without claiming that an unreviewed candidate is safe.
Do not use an arbitrary pilot size as the scope.
An output sink may expose stored lower-trust data without a direct request
marker; do not defer all output sinks on that basis. A user can stop after any chunk
without losing completed work.

Value scope is complete when every relevant surface lane has been inspected,
no ready lane has an unreviewed distinct security relationship, and each
deferred group has a source-backed reason. Counts alone do not prove this:
record which components, producers, operations, and controls were sampled and
what remains uncertain. A few safe reviews or an unexamined inventory are not
evidence that nothing valuable remains. If work stops sooner, call it a partial
Value review and retain a concrete resume lane; do not describe the repo as
free of issues. An unresolved review must name its decision-changing
missing fact. Report reviewed, deferred, and unselected counts and coverage;
do not call this comprehensive or clean. Reopen scope if a route, control, or
actionable finding changes the map. If comprehensive review was requested,
keep that scope unless the user changes it.

Within any mode, mix components, capabilities, producers, and destinations
rather than taking the first IDs in file order. Before selecting a neighboring
ID in a previously reviewed helper, ask whether it tests a distinct caller,
operand, control, or effect; otherwise prefer a different relationship. For a
large queue, preview a few plausible IDs with a
small `source` read around each inventory location before building bundles.
This quick check can reveal a generic wrapper, a nearby control, or a different
operation than the capability label suggests. Use it to order work and test
smart-scope eligibility, not to assign a verdict or silently remove an ID from
the inventory. Choose the next
few exact IDs, then run:

Each inventory ID already has the full source-root-relative file path and line.
For sink-only cases, use that path to distinguish an entrypoint or handler from
a bootstrap file, template, shipped library, or test, then inspect the exact
operand. A file include also has a *target path expression*; do not confuse it
with the path of the file containing the sink. A fixed-looking target, a path
rooted under a plugin directory, and a request-selected target merit different
priority. For writes, distinguish a final destination from temporary staging
or cleanup before materializing a bundle. Neither a path role nor an operand shape
is a verdict without tracing its producer and controls.

`mehscan investigate review-bundles ROOT --inventory RUN/inventory --review-ids ID,ID --output RUN/chunk-N`

Keep chunks small enough to read and research independently. The generated
manifest covers **only those IDs**; the inventory is the complete admitted
queue. Do not load every request into context. Use the normal bundle workflow
and a journal named for the ID that prompts each query. For multi-ID chunks,
follow [shared-pattern review](pattern-sweep.md): reuse an inspected source
fact without re-querying it for each ID, but verify each exact operation and
operand before its verdict.
For simultaneous source previews or worker reviews, use a separate journal
file per ID or worker; never append concurrently to one journal file.

## Keep the big picture visible

Create `RUN/review-plan.md` after inventory and read it first on every resumed
run. Put this short status at the top, then keep any detailed map below it:

| Field | Record |
| --- | --- |
| Goal and scope | User's objective, mode, included/conditional/deferred selection tests, any explicit limit, source root and fingerprint. |
| Big picture | Stack/deployment limits, source-backed attack-surface map, total admitted IDs, coverage limits, compact capability/CWE/strength/component heat map, important gaps, and observed yield. |
| Progress | Prior same-fingerprint verdicts, newly selected, finalized (`issue` / `not_issue` / `needs_review`), in progress, deferred, and still unselected counts; name the owner of active ID groups. |
| Ranked queue | A few category/component lanes tagged in-now, conditional, or deferred, with rank, status, rough remaining scope, next selection test, and reason. Include follow-ups separately when their missing fact differs from unselected work. |
| Stop condition | What completes the requested scope, or why work is paused and how to resume. |

Use `ready`, `active`, `sampled`, `waiting`, and `deprioritized` as working
statuses, not verdicts. Rank by plausible impact, evidence strength, component
exposure, and observed yield; volume alone does not set priority. Keep the
table small by grouping related IDs, usually by capability/CWE and component.
Show a sample count as a sample, not as completion of the lane. Mark a
follow-up `waiting` when the needed fact is outside the available source and
move to another ready lane. A newly found lead can enter the queue without
being misrepresented as a scanner finding. The next reviewer should be able
to choose a bounded chunk from the table without guessing which prior lead
was meant.

Update the status and queue after inventory, after each chunk, and before a
handoff or final answer. Revise ranks when research reveals a shared control,
different runtime role, or poor yield. `needs_review` counts as a completed
investigation only when it identifies the decision-changing unavailable fact.
The CLI's `work.complete` describes one selected chunk; use this ledger for
whole-repository progress.

In auto mode, carry out the next authorized action without a confirmation loop.
Tell the user the big picture and next step after the pilot and at meaningful
chunk checkpoints, using observed work to describe cost rather than inventing
an ETA. If the user has not specified exhaustive scope, continue the stated
smart or focused plan and label the remainder out of scope. If the user
has requested exhaustive scope, do not narrow it without their direction.
At any stop, leave at least one ready lane or state why the queue is waiting,
so another agent or the user can resume without rescanning or guessing.

For parallel work, give each worker the source fingerprint, exact assigned
IDs, relevant component hypothesis, request paths, and response destination.
Each worker finalizes its own IDs and reports unresolved facts. The coordinator
checks for missing or overlapping IDs, updates the shared plan, and chooses the
next assignments. Do not use a worker's verdict to close a neighboring ID.
Current Mehscan summaries and reports are chunk-scoped; a complete repository
result needs an explicit cross-chunk accounting step.

For smart or focused work, report the selected scope and the admitted
work left outside it. For comprehensive work, continue until every admitted ID
has a verdict, or name the remaining IDs and why work stopped. Do not equate
one chunk or a capped manifest with a whole-repository assessment.

## Follow up on reviewer-origin leads

The report's `reviewer_origin_leads` are source-backed questions found beside
admitted IDs, not scanner findings. Put a consequential lead in the ranked plan
with its originating review ID, exact path/line, question, and `unreviewed`
status; group obvious repeats. Choose it like any other Value work when its
potential effect and available evidence justify the time. Its source location
is the starting point, not a substitute for tracing the actor, input, control,
and effect with journaled Mehscan queries.

Record the independent follow-up in `RUN/lead-reviews.md`: originating ID and
question, `issue` / `not_issue` / `needs_review`, exact cited source locations,
the decision-changing blocker if any, and the query journal path. Mark the
plan row done or waiting. Do not change the originating scanner verdict, count
this as an admitted ID, or claim it as a validated Mehscan finding. A confirmed
lead is a separately reported source finding; an unresolved lead stays in the
queue. Recheck for a matching admitted ID before calling the lead new coverage
or spending a second review on the same operation: search the full
same-fingerprint inventory, not only the current selected chunk. If an ID
exists, queue that exact ID and keep the original verdict separate.
