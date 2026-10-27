# Experimental review workspace

`scripts/review_workspace.py` implements the first working-state slice of the
[workspace plan](review-workspace-plan.md). It is an operator/controller script,
separate from the ordinary worker and provider adapter. It launches no model and
performs no native admission. Its output always says `native_admission: false`.

The implemented slice supports persistent source evidence, scoped reviewer
propositions, caller-specific applicability, deciding questions, partial working
drafts, work splitting, bounded context views, explicit session replacement, call
reservations and usage records. It uses Python's standard-library SQLite support;
no additional dependency is required.

The [common source-channel slice AF](experiments/review-workspace-source-channel-results.md)
adds `--source-profile` to native review and workspace initialization. The same
source-only manifest binds exact bundle IDs, inventory/repository, file hashes and
ranges, with eight explicit windows/64 KiB per target. It remains separate from
the ordinary four-window automatic policy-lead default. See
[worker usage and schema](review-worker.md). Profiles do not transfer judgments or
caller applicability; native review maximum stays 20.

Actual packets pass coverage/equality across Directus deletion, Juice Shop checkout
and SQL. The subsequent 17-call live study remains incomplete: workspace Sol and
Terra each return two unknowns; native's filter correction works, followed by a
query-batch rejection later traced to inconsistent advertised versus aggregate
allowances. The experimental comparison harness now clamps the offered query
units to both ledgers without refunding rejected batches. See the
[AG diagnostic](experiments/review-workspace-retrieval-diagnostic-results.md).
Terra retains the storage/hook condition; Sol saves
it in a proposition but omits it from final answers. This establishes transport,
not faster or source-complete review. The
[current plan](review-workspace-plan.md) targets package fidelity and selective
shared investigation; deeper contract reuse still needs a demonstrated consumer
population. AG does not justify automatic helper expansion across all reviews.

Lookup results now use atomic source/receipt publication. The controller stages
captured source and its native receipt in one SQLite transaction, checks the bound
source/runtime/owner before commit, then publishes both together. This replaces
the two full native checks around separately persisted source and receipt. The
freshness callback also runs on idempotent publication replay. Other controller
and paid-inference freshness checks remain in place; no cross-turn freshness cache
is introduced.

Query reservations and received-result byte observations commit separately before
publication. A stale/invalid result leaves its query units and observed bytes
charged, without making its new evidence or completed receipt available. Successful
publication does not charge those bytes again; reuse still counts each received
result. Hashing the staged source expectation avoids duplicating its text in the
bounded action. These are controller changes; the model action schema and native
admission policy are unchanged. This does not resolve the remaining review-quality
or caller-applicability gap.

Routine file/directory mismatches and conflicting `path`/`path_prefix` filters now
return `lookup_feedback` receipts in
the experimental workspace. The original query and deciding question are retained;
the rejected query executes no native command and supplies no source evidence.
Corrections list only arguments actually offered by that tool. The reviewer must
explicitly correct its next request; no filter is silently broadened or renamed.
Valid independent requests in the same fully prevalidated batch still execute.

Feedback consumes the offered query units and received JSON bytes, and each model
turn retains its paid usage. It creates no additional model slots or automatic
provider retry. Question closure still requires source proof. Path escapes,
unsupported arguments/limits, source/runtime/owner changes and unknown paid usage
remain outside this narrow recovery path and are checked before classifying a
recoverable filter conflict. Ordinary review now recognizes the same typed error
through its existing single protocol-correction path. Its rejected batch executes
no sibling lookup; a repeated mistake still stops. This differs from workspace's
per-query feedback receipts and grants no extra model or query allowance.

The [offline publication comparison](experiments/review-workspace-publication-results.md)
now verifies this slice on the pinned Directus source: two fresh pairs, 22 versus
18 native checks, mean two-turn execution 13.309 versus 11.202 seconds, identical
captured source/lookups/query spending, and zero real model calls. All 109 workspace
tests pass. This is a controller timing result, not a live review-quality recovery.

Native provider packets now retain the selected card's operand facts, explicit
relationship, observed/open decision facts, nearby/application locations and
truncation information. Related native contracts are included once for the active
claims. These scanner observations remain leads, not verified caller applicability
or a mandatory checklist. The native catalog digest is part of the workspace
runtime binding, so altered catalog data is rejected; use fresh workspaces rather
than resuming older experimental stores under this code.

An answered deciding question now keeps its latest conclusion and cited source
visible while its own claim remains active. Full attempts/lookup history stay in
storage, and answers do not transfer to another caller merely through shared
implementation. No extra proposition action or new model fields are required.
Changing an answer reactivates its drafted consumers; a new deciding lookup also
reopens a resolved question without refunding prior spending. Native bundle closure
cannot use an older settled verdict while its deciding question is open. This
preserves known facts and unresolved relationships separately, but still relies on
the reviewer to establish that a cited fact actually answers the question.

The [context/state verification](experiments/review-workspace-basis-results.md)
passes 118 workspace tests and a fresh six-claim native-packet audit with identical
initial source and zero real provider calls. These are delivery/state guarantees;
the next step is a diverse bounded live quality comparison before more scaffolding
or the still-unreviewed mixed main wave.

The [earlier live comparison and Terra 6.1 medium run](experiments/review-workspace-context-results.md)
used twenty observed calls but both workspace studies stopped on invalid directory
values in file filters. Terra finalized canonical logout as a scoped negative and
kept SAML authorization unresolved, with a separate local-revocation lead. The
frozen expected SAML issue has a claim-scope ambiguity and cannot establish a model
ranking from verdict agreement. Both studies remain closed.

The [aligned feedback comparison X](experiments/review-workspace-feedback-results.md)
has since run: 34 observed calls, four Sol workspace verdicts and three Terra
workspace verdicts. Sol omits the predeclared effective sanitizer-configuration
check; Terra stops on conflicting filters after two delivered feedback receipts.
This is partial confirmation, not full source-quality acceptance or demonstrated
whole-package savings. The subsequent conflict-feedback extension is offline only;
X remains closed. Current offline checks cover 129 workspace tests plus seven
common-validator checks. No mixed main wave or full-app review has run.

The [surgical correction plan](experiments/review-workspace-surgical-plan.md) retains
the three supported cases and local Directus evidence. Existing state can reopen
one claim while preserving sibling drafts, answered local facts, source and paid
work; a native-bound regression checks that path through feedback and correction.
The [Directus follow-up Z](experiments/review-workspace-directus-followup-results.md)
now completes directory-error recovery in Terra and assisted shared-configuration
closure in Sol, with eight observed calls and no new runtime/guidance change. The
root version catalog remains uninspected by those reviewers; the full original
profile is not retroactively passed. Retain the completed mechanisms and other
three cases. Next test a small new related-claim contrast with available source
metadata, rather than repeating the unchanged Directus case. X's original gate
remains unchanged.

The [shared-policy contrast AA](experiments/review-workspace-policy-contrast-results.md)
has now run: both workspace models retrieve shared helpers once, keep configuration
conditions explicit, close two local claims independently and continue only the
external claim. Six local case/arm outcomes have supported mechanisms. The external
fixture has a binding defect and is corrected only in an unrun offline copy; neither
matching labels nor stable native IDs erase that limitation. Preserve the working
state behavior and successful cases for a small real-application comparison.

The [real checkout comparison AB](experiments/review-workspace-checkout-results.md)
then exposes a question-scope guard failure in both workspace models. The offline
correction separates query beneficiaries from immutable question ownership and
permits source-cited per-claim settlement during a narrowed continuation. The
shared question remains open for other claims, and changed answers/lookups/source
still require reconsideration. All 137 workspace tests pass at that closure. The
original study remains closed with its native results and paid traces; AC below
subsequently uses the corrected runtime.

The [carried-source completion AC](experiments/review-workspace-checkout-completion-results.md)
then finishes in two Sol calls/one Terra medium call without errors. Sol verifies
the remaining ownership/policy evidence; Terra's wallet proof is supported while
its basket-policy basis is incomplete. Exact repaired shared-scope paths are not
exercised live in AC. The first-turn boundary is covered before dispatch, with all
138 workspace tests passing. An audited source map and an unrun source-only profile
extension retain the useful work without silently repairing model answers or
discarding earlier costs.

The [Directus deletion comparison AD](experiments/review-workspace-file-delete-results.md)
then retains four unresolved workspace decisions across Sol/Terra medium, while
native stops on a structured file/directory filter error. Both models inspect the
shared deletion control but leave actual HTTP accountability unread; Terra also
preserves the original-storage/post-hook-key condition. Matching uncertainty is
not a completed authorization package. Sixteen observed calls cost 296.335 active
seconds, with no repeated source lines across lookup results within an arm
(excluding prompt replay/navigation). A narrow post-closure fix lets native's
existing single protocol correction recognize the typed filter error. Original
paid results remain closed; source selection and controller overhead remain open.

The [offline source-profile audit AE](experiments/review-workspace-source-profile-audit-results.md)
finds that ordinary preparation drops four of the original eight requested windows
even while cross-arm parity passes. Experiment designs can now declare optional
`required_initial_source` windows by comparison bundle/claim key, with exact ranges
and whole-file hashes. Preparation rejects incomplete delivery and binds its
coverage receipt to the run. This gate supplements parity; it does not establish
caller applicability or security truth. A distinct four-window caller-source
control passes actual packet delivery with zero model attempts. A common explicit
source channel and selection-cost audit remain the next implementation work.

## Initialize outside the source root

Save a trusted experimental seed as `RUN/seed.json`:

```json
{
  "source_root": "C:/authorized/application",
  "binding": {
    "snapshot_id": "EXACT_NATIVE_SNAPSHOT_ID",
    "plan_id": "EXACT_NATIVE_PLAN_ID",
    "runtime_id": "EXACT_NATIVE_RUNTIME_ID"
  },
  "claims": [
    {
      "review_id": "EXACT_SELECTED_NATIVE_REVIEW_ID",
      "property": "Does the selected query bind request values outside SQL grammar?",
      "path": "routes/search.ts",
      "line": 23,
      "bundle_id": "EXACT_ORIGINAL_BUNDLE_ID"
    }
  ],
  "limits": {
    "model_calls": 6,
    "queries": 12,
    "source_bytes": 131072
  }
}
```

These are example ceilings, not a recommended live-run configuration. The seed
must describe the complete selected membership of each original bundle before
its working draft can be handed to native finalization.

```text
python scripts/review_workspace.py init --workspace RUN/workspace.sqlite --seed RUN/seed.json
python scripts/review_workspace.py status --workspace RUN/workspace.sqlite --seed RUN/seed.json
```

Initialization publishes a complete database without replacing an existing one.
Opening a workspace checks its stored source/plan/runtime binding against the
supplied binding. The selected claims and limits are immutable after creation;
editing the seed does not change stored claims or replenish budgets.

The current seed API trusts the controller to supply native identifiers. It does
not verify their authenticity, the full source snapshot or native bundle
membership. The next integration step must obtain and validate this data through
the existing native work package and source checks. Do not use this script's
binding check as a substitute for native validation.

## Apply one explicit action

Save a source-preparation action as `RUN/action.json`:

```json
{
  "kind": "source",
  "path": "routes/search.ts",
  "start_line": 19,
  "end_line": 25,
  "review_id": "EXACT_SELECTED_NATIVE_REVIEW_ID"
}
```

```text
python scripts/review_workspace.py apply --workspace RUN/workspace.sqlite --seed RUN/seed.json --action RUN/action.json --operation-key capture-search-1 --expected-revision 0
```

The action and its receipt commit atomically. A competing writer or stale
revision is rejected. Retrying the same operation key with the same original
revision and action returns its original receipt with `replayed: true`; different
input under that key is rejected. An old receipt's revision is not the current
workspace revision; read status before starting different work.

Source preparation reads at most 400 inclusive lines from an at-most-8-MiB UTF-8
file. It stores a whole-file hash, the exact source window, completeness and the
first prompting claim. Identical windows reuse that evidence identity. They do
not fabricate per-claim native query journals. Changed captured files prevent
further reuse under the old workspace binding. This checks cited files, not the
entire application snapshot.

## Actions and their boundaries

Every action has a `kind` and the fields below. Unknown action fields are rejected.
Draft results retain the native brief-result payload for later finalization.

| Kind | Fields besides `kind` | Effect |
| --- | --- | --- |
| `source` | `path`, `start_line`, `end_line`, `review_id` | Capture controller preparation source; return `evidence_id` |
| `proposition` | `proposition_id`, `statement`, `scope`, `conditions`, `exclusions`, `evidence` | Append a source-backed interpretation revision; return its revision |
| `dispute` | `proposition_id`, `reason` | Dispute its latest revision and flag recorded consumers |
| `applicability` | `review_id`, `proposition_id`, `proposition_revision`, `evidence`, `reason` | Record a caller-specific interpretation; return `applicability_id` |
| `question` | `question_id`, `review_ids`, `question` | Add a deciding question; reopen drafted consumers for reconsideration |
| `answer` | `question_id`, `status`, `reason`, `evidence` | Record an investigation attempt; status is `open`, `answered` or `blocked` |
| `split` | `work_id`, `new_work_id`, `review_ids`, `strategy` | Move claims into a child work item without a new budget |
| `focus` | `work_id`, `evidence_ids`, `proposition_ids` | Select evidence and propositions for the next context |
| `session` | `work_id`, `parent_session`, `max_bytes` | Freeze a bounded working packet and retire previous sessions for this work item |
| `attach_session` | `session_id`, `artifacts` | Bind provider configuration and packet/task hashes to the session |
| `start_call` | `session_id` | Reserve one aggregate model call before dispatch; return `call_id` |
| `finish_call` | `call_id`, `usage` | Record observed counters once for that call |
| `reserve_queries` | `queries` | Reserve positive query units before external lookup dispatch |
| `draft` | `result`, `applicability`; optional `propositions`, controller-derived `resolved_questions` | Save one claim's working brief result, dependency revisions and source-backed resolution scope |
| `draft_batch` | `drafts` | Apply an array of draft actions atomically |

`evidence`, `evidence_ids`, `proposition_ids`, `review_ids` and `applicability` are
arrays of their corresponding stored IDs. Text fields in propositions and
applicability are required and bounded. Express an empty condition explicitly,
for example `"none established"`; absence of a condition is not inferred safety.

An answered question requires source evidence. Retrieval alone leaves its status
unchanged. An unanswered deciding relationship for that claim prevents an
`issue`/`not_issue` draft; use `needs_review` with explicit checks. In v2 the
controller can derive per-claim `resolved_questions` when a source-cited settled
decision accompanies a shared question's continuation for other claims. It does
not mark the entire question answered or settle any other owner. The model action
schema is unchanged; this is controller bookkeeping. `settled_review_ids` exposes
that scope in the provider view and retains its source proof through focus changes.
Other open questions still block closure, and shared answer revisions or deciding
lookups involving settled claims reactivate affected drafts. Source binding does
not certify the truth of an answer, proposition, applicability judgment or verdict.

`usage` contains `input_tokens`, `cached_input_tokens`, `output_tokens` and
`elapsed_ms`. Each is a nonnegative integer or `null` when unavailable. Cached
input cannot exceed reported total input. A reserved call without a usage record
remains unobserved across restarts. A total is `null` if any contributing call's
counter is unknown; missing usage never becomes zero. Elapsed time here sums
observed call durations and is not application wall time.

Calls, query reservations and unique captured source bytes share one workspace
allowance across sessions and splits. The state module does not enforce token,
spend, wall-time or per-work-item ceilings, and does not observe provider calls
itself. The native bridge below adds bounded provider dispatch and observed-token
and elapsed-time gates. Session creation alone neither dispatches nor charges a
model call.

## Reuse knowledge in a bounded fresh context

After capturing a helper and a caller, record a scoped proposition about the
helper. For example: a middleware helper replaces `body.UserId` with the
authenticated subject; route parameters remain unconstrained.

Use `focus` to select that proposition and the next caller's source before
applicability is established. Record applicability only after examining that
caller. The second caller may consume a route parameter and receive an unsafe
verdict while the first caller consumes the bound body field and receives a safe
verdict. The shared helper interpretation does not transfer either decision.

```text
python scripts/review_workspace.py knowledge --workspace RUN/workspace.sqlite --seed RUN/seed.json --proposition-id body-owner
python scripts/review_workspace.py view --workspace RUN/workspace.sqlite --seed RUN/seed.json --work-id initial --max-bytes 32768
```

Views contain active claims, selected latest propositions, recorded applicability,
relevant source and pending deciding questions. Drafted claims leave the active
view unless flagged for reconsideration. Draft history and abandoned evidence
remain in storage. Selected source is rechecked; an oversized view fails with a
request to split work or select smaller evidence. Nothing is silently truncated.
The limit is serialized UTF-8 bytes, not a token estimate or model context size.

Propositions are explicitly identified reviewer interpretations inside evidence
data. They are never trusted guidance. Retrieval initially uses explicit IDs;
symbol-based retrieval, semantic search, rule-specific scheduling and AI grouping
are later work.

A `session` action stores the packet and digest under a new identity. A parent
must belong to the same work item. A `start_call` action rejects retired sessions
or a session whose working evidence/claims have changed. Usage and reservations
can grow without changing the immutable packet. Provider integrations must supply
current budgets at dispatch and retain the existing packet/schema checks. The
native bridge currently creates single-turn checkpoints, each with a fresh
provider conversation.

## Export a complete working draft

```text
python scripts/review_workspace.py bundle-draft --workspace RUN/workspace.sqlite --seed RUN/seed.json --bundle-id EXACT_ORIGINAL_BUNDLE_ID
```

The CLI wraps the draft in `result` and marks it `native_admission: false`.
Extract that payload for subsequent native finalization; the wrapper itself is
not a finalizer input. Export refuses missing drafts or consumers awaiting
reconsideration, and checks that cited source remains unchanged. It does not
validate all native response fields or prove that seed membership matches a real
bundle. The original native finalizer must validate the complete response.

Revising or disputing a proposition flags every recorded applicability consumer.
It preserves proposition history and old working drafts. Clearing a flag requires
a new draft; stale or foreign applicability cannot support it. Native history
and supersession remain the responsibility of the existing state commands.

### Reviewer-visible package

The read-only `review-package` command projects complete original bundles into
`mehscanWorkspaceReviewPackage/v1`. It contains each unchanged claim result and
property, exact linked proposition revisions with conditions/exclusions, recorded
applicability, current deciding questions and one shared captured-source catalog.

```powershell
python scripts/review_workspace.py review-package --workspace RUN/workspace.sqlite --seed RUN/seed.json
python scripts/review_workspace.py review-package --workspace RUN/workspace.sqlite --seed RUN/seed.json --format markdown
```

By default all selected bundles must be complete. `--bundle-id EXACT_BUNDLE_ID`
exports that complete bundle and explicitly lists omitted workspace claim IDs.
This never permits exporting only part of a native bundle. JSON retains the
standard `native_admission: false` / `result` CLI wrapper; Markdown is a human
view of the same package. The package is not a native finalizer input.

Each note link says either `caller_applicability_recorded` or `context_only`.
The former records a reviewer judgment, not controller-certified applicability;
the latter records context exposure without asserting applicability. Unlinked
propositions are excluded. A note's exclusions do not automatically become native
checks or blockers and do not change the verdict. A question resolved only for one
claim remains visibly distinct from its global/shared status.

Export checks source hashes, dependencies and reconsideration; stale/disputed
propositions or incomplete bundles are rejected. It reads one workspace revision
without changing draft history, usage or reservations. Source appears once in a
shared catalog, with IDs and whole-file hashes; the Markdown view links note and
question evidence to those excerpts. Literal reviewer/source text is fenced.
No new inference, navigation, stored fact or model action is required.

Native-bound `finalize` writes `review-package.json` and `review-package.md`
beside the original `draft.json` and `response.json`. `validated.json` binds their
hashes alongside the native response. Only the brief native results are passed
to the finalizer. The experimental batch comparison also writes an aggregate pair
beside `treatment/findings.json`, checks its draft identities against the finalized
bundles and returns the package paths in its result.

The standalone command verifies the supplied stored binding and cited source; it
does not perform the bridge's full native owner/runtime checks. An export made
from archival state is a newly derived view, not runtime resumption, new native
validation or a repaired security conclusion. The package preserves judgments and
qualifications; it does not establish that they are true or complete.

## Native-bound checkpoint bridge

`scripts/review_workspace_bridge.py` connects the workspace to the current native
state work command, native bundle generation and finalizer, and bundled Codex
adapter. It remains experimental and separate from ordinary worker scheduling.

The bridge initializes from a live native work package and an ownership receipt.
It checks full native source freshness, current plan/parents/facts, runtime,
configured provider and ownership before and after guarded work. It shares the
ordinary controller's stream lock. Native bundle generation establishes the
selected membership and source-backed questions; the bridge preserves those
original bundle boundaries through finalization. It prepares native sweep source
once as controller evidence without fabricating source-query journal activity.

Freeze an experiment file containing these fields before initialization:

```json
{
  "limits": {"model_calls": 6, "queries": 12, "source_bytes": 131072},
  "experiment": {
    "max_input_tokens": 200000,
    "max_output_tokens": 20000,
    "max_elapsed_seconds": 600,
    "context_max_bytes": 32768
  }
}
```

These are illustrative values. Choose the actual ceiling from the representative
slice and baseline. Aggregate call/query/source allowances cannot exceed the sum
of selected claims' bound native allowances. Provider, source, selected work,
implementation hashes and experiment settings bind the workspace. Changing
experiment ceilings requires a new workspace rather than editing its metadata.
The file freezes executable limits; evaluator labels, baseline provenance and
the rest of the experiment design remain in the separate evaluation manifest.
`bridge-trace.jsonl` records operation wall time, native-command time and success
or failure without command arguments or ownership credentials. Per-session
provider metrics retain actual counters and prompt bytes. Operation times include
nested native work; do not add them together as independent durations.

For PowerShell, collect the common arguments in a task-specific variable:

```powershell
$workspaceBridgeArgs = @(
  '--scanner', 'C:/trusted/mehscan.exe',
  '--source-root', 'C:/authorized/application',
  '--inventory', 'C:/review/inventory',
  '--store', 'C:/private/review-state',
  '--stream', 'local-review',
  '--claim', 'C:/private/claim.json',
  '--work-package', 'C:/review/work.json',
  '--skill-root', 'C:/trusted/mehscan-security',
  '--provider-contract', 'C:/private/provider-contract.json',
  '--directory', 'C:/review/workspace'
)
python scripts/review_workspace_bridge.py init @workspaceBridgeArgs --experiment C:/review/experiment.json
python scripts/review_workspace_bridge.py check @workspaceBridgeArgs
```

The native plan must already bind the intended provider contract for provider
dispatch. The ownership receipt, native store, provider configuration,
authentication and private provider sessions stay outside workspace exports.
Initialization exports `seed.json` for using the state CLI with this workspace;
it contains source/claim/budget bindings, never ownership or authentication.

Use the state API to split work, select evidence, retain propositions and record
caller applicability between checkpoints. Then prepare a fresh provider task:

```powershell
python scripts/review_workspace_bridge.py prepare @workspaceBridgeArgs --config C:/private/codex-config.json --work-id initial --operation-key checkpoint-1
```

Preparation launches no model. Its result provides `session_id`. Retrying the
same operation key can finish interrupted preparation and reuses the original
session; changed or retired working contexts cannot be silently resumed.
Context/task/fact files and provider configuration hashes are recorded in the
workspace before dispatch. An altered prepared packet is rejected.

The following explicit command launches the configured model:

```powershell
python scripts/review_workspace_bridge.py review @workspaceBridgeArgs --config C:/private/codex-config.json --session-id SESSION_ID
```

Each checkpoint is currently **one final-only turn over prepared evidence**. It
uses the existing bundled provider schema, common/category guidance and upstream
tool restrictions; source lookups and a simplified model-directed workspace
action protocol are not implemented in this slice. Missing decisive facts remain
`needs_review`. The context limit applies both to the working view and assembled
packet; fixed adapter instructions and wire schemas add overhead measured by
provider metrics. A packet exceeding the limit must be narrowed explicitly.

All propositions presented in a checkpoint are conservatively recorded as draft
dependencies, even without an affirmative caller-applicability record. Revising
one reopens those drafts; presentation does not establish that the proposition
applies or transfer another claim's verdict. Results must cover exactly the active
claim IDs, cite source shown in the checkpoint and commit as one atomic batch.

Call reservations precede dispatch. A completed but rejected reply retains its
reported counters, and native/workspace freshness is checked again before any
draft is saved. A dispatched checkpoint cannot be launched twice. A new context
does not replenish allowances or clear unknown usage. Input/output gates stop
subsequent calls after an observed ceiling is reached; one in-flight turn can
exceed a token ceiling. They are not hard preflight token or spend caps. The
elapsed-time deadline starts at the first reservation and survives context
replacement, including operator idle time between calls.

```powershell
python scripts/review_workspace_bridge.py recover-usage @workspaceBridgeArgs --session-id SESSION_ID
```

Accounting recovery imports a matching saved metric without calling the model.
It can retain costs even when changed source prevents using the answer. If no
metric exists, the call remains unknown and further dispatch is blocked. Automatic
recovery of a completed answer after an interrupted controller write is not yet
implemented; no blind redispatch is permitted.

When all members of an original bundle have working drafts:

```powershell
python scripts/review_workspace_bridge.py finalize @workspaceBridgeArgs --bundle-id ORIGINAL_NATIVE_BUNDLE_FINGERPRINT
```

The bridge assembles the complete original response and invokes the native
finalizer under the current source/runtime/work fences. Successful output says
`native_validated: true` and `native_admission: false`, and includes a response
path plus a validation sidecar. It creates no native state decision, performs no
supersession, and does not complete a pending change pass. Subsequent native
state admission remains a separate milestone. A source/plan change after
validation still requires fresh checks at eventual admission.

## Model-directed workspace actions

Set `experiment.protocol` to `"workspace-actions-v2"` in the frozen experiment
file to use the compact action contract. Omit it, or use `"checkpoint"`, to retain
the earlier final-only checkpoint contract. Mode is immutable within a workspace.
The action pilot currently requires fresh native work without inherited native
decisions, pending questions or evidence updates; those are rejected rather than
silently omitted. Changed-path review and native state admission remain separate.

The new mode uses `skills/mehscan-security/scripts/workspace_protocol.py` through
the bundled adapter. It replaces the ordinary progress/routing response envelope
and initial category-manual injection with a short review contract. Detailed
guidance remains available through allowlisted lookup names. Existing host-tool
restrictions, provider binding, usage recording and source/runtime fences apply.
The module is on the release allowlist because the adapter imports it; the
workspace controller scripts themselves remain experimental.

Each model response has exactly three arrays:

- `updates`: changed propositions, caller applicability, new questions or question answers,
  disputes, or optional focus selection for the next context.
- `lookups`: deciding questions, their affected active IDs and independent typed
  queries. The controller executes them after validating the entire response.
- `decisions`: scoped decisions for any subset of active claims, without native
  `checks` or `blockers` fields.

There is no `working_chain`, running progress inventory, routing table or
mandatory whole-operation assessment. A response may finish one claim and
investigate another. It cannot decide a claim while requesting its deciding
evidence in the same response.

Version 2 makes outstanding-work formatting controller-owned. A `needs_review`
decision requires an unresolved saved question for that exact claim. Create it
with a `question` update if a lookup did not already create it; an `answer` update
records whether it is open, answered or blocked and why. The controller renders
native `checks` from unresolved question text and native blockers from blocked
question reasons, including updates in the same atomic response. Settled
decisions cannot close while a deciding question remains unresolved. Overlong
or excessive native checks are rejected rather than silently truncated.

The current adapter rejects the old version and old decision fields. Earlier
experiments retain their frozen version-1 packages and original answers; create
a fresh native-bound workspace rather than rebinding a saved session.

For example, a lookup request can be:

```json
{
  "updates": [],
  "lookups": [{
    "question_id": "owner-guard-contract",
    "review_ids": ["EXACT_ACTIVE_NATIVE_ID"],
    "question": "Does the called guard reject an owner mismatch before mutation?",
    "queries": [{
      "tool": "definition",
      "review_id": "EXACT_ACTIVE_NATIVE_ID",
      "purpose": "Read the deciding guard implementation",
      "arguments": {"name": "guardOwner", "path": "src/guards.ts", "limit": 20}
    }]
  }],
  "decisions": []
}
```

Available tools are current `source`, `outline`, `symbol`, `definition`,
`references`, `paths`, `guidance`, and workspace `knowledge`. Pinned-base lookup
is not part of this current-source pilot. `knowledge` takes `{"name":"text"}`
and retrieves at most eight propositions whose ID, scope or statement contains
that literal text, without assuming semantic or caller equivalence. Knowledge
is evaluated against the latest revision rather than returning a cached old
interpretation. Its source is freshness checked.

`scripts/review_workspace_actions.py` validates scope, aliases, query arguments,
aggregate allowance, references and every interpretation update before executing
lookups. Updates and partial decisions commit in one transaction; an invalid
later action cannot leave earlier judgments saved. Model actions cannot set
budgets, reserve calls, read arbitrary host files, alter native selection, or
admit native decisions.

Each lookup is reserved and recorded against its deciding question before I/O.
It retains the exact request, result, original attribution, returned evidence,
native query count and any reuse origin. Returned source enters the next
context's evidence. Navigation results remain navigation; retrieved source does
not automatically answer the question. The model must answer it explicitly or
preserve its precise gap. An interrupted lookup remains a visible reservation
without a result; it never establishes absence or silently gains a free retry.

A follow-up may reuse a visible question ID with narrower lookup wording when
its claim scope is unchanged. The original deciding question and answer history
remain unchanged and open until explicitly answered. Each reservation and
receipt preserves its own `requested_question`, including reused results. This
does not permit moving an ID to another claim or continuing an unseen question.

When independent work reuses a locally declared question or proposition name,
the controller scopes an unseen collision to that work and maps references
consistently. Existing visible knowledge retains its revision rules; unseen
foreign knowledge cannot be answered, revised or applied implicitly. Category
guidance is delivered only to the work that requested it.

The controller also splits a decision citation spanning several supplied windows
into separate supplied ranges. Any gap must contain only snapshot-verified blank
lines; unseen substantive code and invalid/out-of-file extents are rejected.
The raw paid answer remains unchanged, the canonical draft uses the separate
ranges, and the bridge records the projection. This is citation formatting, not
new reviewer evidence or a changed verdict.

Identical completed reads reuse the existing result, while covered source reads
use prepared bytes. Reuse still consumes the frozen query-unit allowance but
does not fabricate native journal entries. `definition` reserves two query units
for symbol location and its bounded source read. Guidance and knowledge each
reserve one. Actual new native query journals are retained across checkpoints
and supplied to finalization under the original prompting ID.

Proposition and applicability evidence uses the current short source handles.
The next turn sees the saved interpretation and its conditions/exclusions,
selected source, and every retained receipt for each unresolved question. Full
lookup history remains stored. Loading guidance places it in a distinct trusted
guidance section; saved reviewer propositions remain untrusted interpretations.

Use an optional focus update to keep the next context small:

```json
{"kind":"focus","evidence":["source1"],"propositions":["owner-guard-contract"]}
```

This changes the active view, not the evidence store. Newly retrieved evidence
is added to that view, and selected propositions bring their supporting source.
No silent truncation or automatic safe conclusion follows from omitted context.
An oversized context still requires explicit narrowing or work splitting.

Continue with another `prepare`/`review` pair using a new operation key, optionally
linking `--parent-session` for the same work item. Each pair starts a fresh
provider context from saved state. No unbounded automatic model loop is added.
Partial decisions leave the active claim list but remain unadmitted drafts until
their complete original native bundle is finalized.

The first comparison design is pinned in
[review-workspace-pilot.json](experiments/review-workspace-pilot.json). It selects
12 Juice Shop claims: seven source-audited positive sites, four local clean
controls and one unresolved generated-resource relationship. Their saved
treatment baseline used 45 calls, 1,267,942 input tokens and 24,364 output tokens.
These historical figures are reference measurements, not proof of savings.

The comparison uses fresh ordinary singleton reviews versus workspace-action
singletons with shared knowledge, with model/effort, source, initial evidence,
aggregate ceilings and concurrency matched. The design is frozen; exact current
runtime/provider hashes and initial-evidence equality receipts must be bound in
an immutable run manifest before live launch. Evaluator labels and old answers
must never enter model context. The first live attempt has now stopped; see the
[pilot results and stop decision](experiments/review-workspace-pilot-results.md).
The ordinary control completed 12 claims; workspace validated one before a
claim timeout with unknown provider usage. The [revised next-work
plan](experiments/review-workspace-next-plan.md) separates a bounded completion
diagnostic, actual producer/consumer reuse and a small SQL grouping experiment.
A grouping diagnostic requires reliable execution; broad expansion still
requires the mixed-package quality and efficiency gates.

The provisional unresolved label is not a requirement to preserve an old
verdict: newly decisive source may settle it. What must survive is any genuinely
remaining relationship and its scope. Supported mechanisms must be preserved;
fewer findings, forced dismissals or shorter responses do not satisfy the gate.

## Bounded route-source preparation

`scripts/review_workspace_routes.py` can prepare route-shaped source at native
reference locations before provider dispatch. Call `attach_route_context` under
the native controller lock with a snapshot-bound receipt containing `query` and
`result`; reserve and retain the native locator execution separately. The helper
captures actual source and focuses it into the work item without creating
propositions, applicability or decisions. The returned preparation receipt
records source bytes and limits. Limits are persisted as controller-owned
`preparation_limits` actions and appear in fresh packets, including after a split.

The helper is limited to 64 reference sites, eight windows and 8 KiB. It is a
textual locator, not a general route resolver or proof of authorization. Dynamic
registration and incomplete native results remain explicit. This is opt-in
experimental preparation; it does not make exhaustive caller discovery part of
every rule. See the [offline packet results](experiments/review-workspace-v2-offline-results.md).

## Current validation and next gate

Run the dedicated tests with:

```text
python -m unittest discover -s tests/review_worker -p "test_workspace*.py" -v
```

Tests cover persistence, atomic rollback and publication, competing writers,
idempotent replay, binding mismatches, source freshness, separate safe/unsafe
caller drafts, unresolved questions, proposition revisions, dependency reopening,
work splitting, bounded context selection, call budgets and unknown usage across
session replacement. The CLI is also exercised across independent processes.

Bridge tests additionally use the actual native CLI and bundled adapter with a
deterministic launcher: fresh sessions reuse a proposition, preserve original
bundle membership and produce a source-validated native response. Tests cover
tampered work/packets, unknown calls, preparation retries, observed-token gates,
frozen experiment settings, paid stale answers and retained usage after rejection.

Action tests additionally exercise partial closure, a source/navigation/guidance
batch, saving a learned proposition, caller applicability, and retrieval from
another work item through four fresh bundled-adapter sessions. Native
finalization preserves the complete original bundle and actual per-ID journals.
Invalid lookup paths retain paid provider usage while executing no query and
saving no earlier decision.

These tests establish the integration path, not native state admission, model
judgment quality or live token savings. The experimental scripts are not yet
wired into ordinary review. The later context-preservation defect is now fixed:
distinct navigation receipts under one question reach the next model view.
Restart guards and incomplete-call accounting are verified. A [single login
smoke check](experiments/review-workspace-smoke-results.md) completed with observed
usage and passed offline action/source audit. The [bounded notebook handoff](experiments/review-workspace-notebook-results.md)
is now implemented and tested. The live wallet producer retained an unread
route/middleware question and saved no fact; neither consumer arm ran. [Offline route preparation and version-2
question rendering](experiments/review-workspace-v2-offline-results.md) are now
implemented and verified. A [producer-only test](experiments/review-workspace-producer-v2-results.md)
then completed in two calls and exported one bounded wallet-scoped note. The
[consumer comparison](experiments/review-workspace-consumer-results.md) now shows
safe scope retention and fewer helper queries, but no avoided model turns and
11.70% more input. Both arms retain an unresolved basket effect. That historical
allowance remains exhausted. The user subsequently requested an [expanded
four-arm comparison](experiments/review-workspace-expanded-results.md), now
completed with 121 observed calls and 48 native source-validated dispositions.
It compared operation source preparation, concrete groups and targeted memory
across twelve claims. Groups used 21 calls, versus 35/36 for singleton alternatives
and 29 with a seed; repairs and quality disagreements prevent treating that as
a clean savings estimate. Quality and time govern selection; token-percentage
gates are retired. Controller/skill hashes remain
binding: an earlier workspace cannot silently resume under changed code. The
expanded experiment's controller-only repair uses an explicit isolated runtime
fork, preserves original artifacts and costs, and verifies the deciding context
before replaying an unchanged paid answer; this is not a general migration API.

The subsequent [fresh fixed-controller comparison](experiments/review-workspace-confirmation-results.md)
completed without repairs: 31 singleton versus 21 grouped calls, 24 source-validated
dispositions and no unknown usage/controller errors. SQL/deluxe show uncapped
sharing benefits; basket hit the shared work cap. Both arms retain three unresolved
relationships. Their source leads remain unvalidated questions, not classified
operation findings. The report records that distinction, severity variation,
actual time/usage and the next dependency/mechanism/interactive-CLI work. The
reusable runner is `scripts/review_workspace_comparison.py`; ordinary scheduling
and native bundle defaults remain unchanged.

An opt-in [deterministic work planner](review-workspace-planner.md) now creates
local SQL batches and source-bound same-operation groups from native inventory
and AST/reference evidence. The bridge's `plan` command applies them atomically
to fresh unassigned state. It produces no verdict and invokes no model; ordinary
worker scheduling is unchanged. See the [offline implementation check](experiments/review-workspace-planner-results.md)
for source-binding, abstention and rollback validation. A held-out live reviewer
test, dependency-fact reuse and independent operation mechanism records remain
outstanding.

The next opt-in slice is [shared deciding evidence](review-workspace-evidence.md):
`prepare-evidence` supplies exact helper windows and root-local package metadata
receipts before a fresh reviewer context. Source and dependency records are
stored once with separate consumer questions, source freshness and absent-file
revalidation. The [offline check](experiments/review-workspace-evidence-results.md)
does not establish live savings or dependency effect contracts. Automatic
relevance selection, operation-mechanism records and interactive state navigation
remain outstanding.

The [automatic helper selection milestone](experiments/review-workspace-auto-evidence-results.md)
now connects planner `--prepare-helpers` to atomic deciding-evidence delivery.
It follows explicit relative imports in known registration chains, preserves
arguments/wrapper source and reports unsupported bindings. Offline matched
preparation measures the added source/context and lookup costs; no new live
savings or dependency contract is claimed.

The subsequent [matched native-bucket comparison](experiments/review-workspace-batch-results.md)
completed only its eight-claim safety wave: 32 native versus 30 workspace calls,
with one supported conditional finding unresolved in workspace and slower active
execution despite lower input. The main sixteen/reserved eight claims remain
unreviewed. A lost common API-policy delivery paragraph is restored from the same
bound semantic source and tested offline; live recovery remains unproven.
Trace data also identifies repeated native state/work validation as substantial
controller overhead. The failed study stays closed; native defaults are unchanged.

The [fresh shared-policy regression](experiments/review-workspace-recovery-results.md)
now records partial recovery: five paired claims, 26 observed calls, matching three
findings/one scoped negative/one unknown in each arm. Unsafe and unknown controls
are retained. Workspace emits the conditional SDK finding but omits the caller
binding that native verifies; the full source gate therefore remains unmet. Its
twelve calls take 270.133 active seconds versus native's fourteen/237.113, with
107 state/work validations costing 47.887 seconds. No controller failure, unknown
usage or paid repair occurred. Next address explicit mechanism/applicability state
and equivalent validation boundaries, rather than further unmodified prompt trials.
The sixteen mixed main claims remain unreviewed; both studies are closed.
