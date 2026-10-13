# Local AI review worker

V11 source builds include `scripts/review_worker.py`, a provider-neutral local
controller. It uses the same inventory, bundle finalizer, report importer and
[state journal](review-state.md) as manual review. It does not publish to GitHub.
The advisory Action defaults to native preparation; its optional Value/Comprehensive
mode prepares an active private [review handoff](github-action.md#active-review-handoff-local-integration-preview).
No automatic model launch is enabled in the composite Action.

## Prepare review work

Keep source, trusted tools and review artifacts in separate directories. Create
a pinned Changed inventory with a stable repository namespace, claim a generation
and save its receipt privately. Create a completion template:

```text
mehscan state plan-template --inventory RUN/inventory --source-root ROOT --policy comprehensive --skill-root TRUSTED/mehscan-security
```

The AI worker requires this native runtime-bound plan. The native contract records
the exact executable, trusted skill-package digest, worker protocol and effective
profile limits. Keep the skill outside ROOT. Manual CLI plans without a runtime
remain supported, but the worker rejects them before model execution.

Save the JSON as `RUN/plan.json`. Comprehensive selects every native ID. Value
allows selection, but every other native ID must have an explicit reason in
`deferred_review_ids`. Every changed path starts `unassessed`; an empty native
queue still needs a change pass. Admit the plan and export the work package:

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
{"research":[{"tool":"source","review_id":"EXACT_BUNDLE_ID","arguments":{"path":"src/entry.js","start_line":1,"end_line":20}}]}
```

The next task contains `research.results` with the actual queries and native
outputs, plus remaining budgets. Return either a nonempty research batch or the
normal final draft, never both. Native queries name their prompting ID from this
bundle; change-pass queries use `review_id: null` and are audited separately.
The controller journals newly executed native queries under that ID for finalization. Shared
facts can inform sibling IDs without fabricating a query for each one.

Allowed tools are `source` and `base_source` (`path`, `start_line`, `end_line`), `symbol` (`name`,
optional `path`, `limit`), `references` (`symbol`, optional `path` or `path_prefix`,
`limit`) and `paths` (`name`, optional `limit`). Paths use relative forward-slash
syntax within the authorized root; traversal, Git metadata and symlink escapes
are rejected. Source windows are at most 400 lines and discovery limits at most
100 results. `source` reads current bytes; `base_source` reads the pinned merge base or direct
base, including deleted and renamed old paths. The controller prepares independent
old/new hunk windows and bounded enclosing units rather than always reading the
first 400 lines. Small files carry complete-file evidence; clipping and missing
coverage remain explicit.
References are bounded identifier text matches, not resolved calls; a
`path_prefix` must name a directory. Path discovery uses a literal substring,
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

`source-facts.json` retains actual lookups and original attribution. Repeated
queries reuse results only within the same worker attempt and bound source.
Covered source reads use prepared bytes without inventing native journal activity.
Freshness checks still surround each lookup, including cache hits. No verdict
or fact reuse across revisions is implemented. Metrics distinguish native
execution, preparation reads, pinned-base reads and cache hits.

Adapters may keep one provider session per `conversation_id` and send subsequent
query results as deltas. Resume the exact session, retain the same contract and
schema, and reject changed evidence packets. The controller stays provider neutral;
model authentication and session management belong to the trusted adapter.

Native profile defaults per conversation are Value: 2 research rounds, 8 queries,
128 KiB and 300 seconds; Comprehensive: 3 rounds, 12 queries, 256 KiB and 600 seconds.
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
