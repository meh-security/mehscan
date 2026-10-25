# Mehscan commands

Use the executable and root supplied for the task. `ROOT` is the source
repository, not the directory containing a saved bundle.
Regenerate older inventories with this executable: current admission uses
inventory schema 25. Reuse verdicts only through a source-bound ledger.
Append `--journal JOURNAL.jsonl` to source, outline, references, paths, and
other code-evidence lookups while reviewing a bundle. Bundle listing, cards,
finalization, and validation do not accept `--journal`. Name the journal for
the ID that prompted the query;
Mehscan appends the exact arguments, result or error, and elapsed milliseconds.
Read shared source once and reuse its inspected location for related IDs rather
than issuing the same query into each journal. The response cites only decisive
source; the journals preserve the complete lookup history.

Keep accounting output compact. Save reports, ledgers and large inventory lists
to files; read counts and the relevant selected/reopened IDs, not the expanded
report or whole remaining queue. History roots need their bound
`inventory/overview.json`. Read request paths from the manifest's `bundles`;
top-level JSON files such as `input-binding.json` are not review requests.
Each chunk keeps its matching responses in `CHUNK/responses/REQUEST_FILENAME`.
Keep follow-up chunks under the run; `review-ledger --history RUN` reads nested
manifests too. Inspect its actual `reviewed_count` before reporting coverage.

| Need | Command |
| --- | --- |
| Candidate scan | `mehscan scan ROOT --format candidates` |
| Changed-file scan | `mehscan scan ROOT --changed-from BASE --diff-mode files --format candidates` |
| Changed inventory | `mehscan investigate review-inventory ROOT --changed-from BASE --diff-mode files --output RUN/inventory`; see [Changed review](changed-review.md) for PR/release comparisons, the change pass and freshness. |
| Native repository identity | Add `--repository-key STABLE_ID` at inventory creation (or direct jobs/bundles); for a fork PR use the base product ID and optional `--source-repository-key FORK_ID`. Selected bundles inherit it. Unknown IDs remain unscoped; never invent a platform ID. |
| Review requests | `mehscan investigate review-bundles ROOT --output DIR` |
| Large-repo inventory | `mehscan investigate review-inventory ROOT --output RUN/inventory` |
| Inventory with supplied Roslyn context | `mehscan investigate review-inventory ROOT --output RUN/inventory --csharp-context CONTEXT --csharp-backend BACKEND` |
| Inventory with supplied TS/JS context | `mehscan investigate review-inventory ROOT --output RUN/inventory --typescript-context CONTEXT --typescript-backend SCRIPT` |
| Directed compiler evidence | `mehscan investigate csharp-semantic ROOT --inventory RUN/inventory --evidence-ids ID,ID --context CONTEXT --backend EXE --output FILE` (or `typescript-semantic` / SCRIPT); use card `anchor.id`, not review IDs. |
| Reuse finalized IDs | `mehscan investigate review-ledger --inventory RUN/inventory --history OLD_RUN_ROOT,RUN --output RUN/review-ledger.json` |
| Filter remaining inventory | `mehscan investigate review-inventory-list --inventory RUN/inventory --ledger RUN/review-ledger.json --cwe CWE --limit 50` |
| Value selection / deferred work | Add `--selection value` / `--selection deferred`; Comprehensive uses `--selection all`. Inspect `dependency_review_ids`; rebuild the ledger to reopen unsafe/unresolved dependents (`reopened_count`). Deferrals retain IDs and reasons, not safe verdicts. |
| Filter operand facts | `mehscan investigate review-inventory-list --inventory RUN/inventory --operand-kind fixed_code_relative_path --limit 50` (also `fixed_filesystem_path`, `temporary_filesystem_path`, `immutable_filesystem_operand`, `configured_root_path`, `encoding_call`, `local_operand_origin`, `operand_boundary`, `query_structure`, `process_shell_mode`, `native_operand_declaration`, `local_call_argument`, `prepared_statement_use`, `unclassified`) |
| Shared contract queue | `mehscan investigate review-inventory-list --inventory RUN/inventory --ledger RUN/review-ledger.json --group-by contract --limit 12` (native C# producers: `--operand-kind shared_filesystem_producer` or `shared_outbound_destination`) |
| Reuse inspected facts | `mehscan investigate review-facts ROOT --inventory DIR --facts FILE --contract KEY` (record with `--notes INPUT --output FILE`) |
| Implementation reading queue | `mehscan investigate review-inventory-list --inventory RUN/inventory --selection value --group-by implementation --limit 12` (file/reported symbol/category groups with exact IDs; independent site decisions) |
| Contract members | `mehscan investigate review-inventory-list --inventory RUN/inventory --contract KEY --limit 50` (combine with ledger/component filters) |
| Selected requests | `mehscan investigate review-bundles ROOT --inventory RUN/inventory --ledger RUN/review-ledger.json --review-ids ID,ID --output RUN/chunk-N` |
| Bundle IDs | `mehscan investigate review-bundle-list --bundle REQUEST` |
| One review lead | `mehscan investigate review-card --bundle REQUEST --review-id ID` |
| Related review leads | `mehscan investigate review-sweep --bundle REQUEST` (exact cards with merged source windows) |
| Exact source | `mehscan investigate source ROOT --path FILE --start-line N --end-line M` |
| File outline | `mehscan investigate outline ROOT --path FILE` |
| Find readable paths | `mehscan investigate paths ROOT --name TEXT` |
| Code provenance candidates | `mehscan investigate provenance ROOT --inventory RUN/inventory --limit 200` (inventory scopes header reads/output; `--path-prefix DIR` scopes a component) |
| Enclosing code at known location | `mehscan investigate enclosing-at ROOT --path FILE --line N` |
| Enclosing code from ID only | `mehscan investigate enclosing ROOT --evidence-id ID` |
| Identifier or markup uses | `mehscan investigate references ROOT --symbol NAME --path-prefix DIR --limit 20 --summary true` (per-file locations/previews; `--path FILE` scopes one file; omit summary for full matches) |
| Symbol definitions | `mehscan investigate symbol ROOT --name NAME --path FILE --limit 20` (omit `--path` only when the defining file is unknown) |
| Import uses | `mehscan investigate imports ROOT --name NAME --limit 200` |
| Exact syntax | `mehscan investigate structural ROOT --language LANG --pattern PATTERN --path FILE` |
| Native call syntax | `mehscan investigate native-call-sites ROOT --callee NAME --path FILE` |
| Response shape | `mehscan investigate review-response-schema --bundle REQUEST --output SCHEMA` |
| Finalize brief or full draft | `mehscan investigate review-bundle-finalize --bundle REQUEST --draft DRAFT --journal-dir RUN/journals --output RESPONSE --source-root ROOT` |
| Validate existing response | `mehscan investigate review-bundle-triage --bundle REQUEST --responses RESPONSE --source-root ROOT --summary true` |
| Summarize run | `mehscan investigate review-bundle-summary --run DIR --responses RESPONSES_DIR --source-root ROOT` |
| Final report | `mehscan report --run DIR --responses RESPONSES_DIR --source-root ROOT --format json --output findings.json` |
| Inspect coordinator state | `mehscan state status --store STATE --stream KEY --repository-key ID`; `history` retains immutable all-verdict proof. See [local state](../../../docs/review-state.md) for claims, source-bound admission and explicit supersession. |

Use `--format sarif` or `--format markdown` for those report projections.
For configured SARIF partitions use `--sarif-category mehscan/triaged/pr-delta`
or another stable analysis category; optional `--sarif-run-id attempt-2` identifies
an attempt. Keep reviewer/model, PR number, revision and changing file sets out of
category names. These are artifact exports: complete manifest work does not prove
alert remediation, and Changed/partial reports must not replace an authoritative
baseline. See [the output contract](../../../docs/output-contract.md) for defaults,
category migration and the pending GitHub ingestion acceptance.
Write response drafts as files instead of embedding prose JSON in shell command
strings. If a report needs correction, change the reviewed response and rerun
finalization and `mehscan report`; do not edit the generated report directly.
The response schema and CLI help are authoritative for the installed Mehscan
version. Query results are JSON; inspect all `results`, `truncated`, and
`skipped_files` before concluding that a lookup found nothing.
Save finalized responses as `CHUNK/responses/REQUEST_FILENAME`; `report` reads
that directory and matches each response to its manifest request filename.
Keep `input-binding.json` with copied manifests and requests for historical
verdict reuse. A stale source, native input or review-contract binding requires
fresh review; rebuilding a root overview cannot make an old chunk current.
Regenerate older inventories and ledgers: both now require schema 2.
For C/C++ structural calls use a complete statement such as `memcpy($DEST,
$SRC, $SIZE);`, or use `native-call-sites` for a callee inventory. PHP structural
patterns are parsed as one code construct; do not combine several statements.
Pass structural patterns literally so the shell preserves `$VALUE` and
`$$$ARGS`; in PowerShell use a literal here-string for patterns containing quotes.
`source` reads an exact requested text file under the scan root, including
templates omitted from scan admission; repository ignore rules still apply.
Use a known path directly, or `paths` when the path is unknown. Use a
bare identifier with `symbol --name Shipment`, not `--name "class Shipment"`;
`paths` searches filenames, not method definitions. Read the
applicable engine contract or a repository behavior test when template
interpretation determines the verdict.
`--path` always names one file, never a directory. `outline` and `enclosing-at`
need a file with a supported parser; use `source` for tests or templates that
Mehscan reports as text-only.
`references --path-prefix DIR` searches a component or template directory with
repository ignore rules. Template hits are text locations, not parser or
dataflow evidence. An empty scoped search does not establish runtime absence.
The default brief draft needs only `results` with `review_id`, `decision`,
`confidence`, `summary`, optional `reason`, and optional `evidence` source
ranges (`path`, `start_line`, `end_line`). Finalization reads those exact lines,
fills the full response and journal summary, and validates it. Use
`review-response-schema` only for exceptional full schema 1.3 drafts.
Keep verdict prose concise; [finalization](finish-review.md) describes source
range handling and prose limits.
`paths` is
navigation, not code evidence: read a returned path before citing its contents.
`--source-root` checks that every decisive artifact excerpt occurs in a file
inside that root. It catches paraphrases presented as source text; it cannot
prove that every executed query was recorded.
Changed-scope finalization also requires the saved input binding, matching Git
comparison and current repository source fingerprint. Keep `RUN` outside the
source worktree and regenerate stale runs rather than editing their bindings.

V11 source builds expose `state plan-template|plan|pending|fact|work` for the
[stateful worker](../../../docs/review-worker.md). A work package contains exact
current IDs, parents, pending questions and source-backed updates without an
ownership token. Review all questions for each resumed ID; facts request fresh
adjudication and never change verdicts automatically. Pass the package back to
plan/record admission. If it is stale, refresh it; do not edit its generation,
parents or fingerprints. Use normal queries and finalization for the new answer.

For a provider-neutral worker, create the plan with the trusted skill package:
`mehscan state plan-template --inventory DIR --source-root ROOT --policy value --skill-root TRUSTED/mehscan-security`.
The native runtime binds profile defaults (Value: 2 rounds/8 queries/128 KiB/300s;
Comprehensive: 3 rounds/12 queries/256 KiB/600s per conversation). Set
`--research-rounds`, `--research-queries`, `--research-bytes` or `--timeout` on
that template to configure them explicitly. The worker consumes the admitted
limits; changing policy, limits, engine or skill requires a new native plan/work
package. Manual plans without a runtime remain usable in the CLI, but cannot
be submitted to the AI worker. `state runtime-template --skill-root DIR --policy
value` emits the same effective contract without an inventory.

Runtime-bound `state plan`, `work` and `record` require `--skill-root DIR`.
The native CLI checks the actual trusted package outside source against the
contract digest; the AI worker supplies this argument automatically. Changed
engine or skill bytes require a new contract and plan. Historical state remains
readable without the old package.

For the bundled BYOK Codex adapter, export its trusted `--contract` descriptor
and supply `--provider-contract FILE` to the native runtime/plan and bound
plan/work/record commands. The worker receives the same file and requires the
bundled adapter configuration to match. Model/effort/client-version changes invalidate
old work. Use provider descriptors; schema-1 execution needs a fresh plan.
See the [BYOK adapter contract](../../../docs/codex-reviewer.md).

Without an orchestration policy, the worker runs the selected model directly
across its parallel job pool. It exposes research and final decisions without
handoff or automatic verification instructions. A failed provider process with
no completed-turn receipt can retry once in a fresh conversation using the same
remaining job budget. Exhausted budgets, rejected completed replies and source
validation failures do not receive that automatic retry. Recovery preserves
completed jobs; use the existing `--resume-from` workflow for an incomplete attempt.

`worker.json` reports the review mode, provider retries and observed token/time
totals by provider/profile/role. Failed-call timings remain in `timings_ms`.
Missing counters remain null, including cache writes when not exposed. Check
`usage_complete`, `cache_write_usage_complete` and `unknown_provider_calls`
before interpreting totals as complete. Native-only admission does not complete
a separately required change pass.

## Tiered controller

Opt in at `state runtime-template` or `state plan-template` with
`--review-orchestration FILE`, alongside the normal primary `--provider-contract`.
The trusted JSON declares `expert` (a different model's provider descriptor),
`case_limits` and `run_limits` (`model_calls`, `queries`, `bytes`,
`timeout_seconds`), `max_reviews_per_job`, `audit_percent` and `audit_seed`.
Use small related bundles within that declared size. A case is one bundle;
its limits cover both assessments and explicit recovery attempts. Budget for
verification and audits, not only the first review. Limits are dispatch/source
work bounds, not a hard token or currency cap.

Pass `--expert-command FILE` to the installed worker, using a separate trusted
argv/config for the pinned expert profile. `--workers` and `--expert-workers`
reserve routine/expert capacity; either queue can borrow unused capacity, with
their sum as the tiered run's total concurrent-call cap;
`--expert-review-ids ID,ID` starts the containing bundles there directly. Otherwise
typed routing, proposed issues and seeded closure audits select a second stage.
Keep the normal primary descriptor on native work/record calls. Native tiered
admission also requires the controller's `--review-execution FILE` and its
`assessments/` artifacts. Do not hand-assemble execution receipts to bypass review.
Routine investigation allows up to two model turns for clear local work or a
source-backed dependency request. Matching questions, scope and evidence, or an
explicitly selected existing request, share scoped expert research by default.
Experimental `--source-collector-profile routine` selects raw-source collection
instead; `expert` selects the already bound expert profile for that collection.
The profile is recorded in recovery bindings; it cannot change during recovery.
Collection uses the bound runtime's research turns and shared budgets to locate
then read relevant source; set research-rounds to permit dependent navigation.
`research-knowledge.json` retains navigation summaries, unread edges and raw
source support for the same snapshot and runtime, never a shared safe verdict.
Collector narrative summaries stay in the audit register; callers receive raw
source and explicit gaps, not the collector's description of effective checks.
Each waiting caller resumes without new source queries; one further
turn permits citation repair or interrupted-call recovery. All calls retain the
original shared case/run ledger. Incomplete collection is valid pending work, not
a trigger to repeat the same expert investigation. Ordinary pending-to-resolved
progress is terminal; affirmative contrary verdicts still need resolution.
If a routine draft's citation fails after its last normal turn, one unused turn
in the original runtime and shared budgets may correct citations only. It cannot
start more research or expand the case budget. Source-note schemas expose only
eligible inspected-source handles; navigation stays available for locating code.
The controller batches adjacent pending-question registrations into native
`state pending-batch` transactions (up to 256 exact questions per transaction),
preserving source/ownership checks and idempotent recovery.
Optionally add `quality: {"adjudicate_disagreements": true, "final_qa": true}`
to the orchestration JSON. Budget for up to four conversations per bundle plus
their research turns. Adjudication retains the independent assessments and names
the disputed claim and source resolution; unavailable external facts stay pending.
Final QA can reopen exact IDs but cannot dismiss or promote a finding. It checks
bounded bundles with a capped set of same-file peers, not a whole-run transcript;
peer omissions remain explicit. Preserve `quality-summary.json` with the stage
receipts. Without this policy, contrary verdicts remain pending for later review.
The Action's automatic single-profile setup does not configure this
local opt-in workflow. Preserve the run's checkpoints, receipts and stage files.
