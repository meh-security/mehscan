# Review a staged source folder

Use the same project configuration for successive exports of a project. The
source can be a managed export, an engineer’s extracted download, or a Git
worktree. Stage the authorized source first and select the configuration from
outside that source folder.

Save a JSON file such as `/review-config/payments.json` with a stable project
key. Add a stream when the configuration belongs to a known branch or release
track.

```json
{
  "repository_key": "onprem:payments",
  "stream": "release:2.x"
}
```

```sh
mehscan project prepare "$SOURCE" --config /review-config/payments.json \
  --output "$RUN/inventory" --artifact payments-2.4.1
```

The command creates a standard full review inventory and a `project.json`
receipt in the new output directory. The receipt lists the repository key,
stream, native snapshot, inventory fingerprint, journal path, and local
memory database. Pass `--project-run /path/to/inventory/project-run.json` to `review_worker.py` to load the prepared source, inventory, journal, stream and memory settings together. Supply the private claim, reviewer configuration and attempt output. The worker derives current work and bundles from the authorized plan. An explicitly supplied work package still pins the handoff. Manual clients pass the project run and private claim through the
[ordinary review workflow](review-worker.md#prepare-review-work). Use
`--stream NAME` for a different review track. When both the configuration and
command omit a stream, the command uses `imported`. The optional artifact
label records the intake reference. Mehscan computes its snapshot from the
source it reads.

Keep a persistent `MEHSCAN_STATE_HOME` outside the source so that repeat
deliveries can share the same local memory. For a one-shot review, use
`--memory-mode temporary` during preparation and the subsequent review.
If persistent memory cannot be opened, preparation reports
`memory.status=unavailable` and still writes the inventory. Use the reason
to recover the store or continue in temporary mode.

The compact `project-run.json` contains the local project bindings. The full `project.json` keeps the intake and upstream history and also works as a reference for older preparations. Use the same prepared reference with the native journal. For example, `mehscan state plan-template --project-run /path/to/inventory/project-run.json --policy value` builds the manual plan. Claim, plan, work, record and end still verify generation, owner and the inputs required by each operation.

For an existing native inventory, `mehscan project bind --source-root "$SOURCE" --inventory "$INVENTORY" --stream "$STREAM"` creates the same `project-run.json` alongside it. This preserves the inventory’s Full, Changed or Impact scope. The repository supplies the default journal and retained-memory locations. Use `--store DIR` for a separate journal and `--memory-store FILE` for a specific database. For a one-shot run, choose a temporary journal and `--memory-mode temporary`. Bind requires a directory with no existing project reference.

## Close and report a project review

After native admission, the worker prints the attempt's `project_run` and the path to its `private_claim`. Use both values from the same invocation. A source review can replace the prepared inventory and advance the claim generation.

Save the worker's JSON output as `worker-result.json`, then close the attempt and render its admitted findings.

```sh
mehscan state end --project-run "$(jq -r .project_run worker-result.json)" \
  --claim "$(jq -r .private_claim worker-result.json)" \
  --status finished --operation-key close-delivery > close.json
mehscan report --close-receipt close.json --format markdown --output findings.md
```

Use `finished` for a completed review execution, including one that records pending questions. For an interrupted worker with an admitted report, use `incomplete`. A planning checkpoint has no admitted report. For a manual review, `state record --project-run FILE --claim FILE --run BUNDLES` also returns an admitted `project_run`. Close that reference using the same private claim. The journal keeps a frozen copy of the validated requests, responses and findings under its state directory. Repeating the record with the same operation key returns the same reference. A subsequent automated audit requires a plan with a bound worker runtime.

Choose an operation key unique to this close and reuse it on retry. The journal verifies ownership and generation. The close receipt names the selected attempt and binds its findings by SHA-256. Keep its attempt directory at the recorded location. Reporting reads the admitted findings, including their original reviewer and any unresolved or missing answers. JSON, SARIF, combined JSON/SARIF and Markdown use the same saved report. The private claim file stays with the operator. Use `mehscan memory export --close-receipt close.json` to inspect the retained publication payload. The receipt resolves the batch from that exact generation even after a later review closes.

For a named work plan, JSON includes `source_review_cases`. Markdown lists the same questions under **Named source checks**, with their answers, cited lines and outstanding facts at source handoff. A run can have zero native candidates and still have unresolved named checks. Native decision counts and SARIF alerts come from native review decisions. The close receipt renders the frozen report even if the working ledger later changes.

Older attempt references can still render findings with `mehscan report --project-run FILE`. Earlier close receipts require the original run or attempt reference for reporting.

<a id="start-a-fast-audit-after-close"></a>

## Audit a closed project review

Use the close receipt and a new attempt ID to claim the next generation on the same source. Save the private claim outside the source directory. Repeating the claim with the same ID and operation key recovers its receipt.

The following example runs a Full audit of pending decisions. Use `--second-pass fast` for nomination-based selection.

```sh
(umask 077 && mehscan state claim --close-receipt close.json \
  --attempt-id audit-1 --operation-key claim-audit-1 > audit-claim.json)

python scripts/review_worker.py --scanner "$MEHSCAN" --close-receipt close.json \
  --claim audit-claim.json --second-pass full --second-pass-scope pending --supersede \
  --reviewer-command "$REVIEWER_COMMAND" --reviewer-label "$REVIEWER_LABEL" \
  --output audit-1 > audit-result.json
```

Use the same bound skill and provider settings as the original plan. The journal checks the terminal transaction and source snapshot. The worker verifies that the admitted decisions are still the journal heads.

Fast spends calls on actionable nominations in the chosen scope. Full selects every admitted answer in scope. A verifier assesses the source independently, then a separate conversation compares that assessment with the saved first pass. Missing first-pass answers remain open in both modes.

Named work plans draw both stages from the original allowance. If verification finishes and the comparison cannot be funded, the audit keeps the baseline decision and marks the claim `not_checked` in `second-pass.json`.

The first-pass findings remain available through `close.json`. Use the new worker result to close the audit generation. If the audit is interrupted, repeat the worker invocation with the same claim, a new output directory and `--resume-from` pointing to its latest attempt.

A closed Value review with a named work plan can also continue into Comprehensive under its remaining allowance. [Continue Value into Comprehensive](review-worker.md#continue-value-into-comprehensive)

## Compare an explicit baseline

To compare with a saved source version, add `--base SNAPSHOT` from a previous
preparation in the same repository scope. The receipt's
`memory.capture.changes` lists added, modified, and removed discovered files.
Supply a known baseline and compare exports with the same review scope and
coverage. An unavailable baseline stops preparation. Use the resulting paths
with the [whole-file Changed workflow](../skills/mehscan-security/references/changed-review.md#select-the-comparison)
when that is the intended scope. A preparation with `--base` still produces
a full inventory.

## Pull configured shared context

Add an optional `"remote": "https://sync.example.com"` to the project
configuration for a pre-initialized native Turso upstream. Supply
`MEHSCAN_TURSO_AUTH_TOKEN` in the environment when required. Pass
`--pull true` to refresh the project's replica and include matching
publications under `upstream.sync.context` in the receipt.

The command uses a separate context cache for each configured remote so that
local drafts staged for publication stay out of the pulled context. Check
`upstream.sync.status` for `pulled`, `cached`, `uninitialized`, or `unavailable`. A cached view gives its age in seconds and the refresh failure. It is scoped to this remote, repository, stream, snapshot, inventory and requested baseline. A pull
that fails, hits a busy cache, or exceeds its 15-second deadline still leaves a
local inventory for the review. Treat publications as advisory context and
verify them against current source. For explicit publication, use the receipt's
remote, replica, and repository key with the standard
[native sync sequence](turso-sync-server.md#initialize-and-verify-a-publication),
starting with `memory sync pull` on that writable replica.

Before choosing work for a later scan, read
`upstream.sync.context.review_state.findings` for the current shared outcomes.
Each current decision names the publication containing its assessment and
source evidence. A [shared resolution](turso-sync-server.md#publish-a-shared-resolution)
also carries the reviewer type, rationale, and exact superseded heads. Use
this context to inform the current review. Native local admission determines
which decisions a scan can reuse and which work it has completed.

To read the reasoning from a known earlier delivery, use its saved `snapshot`
and `inventory_fingerprint` from `project.json`:

```sh
mehscan project prepare "$SOURCE" --config /review-config/payments.json \
  --output "$RUN/inventory" --pull true --base "$BASE_SNAPSHOT" \
  --base-inventory "$BASE_INVENTORY_FINGERPRINT"
```

The receipt puts the historical review under `upstream.sync.baseline.context`
and keeps the current scope under `upstream.sync.context`. The baseline snapshot
must already be available in local memory. Use the changed paths and cited
dependencies to recheck whether the old reasoning still applies.

New source-admitted publications include their original prepared inventory when the upstream supports lineage. Prepare exposes those assessments in `upstream.sync.context.source_review_history`, grouped by effective inventory. Exact inventory decisions continue to use `context.publications`. Run `memory sync init` and pull to enable lineage on an existing upstream.
