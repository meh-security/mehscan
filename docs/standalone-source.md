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
memory database. Use its `inventory`, `state_store`, and `stream` in the
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
