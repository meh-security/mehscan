# Advisory GitHub Action

For the dedicated hosted test repository, phased SARIF acceptance and later App
setup, see [GitHub acceptance setup](github-acceptance.md) and
[release readiness](release-readiness.md).

By default, the root `action.yml` prepares a Changed native review inventory for a current PR
or an explicitly selected release delta. It writes source-bound JSON, a compact
job summary and reusable inventory artifacts. It does not run AI, finish the
reviewer's change pass, assess a prospective merge, upload SARIF, comment on a PR
or approve a merge. Native preparation can complete while security questions and
unsupported/deleted contracts still need review. Do not configure this job as a
required security gate.

This implementation requires the V11 CLI in a reviewed source build. The released
0.8.0 executable lacks these options. Set repository variable `MEHSCAN_V11_COMMIT`
to a reviewed full commit SHA containing both the Action and CLI, then copy
[the caller workflow](examples/mehscan-advisory.yml) into the target repository.
The example builds that pinned tool in its own checkout and places the executable
outside target source. It never builds target code. After release, a verified
prebuilt executable with V11 support can replace the trusted source-build step.
The workflow example is not enabled by this checkout.

The [opt-in BYOK caller](examples/mehscan-byok-advisory.yml) adds an authoritative
credential-lane check, pinned client installation and private company auth setup.
Use it only after native acceptance; [setup instructions](github-acceptance.md#native-action-acceptance)
describe the secret and manual fork authorization. This remains unaccepted on
actual GitHub until a reviewed pin and test repository run are recorded.

The composite Action accepts:

| Input | Meaning |
| --- | --- |
| `scanner-path` | Required trusted executable outside target checkout. Its bytes are fingerprinted and rechecked. |
| `source-path` | Dedicated checkout directory in the workspace; default `mehscan-source`. |
| `scan-root` | Authorized directory within that checkout; default `.`. Parent traversal and external symlinks are rejected. |
| `pull-request` | Explicit PR number on `workflow_dispatch`; automatic PR events supply their number. |
| `base`, `target` | Both required for a manual release delta; mutually exclusive with `pull-request`. |
| `review-mode` | `native` (default), `value` or `comprehensive`. The latter prepare active review work; `provider-config` additionally executes the bundled BYOK reviewer. |
| `skill-root` | Trusted security skill outside target source; defaults to the pinned Action package. |
| `provider-contract` | Optional descriptor for a separate trusted handoff consumer. Mutually exclusive with `provider-config`. |
| `provider-config` | Absolute trusted Codex configuration outside target source/uploads. With Value/Comprehensive, generate the bound descriptor and execute the bundled reviewer. |
| `allow-fork-review` | Default `false`. `true` authorizes fork model execution only on explicit `workflow_dispatch`; automatic fork events prepare native inventory only. |
| `token` | Read-only metadata/private-source token; defaults to `github.token`. |
| `state-store` | Optional pre-existing persistent local directory, absolute and outside workspace/runner temp. All coordinated workers must share one trusted host and store. |
| `state-retry` | `true` explicitly starts a new generation, including after an abandoned running attempt. Defaults to `false`; requires `state-store`. |

Use `contents: read` and `pull-requests: read`. The caller chooses retention and
uploads the returned `artifact-directory` under the unique `artifact-name`.
Artifacts include native code/evidence/context and remain untrusted inputs to a
later reviewer or publisher. Avoid broadening repository artifact access.

## Source and lifecycle contract

For PRs, event data locates the PR. The adapter reads its current state, base/head
repository identities and head SHA from the API, and separately reads the current
base branch tip. It checks out the exact head, fetches the pinned base/history and
scans merge-base to head using `--target` and `--diff-mode files`. The default PR
workflow SHA is a synthetic merge commit and is not used as the source endpoint.
[GitHub's event reference](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows)
describes that distinction.

Every rerun scans the whole current PR changed-file set. An unrelated last push
does not remove earlier PR changes from the inventory. Force pushes and retargets
resolve a new contract. The default caller scans code/base updates and draft/readiness
transitions. Close/reopen are supported edge cases, omitted from its default trigger
list. In native mode, AI is explicitly absent. Title/body-only edits are skipped because those
fields are not consumed by this native preparation. Closed PRs skip scanning,
including when the source fork is already gone.

Release runs resolve both supplied refs to immutable commits and compare directly,
without a merge base. Their target is checked out exactly. A moved release tag,
base-only PR push, changed head/fork/base ref, closure or draft transition detected
before or after scanning marks the attempted artifact stale. Failure to fetch
source/history, a dirty target, a changed executable, missing metadata or a failed
native command does not become a completed review. Each artifact keeps its
original contract instead of being rebound to newer endpoints.

`run.json` keeps execution/attempt identity separate from `snapshot_id`. The latter
hashes endpoint identities, comparison/merge base, scan boundary, native policy,
adapter and scanner bytes, changed content and inventory input bindings. Duplicate
deliveries for the same contract have the same snapshot key and separate immutable
attempt directories. They do not share or supersede verdicts. Native occurrences
use the base repository's stable platform ID; source-fork ID is separate provenance.

Status is `native_only`, `review_ready`, `reviewed`, `stale`, `incomplete`, `skipped` or `cancelled`, never a
merge verdict. Preparation failures before a contract is available fail the Action.
The example's concurrency cancels older attempts; cooperative cancellation also
checks native-command boundaries. Cancellation/runner termination can prevent
artifact upload. There is no durable current generation or cross-run deduplication
store by default, and Actions concurrency is not a publication lock. Optional
[persistent-host coordination](#persistent-host-coordination) uses the local
state commands; independent ephemeral runners still have no shared authority.

## Persistent-host coordination

On an operator-managed persistent host, supply `state-store` pointing to a
pre-provisioned local directory outside `GITHUB_WORKSPACE` and `RUNNER_TEMP`.
All workers for the same repository/PR/root must run on that host and use that
directory. Store access belongs to trusted workflow code. This is a deployment
choice for an already authorized worker environment; the provided hosted-runner
example keeps it disabled. Store paths inside ephemeral job directories fail
instead of silently losing coordination on the next run.

The adapter partitions journals by platform repository ID, PR or release-ref
pair, and scan root. After native inventory preparation, a cancellable OS lock
serializes current GitHub endpoint reads, native generation claims and advisory
artifact emission for that lane. It rechecks base/head under this lock before
claiming, after claiming and before writing the result. Native claims also
validate the source/inventory and compare the expected generation under their
own journal lock. A changed full Action contract gets a new generation even if
its native inventory is unchanged, such as a draft transition or changed trusted
tool. The Action contract is an opaque `--coordination-key` in the native binding;
it does not authenticate the coordinator's assertion.

An owned native-preparation attempt ends `finished`, `cancelled` or `incomplete`.
It imports no AI decisions, so catalog subjects remain unassessed. Identical
running/finished snapshots coalesce without returning ownership; every Action
delivery still retains its separate original artifacts. Coordination does not
avoid native inventory construction, which establishes the exact bound inputs.
Tokens and owners are kept out of exported artifacts and outputs.

`coordination-status` reports `owned_finished`, `coalesced_running`,
`coalesced_finished` or a stale/incomplete/cancelled state; `generation` reports
the admitted native generation when available. `run.json` carries the native
snapshot ID separately from the Action snapshot ID. These are execution facts,
not AI completion or merge authority. A later reviewer needs a fresh authorized
claim and validated admission; this native-only Action does not hand off an
active owner.

If a worker is killed after claiming, the journal can retain a running attempt.
There is no automatic lease expiry or takeover. A duplicate has no owner and
cannot finish that attempt. An operator-authorized rerun with `state-retry: 'true'`
fences the abandoned generation and starts a fresh one. Cooperative cancellation
after a known claim attempts a non-cancellable terminal write; hard termination
or a lost claim receipt can still leave the attempt running. Lock waiting is
bounded to 60 seconds; corrupt journals fail incomplete and require explicit
store recovery. Never replace a corrupt store with an empty one automatically.

The lock covers local result/summary emission, not the caller's later
`upload-artifact` operation. Uploads are immutable historical artifacts; a push
can make one stale immediately after its final check. No current publication
pointer, GHAS upload, protected check or distributed lock is implemented.
Artifact/cache downloads into separate runners, network filesystems and object
stores cannot substitute for this shared local journal. A hosted service with
transactional storage and tested publishing remains separate work.

## Deliberate limits

Base-only pushes do not necessarily trigger a PR workflow. This example rechecks
the base at execution boundaries and supports manual reruns, but it has no base
watcher. A base/head change after the final API read can immediately make the
artifact historical. It supplies no atomic current-state or integration guarantee.

PRs with merge conflicts and fork approval rules can prevent automatic
`pull_request` runs. A manually authorized PR run can prepare head-source evidence
when it is accessible; it still does not assess the prospective merged tree.
Private forks may require read permission beyond the default token. The Action
rejects `pull_request_target`, generic comment events, push events and merge-group
events instead of silently scanning a different ref. Model authentication is selected explicitly through a trusted configuration file;
comment-triggered work is unsupported. See
[GitHub's privileged PR workflow guidance](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target).

No target builds, hooks, submodules or package scripts run. Both the trusted
scanner and Action adapter must stay outside the target checkout. Fetch credentials
are scoped to the base Git URL in a child process and are not persisted or passed
to the native scanner. Target AGENTS/skill files do not configure the worker.
Use a reviewed Action checkout/pin, isolated hosted runners and a trusted scanner;
this adapter is not a sandbox for a malicious executable or shared runner.

Local acceptance uses stubbed read-only GitHub delivery plus real Git/CLI inventory
tests. The real tests cover total PR scope across an unrelated push, native base
and fork namespaces, direct release comparison and dirty-source rejection. Run:

```text
cargo build --package mehscan-cli --locked
python -m unittest discover -s tests/github_action -v
```

CI runs those tests after the CLI build on its existing OS matrix. Actual hosted
checkout/private-fork delivery, cancellation, artifact upload, API closure and
merge gating remain separate acceptance work. Artifact success alone cannot
establish those behaviors.

## Active review handoff (local integration preview)

Set `review-mode: value` or `comprehensive` to prepare a fresh one-run review
instead of ending a native-only attempt. The Action creates a native runtime-bound
plan, exports exact work and creates bundles for the selected native IDs. Templates
currently select all IDs in both profiles; Value does not silently rank or defer.
A zero-native queue still prepares changed-effect work. The Action returns
`review_ready` and a private `review-handoff` path. This status means ready to
review, not reviewed. The example caller remains native-only.

The control directory is a separate sibling under runner temp, with restrictive
permissions on Linux. It contains the state journal, ownership receipt and private
handoff. Upload only `artifact-directory`, never the control directory or all of
runner temp. Ownership is absent from public work, plans and summaries. This is
one run on one host, consumed in the same job; the AI handoff rejects `state-store`. Independent deliveries
have separate stores and do not establish hosted cross-run deduplication.

A trusted integration consumer can execute the handoff with the same local worker:

```text
python /TRUSTED/scripts/github_action.py review PRIVATE/handoff.json --reviewer-command TRUSTED/reviewer-argv.json --reviewer-label provider/model
```

The consumer rechecks source, endpoints, executable, controller, skill and current
work before model execution. It invokes the existing change pass, native reviewer,
finalizer, report validator and state admission. On return it rechecks freshness
and closes the owned attempt. Stale endpoints retain the pinned historical result
and never become a current reviewed result. Failure or cancellation ends incomplete
or cancelled when the owner can still close the attempt. A lost process/receipt can
leave abandoned running state; it cannot be treated as completed. No review result
is reconstructed from downloaded artifacts. Reusing a consumed handoff is rejected.

`reviewed` is successful advisory execution. Native completion and pending/deferred
work remain separate in `run.json`; pending answers can coexist with successful
execution. A separate CLI consumer updates its own invocation outputs. When `provider-config`
is supplied, the composite runs the consumer and exposes its final status; without
it, the composite exposes the prepared `review_ready` handoff.

The controller receives a small explicit environment allowlist without GitHub or
provider tokens, Python path overrides or arbitrary workflow secrets. The bundled
[BYOK Codex adapter](codex-reviewer.md) consumes provider-bound work with explicit
private authentication and upstream analysis-only settings on every start/resume.
It does not add a process sandbox; runner isolation belongs to the company.
Export its provider descriptor before preparation and supply `provider-contract`.
The worker checks the bundled adapter config against native provider/model/effort/
client-version metadata.

The existing command deadline bounds the consumer launch to 900 seconds; native
conversation limits are bound independently. Opt-in model execution is wired;
live hosted acceptance remains pending. The provided caller example remains native-only; no SARIF upload, PR
publication or required check is enabled. Automatic model scans will begin with
authorized same-repository PRs; external fork scans require maintainer authorization
before receiving company model credentials.

## Opt-in BYOK Action execution

Prepare the [trusted provider configuration](codex-reviewer.md) in a prior company-
approved setup step. Install the chosen Codex CLI outside target source and provide
one explicit supported authentication JSON file; keep auth, config and sessions
outside the complete artifact upload root. The Action does not install a provider,
log in automatically or discover model keys from the workflow environment.

```yaml
- name: Review changed files with the company model
  id: mehscan
  uses: ./.mehscan-tool
  with:
    scanner-path: ${{ runner.temp }}/mehscan-build/release/mehscan
    review-mode: value
    provider-config: ${{ runner.temp }}/company-mehscan-provider/config.json
```

Use the trusted tool checkout and read-only permissions from the existing caller
example. Keep native mode as default until the reviewed V11 pin and provider lane
are accepted. `value`/`comprehensive` without a config still prepares a handoff for
a separate trusted consumer. With a config, the Action generates its descriptor
and private argv file, consumes the handoff once, executes the worker and closes
ownership. Changed config/command, missing auth, failed execution and stale source
cannot yield current successful review. Model execution failure fails its Action
step while retaining an incomplete/cancelled result where ownership is available.
Configuration stays at its supplied private path; generated descriptor/argv and
handoff files stay in the separate control area, outside exports.

Automatic external fork events with a config prepare native inventory only and
report `fork_model_review_not_authorized`; the model configuration is not opened.
For an explicitly authorized fork scan, dispatch the trusted workflow manually,
select the PR and set `allow-fork-review: 'true'`. GitHub's permission to dispatch
the workflow supplies actor authorization; arbitrary comments cannot enable it.
The workflow author must wire that input intentionally and supply model credentials
only to that authorized job. Private fork fetch restrictions still apply.

The composite's final `status`, `coordination-status` and `generation` come from
model execution when it runs. A consumed handoff is not exported. Completion is
separate: `review-work-complete`, `issue-count`, `pending-review-count`,
`pending-effect-count`, `deferred-count` and `missing-review-count` describe native
work accounting. Missing completion yields empty outputs, not zero issues or
clearance. A successful execution may retain pending questions and coverage limits.
`completion.json` binds this accounting to the snapshot and exact endpoints,
including historical/stale results. `summary.md` displays status and these counts.
Neither `reviewed` nor complete work asserts application safety or merge approval.

After native admission, the artifact directory also contains:

- `findings.json`: the canonical native report, including unresolved reviews.
- `findings.sarif`: native findings with existing fingerprints, paths and supported
  flow evidence preserved, plus advisory snapshot/endpoints/completion metadata.
- `completion.json`: execution status and separate native work accounting.
- `usage.json`: reported token sums, reporting-round counts, elapsed provider time
  and prompt bytes. Missing counters remain `null`; sums may cover only some rounds.
  Counters sum conversation deltas, including continuations without counting the
  earlier turns twice. Metrics with a different accounting basis are rejected.
  No currency cost is inferred from BYOK usage.
- `artifacts.json`: file sizes and SHA-256 hashes for the packaged exports.

SARIF categories are stable per PR/release lane and scan root; individual attempts
have separate run IDs. An empty native inventory gets a real native empty report.
When no selected native work can be rendered, the manifest explicitly records that
limitation rather than manufacturing findings. Pending source-only proof stays in
completion/worker evidence; an empty SARIF result list does not establish safety.
The manifest hashes bytes, without attesting producer identity or authorizing
publication. Historical/stale exports retain their execution status.

Ubuntu deterministic acceptance passed 51 Action tests, including native admission,
subdirectory paths, pending work and renderer failure. Four emitted SARIF documents
passed schema validation, including an empty inventory; the three nonempty-inventory
documents matched native output except advisory metadata.
These tests use a fixture provider, without real inference. Local live Luna/medium
acceptance also completed four synthetic PRs through this consumer on Windows,
with native admission and schema-valid exports. Existing ChatGPT authentication
was used; this does not establish hosted company-key setup. Six Ubuntu release
reviews also passed, including unchanged-helper research and exact continuation.
Hosted auth/cancellation
and a separate trusted publisher remain next work; no SARIF upload or PR write is
enabled.
