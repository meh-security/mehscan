# Local review state and decision history

Mehscan 0.9.0 and newer provide `mehscan state` for a trusted local coordinator. It
keeps generation ownership and immutable native decisions across processes. The advisory GitHub
Action can optionally call them on one configured persistent host. Independent
ephemeral runners do not share a store; see [Action coordination](github-action.md#persistent-host-coordination).

## Claim a generation

Create a current native inventory with an explicit stable repository namespace.
For a fork PR, use the base product's repository ID and preserve the fork ID as
source provenance. Keep inventory, bundles and state outside the source root.

```text
mehscan investigate review-inventory ROOT --repository-key repo:123 --output RUN/inventory
mehscan state claim --store STATE --stream pr:24 --inventory RUN/inventory --source-root ROOT --attempt-id run-1 --expected-generation 0 --operation-key claim-run-1
```

For Changed review, use the [pinned comparison](../skills/mehscan-security/references/changed-review.md)
when creating the inventory. The claim validates the saved inventory against the
current source and binds its repository/provenance, source-only assessment
context, source/input fingerprints, native subject catalog and optional change
comparison. `snapshot_id` names this native state binding; it is distinct from
the Action's larger contract containing adapter bytes and event metadata.
An optional `--coordination-key KEY` binds an opaque trusted-coordinator contract
into the snapshot, so a changed lifecycle/tool contract cannot coalesce merely
because native source stayed the same. It does not authenticate that assertion.

Choose a stable stream, such as `pr:24` or a configured release-review lane, within
the repository namespace. The first generation expects `0`. For an existing
stream, read `state status`, then claim its current generation. A concurrent
update fails the comparison; reread current source/lifecycle metadata before
deciding whether to retry. A successful claim returns `result.generation` and
`result.owner`. Pass both to updates. A different binding or `--retry true`
creates a new generation and invalidates the previous owner. Duplicate running
or finished snapshots coalesce without returning an owner. Cancelled/incomplete
snapshots can start a fresh attempt. Attempt IDs cannot be reused for a new
generation.

Every mutation requires an `--operation-key`, unique within the entire store.
Use a stable key for one logical request: retrying identical input returns its
original receipt; reusing the key for different input fails. `replayed` identifies
that acknowledgement and `currently_owned` reports whether the original command
still belongs to the active running attempt. An old receipt can contain an old
owner and is not current authority. Source-bound claim/record retries still
validate their inventory and artifacts before returning a receipt.

## Admit validated decisions

Select bundles, perform review and finalize responses through the existing
[review workflow](../skills/mehscan-security/references/review-workflow.md).
Retain the manifest, requests, input binding and response files. Import the
validated bundle run using the claim receipt's generation and owner:

```text
mehscan state record --store STATE --stream pr:24 --inventory RUN/inventory --source-root ROOT --run RUN/chunk-1 --generation 1 --owner OWNER --operation-key record-chunk-1
mehscan state status --store STATE --stream pr:24 --repository-key repo:123
mehscan state history --store STATE --stream pr:24 --repository-key repo:123
```

The importer checks current inventory/source, native bundle identity and complete
response contracts, then builds native decision records. Arbitrary report JSON,
legacy decisions without native records and foreign namespaces are not admitted.
All three verdicts retain their full response, evidence, native flows and exact
source/input binding. Tool/triage/scope admission provenance is retained
separately. This validates the artifact contract, not the truth of AI reasoning.

`--allow-partial true` permits missing response files, as reporting does; a
present invalid response still fails. Only accepted responses enter history.
Unselected, deferred or missing subjects remain unassessed. The view includes
the current inventory's whole native subject catalog, so it is not an assertion
that Value selection or a change pass covered every question.

| Subject state | Meaning |
| --- | --- |
| `unassessed` | No unresolved decision has been admitted in this generation. Historical responses are not current verdicts. |
| `recorded` | Exactly one unresolved decision belongs to this generation, with no unresolved older heads. Its verdict can still be `needs_review`. |
| `conflict` | Multiple independent current decisions remain. The view does not pick the newest, strongest or majority response. |
| `awaiting_supersession` | Current decisions coexist with unresolved historical decisions. Explicit fresh adjudication is needed. |

Independent subjects at the same occurrence have independent states. Previously
seen subjects absent from the current catalog appear under
`historical_only_subjects`; disappearance establishes neither remediation nor
safety. `status` is a view of the last admitted generation, not a live Git/API
freshness check. `history` also includes attempt bindings, immutable decisions,
supersession links and admission provenance. Neither read returns an owner token.

## Supersede explicitly

Fresh review can supersede earlier answers for the exact same native subject and
assessment context, including after a changed source snapshot. Save an array of
links and pass `--supersessions FILE` to `state record`:

```json
[
  {
    "decision_id": "NEW_VALIDATED_DECISION_ID",
    "parents": ["OLD_DECISION_ID", "OTHER_UNRESOLVED_DECISION_ID"],
    "reason": "Current-source re-evaluation established the exact input boundary."
  }
]
```

The child must be a new validated decision in that imported run. Parents must
name exactly all unresolved heads for its subject/context, without duplicates.
A self-parent, partial parent list, foreign subject, existing child or concurrent
parent change fails the entire transaction. Only one child per subject can
supersede in one transaction. Any other independent incoming answer remains a
head; explicit adjudication cannot silently discard it.

Old records and proof remain immutable. Re-importing a superseded response
retains its admission history without restoring it as a head. A negative or
pending answer never carries into another generation automatically: even an
identical retry needs current validated admission. Changed source needs a fresh
decision and explicit lineage if the same subject has unresolved history.
Changed native keys, ambiguous moves and different contexts cannot be connected
by this command. A `not_issue` successor does not distinguish corrected false
alarm from verified remediation; that disposition needs additional evidence.

## Account for planned review and pending evidence

`state plan-template`, `plan`, `pending`, `fact` and `work` support explicit
completion accounting and provider-neutral handoffs. See the
[worker guide](review-worker.md) for input shapes and commands. Plans require an
exact selected/deferred partition of the current native catalog and one entry
for every changed path. Comprehensive disallows native deferrals; Value records
their reasons. Plan revisions use `--expected-plan-id` comparison and retain
old revisions and pinned old/current evidence in history.

The status/history `completion` view distinguishes `not_planned`, `incomplete`,
`complete` and `complete_with_limits`. Completion means planned response work
was performed and accounted for; pending verdicts and source-only questions
remain explicit. Deferrals and native coverage gaps remain visible even after
a manual change pass. `security_resolution` is always `not_established`.
There is no new verdict or automatic GHAS disposition.

Typed questions bind exact current decisions or change-pass entries. Source-backed
fact updates bind that question and generation, queue fresh revalidation, and
retain their actual source proof. They never silently convert a pending answer
to issue/not_issue. Work package admission rejects changed parents, facts, plan,
source or generation; fresh adjudication uses the existing supersession rules.

## End execution and preserve the store

```text
mehscan state end --store STATE --stream pr:24 --repository-key repo:123 --generation 1 --owner OWNER --status finished --operation-key end-run-1
```

Terminal status is `finished`, `cancelled` or `incomplete`. It blocks later writes
by that owner. Ending execution does not settle pending verdicts, missing
subjects, conflicts or security coverage. Every view retains
`alert_disposition: "not_established"`. No GHAS dismissal, alert closure, waiver,
thread resolution or merge gate is inferred from it.

The store is one versioned, hash-chained `transactions.jsonl`. Mutations hold an
exclusive OS file lock through replay, precondition checks, append and `sync_all`;
reads hold a shared lock. A receipt follows file synchronization. Torn tails,
unknown schemas, altered hashes, reordered transactions and replay mismatches
fail closed. There is no automatic truncation, recovery or compaction command.
Stop coordinating workers, preserve a corrupt store and restore a trusted complete backup through an
explicit recovery procedure; do not guess away a committed decision.

Use a trusted local filesystem with working locks and synchronization. Shared
network/object stores and multiple runner copies are not supported. Each command
replays the journal; its current limit is 512 MiB. Deployment-grade retention,
bounded replay, backup/recovery and power-loss acceptance remain future work.
The owner token fences cooperative workers; it is deterministic and is not an
authentication credential. Hashes detect accidental corruption, not a malicious
writer rewriting the journal. Protect the store and review artifacts using the
host's access controls. Provenance fields do not authenticate a reviewer.

## Hosted PR integration still required

Generation comparison protects updates within this store; it does not establish
which GitHub snapshot should become current. A delayed event can claim a newer
generation if its coordinator blindly supplies the current number. A hosted
adapter must reread authoritative base/head metadata, persist one shared store,
claim only the accepted current snapshot, and check freshness and ownership again
before publishing. Publication and a push are not atomic with a local lock.

The shipped-in-source advisory Action now supports an operator-provisioned local
store with metadata selection and emission under a coordinator lock. Its default
ephemeral-runner example remains stateless. The lock does not extend to later
GitHub artifact uploads, and killed workers require explicit retry.
Named deployment/integration contexts, authenticated
producer policy, alias/remediation/waiver records, dependency-based verdict reuse
and protected checks are separate pending work. Matching fingerprints alone
cannot authorize any of them.

## Native review runtime profiles

For AI-worker work, add `--skill-root TRUSTED/mehscan-security` to
`state plan-template`. The skill must stay outside source. The effective native
runtime contract binds Value/Comprehensive, exact engine bytes/version, worker
protocol and the trusted skill-package digest. Optional research-round/query/
byte/timeout overrides are resolved in the template, not silently in the worker.
`state runtime-template --skill-root DIR --policy value` exports the same
contract separately. Both Value and Comprehensive default to five research rounds
(six total model calls), 24 query units, 512 KiB and 900 seconds per conversation.
Coverage selection distinguishes the profiles. Templates retain the
compatible all-ID default. Add `--selection policy` to apply native initial
priority hints: Value moves hinted IDs into explicit `deferred_review_ids` with
their reason/dependency; Comprehensive keeps every admitted ID. The advisory
Action requests this selection explicitly. Deferral is unreviewed work, not a
negative verdict. No model-based ranking or hidden exclusion is introduced.

Contract changes produce a new plan/work ID. Exact old handoffs are rejected;
new engine bytes require a newly bound plan. Runtime-bound `state record` requires
`--work-package`. Manual plans without runtime remain valid for direct CLI use,
while the AI worker requires a bound plan. History retains old contracts and
provenance without turning them into current reusable verdicts. Skill-package
hashes exclude `.git` and `__pycache__`, reject symlinks and bind all other package
files. Compatibility checks do not establish that a package is trustworthy.

Runtime-bound `state plan`, `work` and `record` require `--skill-root DIR`.
The native CLI checks the actual trusted package outside source against the
contract digest; the AI worker supplies this argument automatically. Changed
engine or skill bytes require a new contract and plan. Historical state remains
readable without the old package.
