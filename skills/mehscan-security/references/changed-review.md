# Review changed files

Changed scope combines with Value (default) or Comprehensive. Scan whole changed
files, prioritize the changed relationships, and research decisive context within
the authorized source root. It does not establish whole-application coverage or
that every result was introduced by this diff. These flags require Mehscan 0.9.0 or newer.

## Select the comparison

Keep `RUN` outside the source Git worktree. Output files inside it can become
untracked scan inputs and invalidate the review's source binding. Resolve the
actual target from the user or verified PR/release metadata; do not guess a
default branch, previous release or PR head. CLI help is authoritative.

```text
# Local edits: staged and unstaged changes as current working-tree bytes,
# together with nonignored untracked files. This does not review the index alone.
mehscan investigate review-inventory ROOT --changed-from HEAD --diff-mode files --output RUN/inventory

# PR: use a clean checkout of the verified PR head, not a CI merge commit.
mehscan investigate review-inventory ROOT --changed-from PR_BASE_SHA --target PR_HEAD_SHA --merge-base --diff-mode files --output RUN/inventory

# Local branch and edits: compare with the supplied target's merge base.
mehscan investigate review-inventory ROOT --changed-from TARGET_REF --merge-base --diff-mode files --output RUN/inventory

# Release delta: clean checkout of NEW_TAG; compare endpoints directly.
mehscan investigate review-inventory ROOT --changed-from OLD_TAG --target NEW_TAG --diff-mode files --output RUN/inventory

# Caller-supplied file set: repository-relative paths, one per line.
mehscan investigate review-inventory ROOT --files-from LIST --diff-mode files --output RUN/inventory
```

`--target` must resolve to the checkout's HEAD and requires a clean Git worktree,
including nonignored untracked files. The CLI never switches, resets or stashes
the checkout. Missing history, unresolved conflicts or ambiguous merge bases
require fixing the comparison; do not substitute a smaller or empty diff.
Without `--target`, a branch comparison includes local edits; label it that way.
File lists have no verified Git comparison or hunks; blank/comment lines and
surrounding whitespace are ignored, so they cannot represent every Git filename.
Missing files remain deletion records. Keep a list outside `ROOT` when possible.

Files mode does not expand to siblings/importers or fall back to a full scan for
renames, deletions, configuration changes or large diffs. Optional compiler
snapshots/backends currently require full analysis; scoped combinations fail.
Broader Impact/full review is a separate scope choice, requiring authorization
when it exceeds the user's requested work.

## Change pass and selected questions

For a stateful review in this session, follow the [native project workflow](host-review.md).
Register selected and deferred native IDs and every changed path with
`state plan`. Keep source-only leads when no native ID represents a changed
effect. Reviewed entries have no questions; unresolved effects use needs_review
with specific questions and actual pinned old/current evidence. A complete
response pass can still contain pending verdicts, deferrals and coverage limits.
Never report it as application safety or alert resolution.

When a verified stable repository ID or configured namespace is available, pass
`--repository-key ID` during inventory creation. For fork PRs this is the base
product's ID; `--source-repository-key FORK_ID` preserves source provenance.
Proceed unscoped if the namespace is unknown; do not guess an ID or equate remote
names with platform IDs. Selected bundles inherit native occurrence/subject keys.
Inspect their continuity status when matching history, not for each source query.

Inspect the saved `impact_scope` and coverage once: requested/resolved refs,
merge base, working-tree flag, changed paths/statuses, included files and gaps.
Read the actual diff and old source at the pinned base (merge base for a branch)
when a removed control, rename or changed contract matters. Use read-only Git
object/diff queries; disable external diff/text conversion. Scanner changed-line
ranges describe the new side and cannot replace the old source.

Perform a short change pass before selecting IDs. Check changed authentication,
authorization, routing, validation, encoding, producers, dependencies/config,
deleted guards and public effects. For each consequential question, identify the
changed relationship and any unchanged consumer that needs a targeted lookup.
Prefer `source`, `symbol`, `references` and exact old-source reads over loading
the repository. Keep scanner evidence and reviewer inference distinct.

Reuse this inventory with the existing selection and bundle flow:

```text
mehscan investigate review-inventory-list --inventory RUN/inventory --selection value --limit 50
mehscan investigate review-bundles ROOT --inventory RUN/inventory --review-ids ID,ID --output RUN/chunk-1
```

Comprehensive uses `--selection comprehensive`. Follow [bundle workflow](review-workflow.md)
for selected IDs and [finalization](finish-review.md) for decisions. Read whole
changed files as needed, including unchanged sinks; a hunk-only queue can miss a
removed guard. Search unchanged context only for a named missing edge. Record
affected-code questions separately in the run plan or `reviewer_origin_leads`;
an adjacent concern is not a verdict on an existing ID. Deletion/configuration
questions without IDs remain explicit change-pass work; do not invent responses
or pretend the bundle manifest accounts for them.

## Completion and reruns

Keep a compact run note with comparison, policy, change-pass conclusions,
selected/deferred IDs, context reads, unresolved questions and coverage gaps.
Account for deletion-only, unsupported, ignored and unparseable changes even
when there are zero native IDs. Use native completion to confirm the recorded
change pass, then report open effects, deferred work and missing evidence.
For the Action, read the separate delta coverage result before reporting that
the pinned change is covered.

Changed bundles must retain their `requests/`, manifest and `input-binding.json`.
Pass `--source-root ROOT` to finalization, triage, summary and report. Moved refs,
different changed paths or changed source/context bytes make the run stale.
The changed-content snapshot also binds unsupported and non-UTF-8 file bytes.
Regenerate the inventory and review the whole current PR comparison on each
push or base change. Use native identities to locate history and recheck the
deciding evidence after a revision changes. For persistent local work, use the
controller's [journal and Turso memory](../../../docs/review-worker.md#capture-local-review-memory).
Keep the stream and ownership supplied by the coordinator. Canonical JSON and
the journal preserve verdicts, exact-parent supersession, and missing or
conflicting work. Exact memory reuse applies to eligible settled native
decisions on unchanged full-source inputs.

Keep Changed output advisory. Confirmed SARIF defaults to the stable
`mehscan/triaged/changed` category; an explicit `--sarif-category` selects a
configured partition and `--sarif-run-id` names an attempt. Neither changes the
native scope or permits old-verdict reuse. SARIF publication metadata always
leaves alert disposition unestablished; GitHub ignores that custom metadata and
may close absent alerts if a partial artifact is uploaded. Keep the artifact
downloadable until the integration's baseline and closure behavior is verified.

## One-shot GitHub Action

Use the [Action guide](../../../docs/github-action.md#delta-coverage) for pinned
PR review with temporary state. `native_only` means inventory preparation
finished and reviewer work is still outstanding. When a workflow requires
complete delta coverage, use Comprehensive with an authorized reviewer.

Read `delta-coverage.json` alongside the findings. Check the base tip, merge
base, head and scan root, then report pending, deferred or unavailable work.
Cite the pinned base for modified, removed or renamed source and cite the
changed current ranges when marking a path reviewed. An admitted issue can coexist with a
passing coverage gate. A stale result belongs to its original revision.
