---
name: mehscan-security
description: Run Mehscan on an authorized codebase, plan a repository review, or triage Mehscan bundles. Use for Mehscan scans, candidate review, and security reports.
---

# Mehscan security

Use the supplied `mehscan` executable, one on `PATH`, or the executable in the
current Mehscan checkout. If none is available, say so. Check `mehscan --help`
when an option is uncertain. Scan only the authorized source root.

## Choose the job

| Request | Run or read |
| --- | --- |
| Quick leads | `mehscan scan ROOT --format candidates` |
| Machine-readable leads | `mehscan scan ROOT --format json` |
| Changed lines | `mehscan scan ROOT --changed-from BASE --format candidates` |
| AI review of a small repo | `mehscan investigate review-bundles ROOT --output DIR` |
| AI review of a large repo | `mehscan investigate review-inventory ROOT --output RUN/inventory` |
| Existing bundle | `mehscan investigate review-bundle-list --bundle REQUEST`; do not rescan. |

The scan lists **candidates**, not confirmed vulnerabilities. For AI review,
process the requests listed by `manifest.json`. A subset is a scoped review,
not a complete application assessment. See [commands](references/commands.md)
only when creating bundles, validating responses, or producing reports.

## Plan a repository-wide review

For a supplied manifest with exact IDs, review those IDs directly. Otherwise,
before opening many requests, follow [review planning](references/review-planning.md).
Pre-assess the source and requested scope: identify the stack and deployed
surfaces, map inventory concentrations, and use prior same-revision verdicts
to rank review lanes. A bounded small review can use full
bundles; a large or uncertain one uses an inventory and small selected chunks.
If agents are available, assign disjoint IDs with one shared whole-run plan.
Default to Value review: map the attack surface, then cover distinct security
relationships across relevant lanes, including access, output, data exposure,
and state changes without a hard severity cutoff. In a
manageable queue, review nearly every ID; group only source-supported repeats
and clearly inapplicable cases. In a large queue, keep the unselected work
visible and call the review partial until every relevant lane is assessed.
Comprehensive review gives every admitted ID a verdict.
Honor a requested category. Reuse
same-fingerprint completed reviews. For a large queue, use short source reads to rank a few inventory IDs
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
[lead follow-up](references/review-planning.md#follow-up-on-reviewer-origin-leads)
for their independent evidence check. Keep the originating ID's verdict intact.

## Review one bundle

For each review ID, follow [the bundle workflow](references/review-workflow.md):
read its security question and deterministic facts, inspect the relevant
source through Mehscan, choose the next query needed to settle a missing edge,
and cite the decisive evidence behind the verdict. Read **one** matching guide from the
[bucket index](references/triage-buckets.md). The bucket identifies the
security relationship to test; the review's question identifies the exact
operation and operand.

For a bundle with several IDs, first list IDs with `review-bundle-list --bundle
REQUEST`, then follow [shared-pattern review](references/pattern-sweep.md).
Route shared dataflow contrasts to a small focused pass before a long sweep;
review independent operations and entry-point controls in ordinary bundles.
Group only IDs that depend on the same implementation or control. Read a shared
source fact once, then test its applicability to each exact operation; a shared
fact is not a shared verdict. Keep unrelated IDs in separate groups. Journal
each query under the ID that prompted it, and reuse its source location for
later IDs without repeating the query just to fill their journals.
Before a broad review's final report, use the workflow's focused exception
audit for groups whose IDs have different actors, producers, guards, or sink
operands. Keep the first responses; replace only re-reviewed bundle responses
after validating the focused decisions.

Return `issue` for a shown weakness, `not_issue` for an affirmatively safe or
inapplicable relationship, and `needs_review` for a decisive fact that remains
unavailable after targeted queries. Keep reviewer inference separate from
Mehscan facts and retrieved text. Pass `--journal FILE`
to code-evidence lookups, not bundle listing or cards, and include only decisive source in
the brief draft's `evidence` source ranges. State a newly discovered decisive
missing fact in `needs_review.checks` when needed. Use
`review-bundle-finalize` to fill exact source artifacts, attach measured lookup
counts, and validate the final response.
For `issue` and `not_issue`, set `checks: []` and
`investigation.blockers: []`; do not carry a bundle question forward after
resolving it. For `needs_review`, keep each check on one line within 300
characters and name the exact missing fact.

## Deliver

Use `mehscan report` with validated responses for the final JSON, SARIF, or
Markdown output. Preserve unresolved reviews; only confirmed issues are
findings. State the scanned root, any selected-source limits, and whether all
manifest requests were reviewed.

For later user-supplied repository knowledge, policy, or impact recalibration,
use the separate [Mehscan revalidation skill](../mehscan-revalidation/SKILL.md)
against this validated response. Keep the initial review record intact.
