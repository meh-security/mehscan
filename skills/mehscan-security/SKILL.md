---
name: mehscan-security
description: Run Mehscan on an authorized codebase, plan a repository review, or triage Mehscan bundles. Use for Mehscan scans, candidate review, and security reports.
---

# Mehscan security

Use the supplied executable, `mehscan` on `PATH`, or the executable in the
current Mehscan checkout. Scan only the authorized source root. If the executable
is unavailable, say so; use CLI help when an option is uncertain.

## Supplied bundles or exact IDs

Read the manifest to locate its request files under `requests/`. If a source-bound
packet covers the exact selected questions, anchors and source, use it as the
initial view and request missing facts normally; skip duplicate card/sweep reads.
Otherwise start with
`mehscan investigate review-sweep --bundle REQUEST` for several IDs, or
`mehscan investigate review-card --bundle REQUEST --review-id ID` for one.
These views supply the exact questions, facts and source locations. Keep the
original JSON on disk for the finalizer; do not print it, the full inventory,
or binding metadata as startup context. Inspect metadata if a binding error
or a specific accounting question requires it.

For a supplied chunk containing only HTML-output questions, follow
[HTML output review](references/html-output-review.md), then finalize as it
directs. It includes the shared review procedure for this category.
For other chunks, read [bundle workflow](references/review-workflow.md) and **one** matching
guide from the [bucket index](references/triage-buckets.md). For several IDs,
also read [shared-pattern review](references/pattern-sweep.md). Research the
next missing edge through Mehscan. Start component-scoped references with
`--summary true`, then inspect decisive source. Widen for missing edges,
cross-component callers or truncation. Research is not limited to bundle text.

Reuse inspected facts, checking each ID's actor, producer, branch, operand,
control and effect. A shared fact is not a shared verdict. Journal code-evidence
queries under the ID that prompted them; do not repeat a query to populate
another journal. Preserve consequential adjacent questions as separate
unreviewed leads or existing inventory IDs.
Batch already-known independent lookups in one tool turn, retaining each query's
journal. Wait for results before choosing dependent queries; keep batches focused.

Return `issue` for a shown weakness, `not_issue` for an affirmatively safe or
inapplicable relationship, and `needs_review` for a decisive fact unavailable
after targeted research. State uncertainty; keep inference separate from
scanner facts. Load [finalize and report](references/finish-review.md) when
ready to write decisions. Consult [commands](references/commands.md) only for
an operation not covered by these guides. A supplied subset remains a scoped
review, not a complete application assessment.

## New scan or repository-wide review

| Job | Command or guide |
| --- | --- |
| Candidate scan | `mehscan scan ROOT --format candidates` (or `json`) |
| Changed lines | `mehscan scan ROOT --changed-from BASE --format candidates` |
| Repository AI review | [Review planning](references/review-planning.md) |

Candidates are leads, not confirmed vulnerabilities. Default to Value mode;
honor Comprehensive or a requested category. Value prioritizes stronger signals,
clearly justified fixes and promising high-impact leads, including useful medium
issues. Comprehensive covers admitted plausible medium-or-higher issues; it is
not a queue for every raw sink occurrence. Excluded observations remain supporting
facts, not safe verdicts or mandatory deferred reviews. Planning maps the stack and attack
surface and workload before triage; use a small first chunk to measure review
pace and plan the next pass within the user's time budget.
Planning ranks work, accounts for deferred IDs and chooses small chunks or
disjoint agent assignments when requested. Read it for repository scope or
queue decisions, then use the supplied-bundle flow for each selected chunk.
Keep the whole-run plan current and continue authorized work in auto mode.

Use [review scope policy](references/review-scope.md) when choosing modes or
reconsidering a noisy family. It defines practical admission and language
differences; load it once for those decisions, not for each supplied bundle.

Reuse an inventory enriched with supplied Roslyn or TypeScript context;
do not rerun a compiler per ID. Planning describes context flags and scope
lanes. Never turn deferred work into a safe verdict.

For later repository knowledge, policy or severity recalibration, use
[Mehscan revalidation](../mehscan-revalidation/SKILL.md) against validated
responses, preserving the original record.
