---
name: mehscan-security
description: Run Mehscan on an authorized codebase or triage a Mehscan review bundle. Use when the user asks for a Mehscan scan, candidate review, or security report.
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
| AI review | `mehscan investigate review-bundles ROOT --output DIR` |
| Existing bundle | Read the bundle; do not rescan. |

The scan lists **candidates**, not confirmed vulnerabilities. For AI review,
process the requests listed by `manifest.json`. A subset is a scoped review,
not a complete application assessment. See [commands](references/commands.md)
only when creating bundles, validating responses, or producing reports.

## Review one bundle

For each review ID, follow [the bundle workflow](references/review-workflow.md):
read its security question and deterministic facts, inspect the relevant
source through Mehscan, choose the next query needed to settle a missing edge,
and cite the decisive evidence behind the verdict. Read **one** matching guide from the
[bucket index](references/triage-buckets.md). The bucket identifies the
security relationship to test; the review's question identifies the exact
operation and operand.

Return `issue` for a shown weakness, `not_issue` for an affirmatively safe or
inapplicable relationship, and `needs_review` for a decisive fact that remains
unavailable after targeted queries. Keep reviewer inference separate from
Mehscan facts and retrieved text. Pass `--journal FILE`
to each investigation query and include only decisive source in
`investigation.decisive_artifacts`. State a newly discovered decisive missing
fact in `needs_review.checks` when needed. Set `journal_summary` to null in
the draft; use `review-bundle-finalize` to attach measured lookup counts and
validate the final response.
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
