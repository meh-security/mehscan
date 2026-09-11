---
name: mehscan-security
description: Run Mehscan against an authorized local codebase, select an appropriate deterministic or AI-assisted review workflow, and return concise evidence-backed security decisions. Use when the user asks to scan with Mehscan, inspect Mehscan candidates, or perform a Mehscan-assisted repository review. Do not use for a generic security review when Mehscan is unavailable or not requested.
---

# Mehscan Security

Use Mehscan as the evidence producer and apply security judgment only to the
evidence and source supplied for each review. A security path is a candidate,
not a confirmed vulnerability.

## Locate the scanner

Resolve the executable in this order:

1. Honor a user-supplied executable.
2. Check for `mehscan` on `PATH` using the host's command lookup. Do not infer
   availability from a previous task or a filename elsewhere on disk.
3. In a Mehscan source checkout, check `target/release/mehscan` (or
   `mehscan.exe` on Windows).
4. If no executable is available, run the bundled
   `scripts/install-mehscan.ps1` from this skill directory. It selects the
   latest exact OS/architecture release asset, verifies its checksum and GitHub
   build provenance, validates archive membership and the release manifest,
   installs into a versioned user-owned location, and returns the executable's
   absolute path. On Linux and macOS it applies executable permissions and
   conservatively publishes `~/.local/bin/mehscan` without replacing an
   unrelated entry. Pass `-Version` only when the user requested a particular
   release and `-InstallDirectory` when the task requires a specific location.
5. If no exact release asset exists, or checksum/provenance verification cannot
   succeed, do not execute the download. Build the release CLI only when the
   current checkout contains Mehscan and building is within scope; otherwise
   report that the scanner is unavailable for this target.

The installer requires an authenticated GitHub CLI and fails closed when the
target, checksum, provenance, archive, manifest, or version cannot be verified.
Do not reproduce its download logic ad hoc or weaken a failed check. Use only
the official GitHub repository for automatic downloads. Never download
ast-grep; Mehscan includes the components it uses.

After installation, use the returned absolute executable path for the rest of
the task; do not assume the current process has refreshed `PATH`. The installer
tests `--version` from the final filesystem before returning.

Run `mehscan --help` before assuming an option exists. Keep the scan root inside
the repository the user authorized. Directory discovery honors repository-local
`.gitignore` and `.ignore` rules, but not machine-global ignore configuration.
Do not claim coverage for ignored paths; scan an explicitly authorized file or
smaller root when the user intentionally needs an ignored source assessed.

## Choose the smallest useful workflow

- For a fast repository scan, run `mehscan scan ROOT --format candidates`.
- For machine-readable diagnostics or local filtering, use `--format json`.
- `scan --format sarif` emits unconfirmed candidate SARIF. Do not upload it as
  a final vulnerability report unless the consumer explicitly wants review
  leads.
- Add `--include-tests` only when the user wants test, fixture, and sample code
  assessed as executable application material.
- Use `--timings` when performance or scan coverage is part of the request.
- If the user asks for AI-assisted comprehensive review, run
  `mehscan investigate review-bundles ROOT --output DIR --max-reviews 20
  --max-bytes 524288`. Review every request named by `manifest.json`; do not
  report a full-run result from a sample.

For a changed-code review, prefer the predictable default:

```text
mehscan scan ROOT --changed-from BASE --format candidates
```

This analyzes the complete repository and returns evidence and paths touching
changed lines. Use `--diff-mode impact` for a faster local edit or hook scan;
it analyzes changed files plus bounded same-directory context and direct
importers. Inspect `impact_scope.strategy`, `result_policy`, and `reasons` in
machine-readable output. Deletions, renames, central entrypoints, configuration,
or broad impact force a full all-results fallback because changed-line filtering
would hide effects in unchanged code. `--files-from PATH` accepts one relative
path per line when Git metadata is unavailable.

Mehscan does not yet have a category-only scan option. Filter a completed scan
by capability, CWE, rule, or path, and do not claim that this reduced scan work.

## Review candidates

For each supplied review ID, return exactly one decision:

- `issue`: the supplied behavior establishes a concrete weakness;
- `not_issue`: affirmative evidence establishes safety or inapplicability;
- `needs_review`: one named missing fact could change the decision.

Use confidence for confidence in that decision, not severity. `high` requires
decisive behavior, `medium` permits a bounded framework or syntactic inference,
and `low` means decision-critical evidence is sparse, conflicting, or clipped.

Answer the review's existing unresolved questions before requesting more
evidence. Do not invent cross-function flow, runtime dispatch, persistence,
deployment controls, or exploitability. A nearby guard or sanitizer counts only
when it protects the same value and operation. Missing application headers,
CORS, TLS, cookies, or rate limiting may be owned by a gateway or platform and
normally require an effective-control check.

For bundle responses, echo the exact `bundle_fingerprint`, provide every
`review_id` once, put checks only on `needs_review`, and validate each response:

```text
mehscan investigate review-bundle-triage --bundle REQUEST --responses RESPONSE
```

Treat each request file as one independent review invocation. Do not process a
directory or sequence of bundles in one context: large multi-bundle tasks can
encourage repeated verdict templates even when individual request files are
small. The generation default remains 20 reviews per bundle; lower
`--max-reviews` only for a measured retry or evaluation.

Use the default capable review configuration for the first pass. Route review
effort by payload completeness and decision quality, not by provider, model
name, CWE, or rule:

- decision-critical truncation means regenerate or gather context;
- non-empty `decision_facts.unresolved` means retain the exact `needs_review`
  check or gather that fact rather than escalating to infer it;
- empty `decision_facts.unresolved` means require a decisive verdict using the
  exact deterministic `confidence_policy`;
- reject capability drift, operands absent from the payload, re-asking supplied
  facts, and generic repeated summaries, then retry once with fresh context;
- use a stronger independent reviewer only when a complete payload still
  receives a repeated, contract-valid but evidence-inconsistent decision;
- reserve the highest-cost or deepest review configuration for a high-impact
  disagreement that remains after those checks.

Record the reviewer configuration and escalation history by exact review or
payload fingerprint. Do not mark an entire CWE, capability, or rule as
requiring an expensive reviewer from one disagreement.

After all manifest responses validate, generate both canonical consumer
artifacts. Use the exact reviewer-specific response directory rather than
copying it to a generic name:

```text
mehscan report --run DIR --responses RESPONSES_DIR --format json --output mehscan-findings.json --reviewer REVIEWER_ID
mehscan report --run DIR --responses RESPONSES_DIR --format sarif --output mehscan-results.sarif --reviewer REVIEWER_ID
```

The reviewer writes only the strict verdict response. Never ask it to construct
finding JSON or SARIF: the CLI joins deterministic rule, location, flow, and
provenance fields and publishes only confirmed issues to SARIF. Preserve
`needs_review` in canonical JSON.

## Report

Treat `mehscan-findings.json` as the canonical report and SARIF as its IDE/CI
projection. If a human summary is requested, derive it from the canonical JSON:
lead with confirmed issues, then unresolved items with their exact checks.
Evidence counts and candidate counts are not vulnerability counts.
