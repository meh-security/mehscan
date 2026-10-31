# Mehscan review and reporting contract

Status: accepted implementation contract

## Goals

Mehscan uses one executable for deterministic scanning, AI-review preparation,
response validation, and final reporting. Each boundary has a purpose-specific
format:

```text
source -> Rust evidence -> review request JSON -> verdict JSON
       -> canonical finding JSON -> SARIF + Markdown
```

SARIF is an external findings format. It is not the transport between the
deterministic scanner and the reviewer.

## Commands

```text
mehscan scan PATH --format json|candidates|sarif-candidates
mehscan investigate review-bundles PATH --output RUN_DIR
mehscan investigate review-response-schema --bundle FILE --output SCHEMA
mehscan investigate review-bundle-finalize --bundle FILE --draft FILE --journal-dir DIR --output FILE --source-root PATH
mehscan investigate review-bundle-triage --bundle FILE --responses FILE
mehscan report --run RUN_DIR [--responses DIR] --format json|sarif|markdown
```

`scan --format sarif-candidates` remains candidate SARIF: every result is an
unconfirmed review lead. The legacy `sarif` spelling remains an alias.
`report --format sarif` is post-triage SARIF and contains confirmed issues only.
`report --format markdown` is a human-readable projection. It leads with items
that still require review and their exact checks, then summarizes confirmed
issues and dismissed candidates. Pass `--include-dismissed true` to include the
not-issue decision summaries rather than only their count.

## Review request

### Changed scope

`scan --diff-mode files` and scoped `investigate review-inventory` analyze whole
existing changed files, without sibling/importer expansion or full fallback.
Changed inventories default to this mode; `scan` retains its Full default.
Deleted, renamed, unsupported and excluded paths remain change metadata, even
when there are no admitted questions. A separate reviewer change pass is needed
for removed controls and affected unchanged consumers; the CLI does not certify
that pass or PR completeness.

Inventory schema 25 carries optional `impact_scope` through jobs, bundle requests,
manifests and canonical `scan.impact_scope`. The report and bundle schema versions
remain compatible with these additive optional fields. SARIF run properties carry
the same scope as `impactScope`. Git scope includes requested refs, resolved base,
HEAD and target commits, optional merge base, working-tree semantics, file status
and new-side changed-line ranges. An explicit file list has no Git comparison.
The separate `snapshot_fingerprint` binds raw changed-file bytes with SHA-256,
including ignored, unsupported and non-UTF-8 files. Deleted paths and symlink
pointers retain their own states; symlink targets outside the root are not read.
Directories/gitlinks retain pointer/status metadata rather than recursive content
coverage. A snapshot binding is not semantic finding identity or verdict reuse.

`--target` requires a clean checkout at that exact commit. `--merge-base` compares
one merge base against the target; direct endpoints support release deltas.
Optional compiler inputs currently require full analysis. Scoped requests inherit
inventory scope and cannot replace it through bundle command flags.

Scoped finalization, triage, summary and reports require `--source-root`, the
original manifest/request layout and `input-binding.json`. They revalidate the
Git comparison, repository source fingerprint and bound request contents. Store
output outside the source worktree. Ref movement or changed source/context bytes
requires regenerating the inventory. Snapshot hashes bind current reviewer work;
native question identity below has a separate purpose.

### Native operation and triage identity

New inventories, jobs and bundles carry `identity_catalog` schema 1. Supply a
stable opaque `--repository-key`, such as `github.com/repositories/123`, on
`review-inventory`, `review-jobs`, `review-tasks` or direct `review-bundles`.
Use a platform repository ID or a configured persistent namespace, not an owner
name, credential-bearing remote URL or absolute checkout path. There is no
automatic remote-to-platform mapping. Without a namespace, continuity is
explicitly `unscoped`, with no cross-repository uniqueness guarantee.

For fork PRs, the assessed repository key is the base product; the optional
`--source-repository-key` records the fork/head provenance separately. Inventory
selection inherits both keys and rejects overrides. Git subdirectory scans use
the repository-relative prefix. For non-Git sources, ROOT must be the complete
repository source root; arbitrary extracted subdirectories have no inferred prefix.

`occurrence_key` uses versioned canonical typed serialization and SHA-256 over
repository namespace, rule/invariant, repository-relative path, language,
enclosing symbol, typed operation tokens, operation role and structural control
scope. `subject_key` adds the native source-to-operation relationship, or an
explicit operation question when no deterministic flow exists. Neither key
contains a verdict, severity, tool release, commit, run ID or entire proof flow.
The finding's `id` projects the occurrence key; existing review/evidence IDs
remain snapshot work handles and provenance.

Typed AST normalization removes comments and incidental whitespace. String,
character, regex and directive contents retain exact value distinctions through
digests rather than copying their text into identity metadata. Python control
indentation remains in structural scope. Parsing gaps, non-exact anchors and
oversized operations use a bounded exact-source digest and `snapshot_bound`
continuity. Identical site/producer tuples are detected before selected queue
pagination; ambiguous sites retain distinct snapshot discriminators and never
inherit continuity through an ordinal. Moves, operand rewrites and some control
changes can change keys; automatic aliases are not implemented.

Finalization recomputes tuple hashes and checks namespace, invariant/path and
selected-anchor binding. Inventory-backed jobs compare regenerated identities
against the current source catalog. Compact inventory entries expose identity
summaries; full tuples remain in the catalog. Context currently means a typed
`source_only` assessment with its source boundary, not deployment applicability.

Canonical JSON always retains `decision_records` for all three verdicts,
independently of `--include-dismissed`. Each record includes native identity,
source/inventory/job/bundle basis, a response digest, native evidence/proof paths
and the complete validated response with decisive artifacts, citations and
blockers. Matching keys never makes that evidence current or authenticates its
producer. An issue and pending subject remain separately reportable at the same
occurrence. Reports do not select an authoritative current decision. The optional
[local state store](review-state.md) admits validated native runs, retains all
proof, fences stale generations and requires exact-parent supersession. Waivers,
hosted publication and cross-revision safe-verdict reuse remain separate work.

Confirmed SARIF exposes structural namespaced keys in
`partialFingerprints["mehscanFinding/v2"]` and identities in result properties.
Unscoped/uncertain records use separately named matching hints. Legacy bundles
without catalogs retain the v1 projection. New catalogs also carry an optional
`primary_location_fingerprint`: the exact snapshot primary location and GitHub's
`primaryLocationLineHash`. The engine hashes original bound source once per
represented file, including unselected lines for duplicate counts. Report rendering
exports the hint only when its location exactly matches the finding. The hint is
excluded from native occurrence/subject keys, but included in job/bundle bindings.
Missing source or unsupported standalone-CR position mapping omits the hint; legacy
bundles do not acquire a hash from a later checkout.

Line hashing follows the [GitHub upload-sarif algorithm](https://github.com/github/codeql-action/blob/main/src/fingerprints.ts)
(checked 2026-10-11): a 100-unit rolling window over UTF-16, with spaces/tabs skipped,
normalized line endings and per-file duplicate counts. Compatibility tests use
GitHub's published vectors. [GitHub code scanning](https://docs.github.com/en/code-security/reference/code-scanning/sarif-support-for-code-scanning)
uses this line hint; custom native keys do not guarantee distinct GitHub alerts for
different operations on the same line. Mehscan retains those distinct occurrences
and their decisions. Actual alert ingestion remains untested. Confirmed-only SARIF
remains a finding projection; all-verdict history stays in canonical JSON.

Aggregation keeps `flow` and `additional_flows` as separate complete native paths,
deduplicated and ordered deterministically for the same verdict. It never joins
alternative sources into a fabricated path or promotes a pending path into issue
proof. SARIF exports one `codeFlow` per path, preserving every represented step;
Markdown lists each path's source/sink endpoints. Observations without native paths
retain related evidence without acquiring a flow. This is bounded engine evidence,
not a claim of exhaustive whole-program data flow. Git subdirectory prefixes apply
to every SARIF primary, related and flow URI so paths address the repository root.
GitHub can truncate displayed flows or reject output exceeding its ingestion limits;
upload-size guardrails and explicit projected truncation are still integration work.

### Request contents

Review requests are self-contained JSON. They carry facts that may
affect a verdict:

- stable job, bundle, review, rule, and evidence identities;
- exact rule semantics and the security question;
- structured source, sink, control, and configuration observations;
- bounded source excerpts;
- a deterministic flow when one exists;
- established facts, effective controls, and unresolved facts;
- non-default reachability, availability, and truncation context; and
- a playbook for the selected review question.

Request files are compact JSON. The manifest retains review membership,
sizes, fingerprints, and coverage.

The following concepts must remain distinct:

- severity (impact) and confidence (certainty);
- rule identity and finding identity;
- verdict, reachability, and build availability;
- source, sink, and effective control;
- decisive checks and remediation; and
- deterministic match confidence and reviewer confidence.

## Reviewer response

The reviewer returns one strict result per review:

```json
{
  "schema_version": "1.3",
  "bundle_fingerprint": "...",
  "results": [{
  "review_id": "...",
  "selected_anchor_id": "...",
  "decision": "issue",
  "confidence": "high",
  "summary": "...",
  "checks": [],
  "investigation": {
    "decisive_artifacts": [],
    "journal_summary": null,
    "citations": [{"artifact_id": "...", "claim": "..."}],
    "reviewer_inferences": [],
    "reviewer_origin_leads": [],
    "blockers": []
  }
  }]
}
```

Allowed decisions are `issue`, `not_issue`, and `needs_review`. `checks` is
empty for decided results and contains only decisive missing facts for
`needs_review`. Finalization fills `journal_summary` from recorded queries and
checks exact source excerpts. The response does not repeat flow, CWE, severity,
or rule metadata; the reporter joins those fields by review ID.

## Canonical finding JSON

`report --format json` is the canonical consumer artifact. It contains:

- tool, scan, and reviewer identity;
- counts for review decisions and deduplicated outputs;
- confirmed `findings`;
- deduplicated `review_required` records;
- a dismissed-review count and optional compact dismissed audit records; and
- review-quality warnings.

A reported result uses one name for each concept:

- `id`: stable instance identity;
- `rule_id`: stable security invariant identity;
- `title`: deterministic behavioral title selected for the specific invariant;
- `description`: validated instance-specific reviewer summary;
- `status`: `issue` or `needs_review`;
- `severity`: impact level plus its source;
- `confidence`: final triage certainty;
- `category` and `cwes`: security classification;
- `primary_location`: principal sink or policy location;
- optional `flow` and `additional_flows`: separate deterministic bounded paths;
- `related_locations`: sources, controls, and neighboring evidence;
- optional decisive `checks`; and
- compact review/evidence provenance.

An `issue` can report a directly observed unsafe SQL, shell-command, or
code-evaluation construction in an operation that should treat input as data,
with low confidence when its runtime exposure remains unresolved. Its
description must name that uncertainty; it must not claim a demonstrated
exploit path. An intentional CLI command or evaluator option with unknown
invocation authority remains `needs_review`.

Severity is never derived from confidence or path state. Until a rule has an
adjudicated severity default, JSON reports `medium` with
`source: fallback_default`; SARIF renders it as a warning without claiming a
CVSS score. This keeps consumer behavior predictable while making the fallback
explicit.

## SARIF projection

`report --format sarif` emits SARIF 2.1.0 containing confirmed issues only:

- `kind: fail`;
- stable invariant-based `ruleId`;
- severity-derived `level`;
- primary and related locations;
- one `codeFlow` per represented deterministic path, with all native steps;
- stable finding fingerprints; and
- confidence, CWE, category, and review IDs in result properties.

`needs_review` and `not_issue` decisions remain in canonical JSON. They are not
published as vulnerabilities to IDE, CI, or ASPM consumers.

### Stable categories and advisory publication

`report` accepts `--sarif-category CATEGORY` and optional `--sarif-run-id ID`.
JSON retains the resolved configuration in `scan.sarif_automation`; core consumers
can supply the same validated `SarifAutomationConfiguration`. The default category
is `mehscan/triaged`, or `mehscan/triaged/changed` whenever a change scope is present,
including empty/deletion-only scopes and full-scan fallbacks. The latter describes
a change-scoped job, not an assertion that native results cover the entire diff.
Reviewer/model, PR number, commit, file set and hash algorithm version do not enter
the default category. Reviewer identity remains run provenance. Custom categories
describe stable analysis partitions; caller configuration must keep their scope
consistent. A category name alone cannot change the typed analysis scope.

The SARIF automation ID is always `CATEGORY/RUN_ID`, with a trailing slash when
the optional run ID is absent. This follows [GitHub's category/run-ID mapping](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).
Run IDs distinguish attempts without creating new categories. Category is limited
to 256 ASCII characters in nonempty slash-separated segments; run ID is one
segment up to 128 characters. Segments accept letters, digits, '.', '_' and '-';
empty, '.' and '..' segments are rejected. Configuration is separate from native
keys, job/source bindings and decision evidence. Malformed configuration fails
before output is written.

Examples of explicitly configured stable partitions:

```text
mehscan report --run BRANCH_RUN --format sarif --sarif-category mehscan/triaged/branch
mehscan report --run PR_RUN --source-root ROOT --format sarif --sarif-category mehscan/triaged/pr-delta --sarif-run-id attempt-2
mehscan report --run RELEASE_RUN --source-root ROOT --format sarif --sarif-category mehscan/triaged/release-delta
```

SARIF run `properties.publication` records `analysis_scope` (`scan_root` or
`change_comparison`), `review_work_complete` and `alert_disposition: not_established`.
Completion concerns the admitted/scheduled manifest work: missing, invalid or
deferred work stays incomplete. A completed `needs_review` response can still
leave a security question unresolved. Completed work, a custom category, zero
results or a deletion-only scope never authorizes remediation or alert closure.
Direct engine reports retain their bundles' common change scope and reject mixed
comparisons. Manifest reports preserve scope even when no bundles were generated.

This metadata is advisory. GitHub ignores custom run properties; it can close
absent alerts if a partial report is uploaded into an existing category. Separate
defaults reduce accidental partition overlap but do not make successive delta
uploads a safe authoritative baseline. Keep Changed/partial output as JSON,
Markdown or downloadable SARIF artifacts until an adapter validates publication
and actual ingestion/closure behavior. The CLI performs no upload.

Migration: the old reviewer-free ID `mehscan/triaged` implied category `mehscan`.
The new `mehscan/triaged/` consistently implies category `mehscan/triaged` (the old
reviewer-present category). Existing deployments must choose a stable category
deliberately and validate a fresh baseline; this change does not migrate, close or
reopen existing GitHub alerts. Candidate `scan --format sarif` remains a separate
projection and does not gain these confirmed-report configuration flags.

## Markdown projection

`report --format markdown` emits a human-readable handoff from the same
canonical finding report. It contains scan and reviewer identity, outcome
counts, review-required items with decisive checks, confirmed issue summaries,
and not-issue summaries when `--include-dismissed true` is set. Markdown is a
projection for people, not a replacement for canonical JSON or SARIF.

Confirmed instances are consolidated under one repair heading when
their behavioral title, capability, and remediation text match, including
equivalent operations observed by different rule IDs. A grouped
heading states its instance count; each instance retains its own location,
severity, confidence, and description. Summary counts continue to count
finding instances rather than Markdown headings. This presentation grouping
does not mutate canonical JSON, SARIF, verdicts, or finding identifiers.

Remediation is selected for the operation or weakness, not merely a broad
capability such as authentication or resource access. Unsupported invariants
leave remediation unset and emit an actionable quality warning instead of an
unrelated category fix. Known native-memory repairs remain invariant-specific.

Manifests record coverage totals and source-scope limitations,
which the CLI projects into canonical scan metadata and Markdown. Availability from explicit
source context is rendered without claiming deployment activation. Related
feature-policy descriptors are labeled as associations and never promoted into
proof that the reported operation is gated.

## Storage defaults

An end-to-end run persists the manifest, compact requests, model responses, and
final reports. Full scanner JSON is optional diagnostic material. Serialized
scan roots are `.` and every artifact location is repository-relative; local
absolute checkout paths are process details and are not written to portable
artifacts.

## Portable scope and aggregated explanations

`investigate review-bundles` accepts optional `--scope-label TEXT`,
`--project NAME` and `--revision REF` labels and persists them in manifest scope.
`report` inherits them and accepts the same options for existing runs. Supply
identical labels when rendering JSON, SARIF and Markdown. Labels are caller
metadata, not independently verified security facts. Generated manifests also
identify scanned source files and warn when review material was included.
Logical roots remain `.` and locations remain relative for portability.

When several issue decisions share one sink/invariant, the canonical finding
retains all distinct contributing issue explanations, source locations and
provenance. A superseded `needs_review` explanation is not appended to a confirmed
issue. This behavior applies across languages and preserves decision counts.
