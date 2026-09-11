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

Review requests remain self-contained JSON. They carry only facts that may
affect a verdict:

- stable job, bundle, review, rule, and evidence identities;
- exact rule semantics and the security question;
- structured source, sink, control, and configuration observations;
- bounded source excerpts;
- a deterministic flow when one exists;
- established facts, effective controls, and unresolved facts;
- non-default reachability, availability, and truncation context; and
- the exact response contract.

Repeated formatting is not useful model context. Request files are serialized
as compact JSON. The manifest remains readable and retains review membership,
sizes, and fingerprints. Larger structural deduplication, such as shared rule
and excerpt tables, requires a separately versioned review-request v2 and must
be justified by bundle measurements and model-convergence tests.

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
  "review_id": "...",
  "decision": "issue",
  "confidence": "high",
  "summary": "...",
  "checks": []
}
```

Allowed decisions are `issue`, `not_issue`, and `needs_review`. `checks` is
empty for decided results and contains only decisive missing facts for
`needs_review`. The response does not repeat locations, flow, CWE, severity,
or rule metadata; the reporter joins those deterministic fields by review ID.

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
- `title`: deterministic rule title;
- `description`: validated instance-specific reviewer summary;
- `status`: `issue` or `needs_review`;
- `severity`: impact level plus its source;
- `confidence`: final triage certainty;
- `category` and `cwes`: security classification;
- `primary_location`: principal sink or policy location;
- optional `flow`: only a deterministic bounded path;
- `related_locations`: sources, controls, and neighboring evidence;
- optional decisive `checks`; and
- compact review/evidence provenance.

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
- `codeFlows` only for deterministic paths;
- stable finding fingerprints; and
- confidence, CWE, category, and review IDs in result properties.

`needs_review` and `not_issue` decisions remain in canonical JSON. They are not
published as vulnerabilities to IDE, CI, or ASPM consumers.

## Markdown projection

`report --format markdown` emits a human-readable handoff from the same
canonical finding report. It contains scan and reviewer identity, outcome
counts, review-required items with decisive checks, confirmed issue summaries,
and not-issue summaries when `--include-dismissed true` is set. Markdown is a
projection for people, not a replacement for canonical JSON or SARIF.

## Storage defaults

An end-to-end run persists the manifest, compact requests, model responses, and
final reports. Full scanner JSON is optional diagnostic material. Serialized
scan roots are `.` and every artifact location is repository-relative; local
absolute checkout paths are process details and are not written to portable
artifacts.
