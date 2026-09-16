# Mehscan 0.2.1

Mehscan 0.2.1 improves source review handoffs and final reports across supported
languages, and packages verified releases for four operating system targets.
Analysis remains source-only; target projects are not compiled or executed.

## Review and report fixes

- Behavior-first finding titles and concrete remediation use rule semantics
  and weakness families across languages. Specific native memory and filesystem
  repairs retain precedence over generic categories.
- Signing-key origin, NoSQL selectors, token protection, throttling, authorization,
  recovery, validation, injection, and filesystem guidance distinguish the exact
  source behavior. Unknown repairs remain explicit report-quality warnings.
- Stored HTML follow-ups identify the producer and persistence boundary whose
  controls need inspection.
- New review manifests and canonical JSON carry scan coverage and scope. Older
  manifests remain readable and disclose missing coverage.
- Markdown groups findings with the same behavior and repair across rule IDs,
  retaining every location and verdict. Confirmed instances and repair groups
  are counted separately; neither is a unique vulnerability count.
- Associated feature policies remain contextual associations. Reports do not
  treat them as proven runtime gates or reachability controls.
- Both bundled skills retain the complete review and report-quality workflow.

## Release and installation

The release workflow tests, builds, extracts, and smoke-tests each target:

| Target | GitHub-hosted runner |
| --- | --- |
| Linux x86_64 | Ubuntu 24.04 |
| Windows x86_64 | Windows 2025 |
| macOS x86_64 | macOS 15 Intel |
| macOS aarch64 | macOS 15 Apple Silicon |

All four jobs must pass before publication. Each ZIP has a SHA-256 checksum and
GitHub artifact attestation. Publication verifies the complete asset set and
uses these reviewed release notes. Tags must point to commits reachable from
`main`, and package versions must match the tag.

The bundled installer downloads public assets and attestation bundles without
GitHub login. PowerShell 7, GitHub CLI with `attestation verify`, and network
access remain prerequisites. Verification enforces provenance and package
contents; there is no checksum-only fallback.

The independently distributed skill source pin for 0.2.1 is added after the
merged release commit is selected. Until that pin is distributed, installations
should explicitly pass `-Version 0.2.1 -SourceDigest` with the independently
trusted full release commit. The convenience skill inside the archive retains
the existing 0.2.0 pin; it cannot embed its own future merge commit.

## Validation and limits

A fresh Juice Shop scan produced 112 independently triaged review items across
27 bundles. Reassembling the validated decisions with the reporting fixes
preserved all decisions: 56 confirmed instances, 4 needing review, and 52
dismissed. The final Markdown contains 32 repair groups and passed independent
report-quality review with minor warnings. This validates report assembly; it
does not claim a second independent model triage or runtime exploit validation.

Affected engine and CLI tests passed locally (364 passed, 36 optional corpus
tests ignored), alongside core reporting tests and strict Clippy checks. The
four-platform release workflow supplies the publication gates.

Coverage exclusions, unsupported files, parse failures, unresolved runtime
facts, and fallback severity remain disclosed. Confidence describes review
certainty and does not establish impact priority.
