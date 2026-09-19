# Mehscan

Mehscan is a source security scanner built for developers and AI coding agents. It identifies security-relevant code, prepares evidence for review, and produces actionable security reports.

Mehscan is under active development. It supports C, C++, C#, Java, JavaScript, TypeScript/TSX, Python, Go, and Rust, with partial PHP and Kotlin JVM coverage. Coverage varies by language and framework; see the [PHP](docs/php-coverage.md) and [Kotlin](docs/kotlin-coverage.md) profiles for their limitations.

See [extended SQL and NoSQL coverage](docs/extended-database-coverage.md) for database query mechanics and remaining language-specific gaps.

## What it does

- Scans source code locally without executing build tools or application code.
- Collects evidence and bounded relationships for security review.
- Prepares self-contained review bundles for an AI coding agent.
- Exports JSON, SARIF, and Markdown reports.

Scan candidates require review before they become confirmed findings. The CLI works independently of any model provider, agent, or plugin.

## Install

The repository includes a release installer for PowerShell 7. It requires GitHub CLI (`gh`) with attestation verification support; GitHub login is not required.

```powershell
./skills/mehscan-security/scripts/install-mehscan.ps1 -Version 0.4.0
```

The installer verifies release checksums and provenance, then returns the executable path. See the [installation instructions](skills/mehscan-security/SKILL.md) for supported assets and source commit pinning. Release downloads are also available on the [releases page](https://github.com/meh-security/mehscan/releases).

To build from source, use Rust 1.88 or newer:

```text
cargo build -p mehscan-cli --release
```

The executable is `target/release/mehscan` (`mehscan.exe` on Windows).

## Quick start

```text
mehscan scan path/to/repository
mehscan scan path/to/repository --format json
mehscan scan path/to/repository --format sarif-candidates > mehscan-candidates.sarif
```

To scan changes relative to a Git revision:

```text
mehscan scan path/to/repository --changed-from HEAD --format candidates
```

Use `mehscan --help` or `mehscan scan --help` for additional options.

## AI-assisted review

Prepare review bundles for your agent:

```text
mehscan investigate review-bundles path/to/repository --output mehscan-review --max-reviews 20 --max-bytes 524288
```

The optional [security skill](skills/mehscan-security/SKILL.md) guides the agent through review and response validation. After review, generate a report from validated responses:

```text
mehscan report --run mehscan-review --responses mehscan-review/responses-reviewer --format markdown --output mehscan-report.md --reviewer reviewer-id
# For deliberately scoped triage; output includes completed/total review coverage:
mehscan report --run mehscan-review --allow-partial true --format markdown --output mehscan-partial-report.md
# Generate the exact response contract without a PowerShell helper:
mehscan investigate review-response-schema --bundle REQUEST.json --output response-schema.json
```

A complete review requires a validated response for every request in the manifest. Selected or sampled reviews cover only the reviewed scope. The [report quality skill](skills/mehscan-report-quality/SKILL.md) checks the final handoff for clarity and actionability.

## Documentation

- [Review and reporting formats](docs/output-contract.md)
- [AI reviewer contract](docs/ai-reviewer-contract.md)
- [AI triage contract](docs/ai-triage-contract.md)
- [Extended rule gap analysis](docs/extended-rule-gap-analysis.md)
- [Extended database coverage](docs/extended-database-coverage.md)
- [Latest release notes](docs/release-notes-v0.4.0.md)

## License

Mehscan-owned source is licensed under the [Apache License 2.0](LICENSE). Bundled ast-grep source retains its [MIT license](crates/ast-grep/LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md).
