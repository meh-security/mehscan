# Mehscan

Mehscan is a source security scanner built for developers and AI coding agents. It identifies security-relevant code, prepares evidence for review, and produces actionable security reports.

Mehscan is under active development. It supports C, C++, C#, Java, JavaScript, TypeScript/TSX, Python, Go, and Rust, with partial PHP and Kotlin JVM coverage. Coverage varies by language and framework; see the [PHP](docs/php-coverage.md) and [Kotlin](docs/kotlin-coverage.md) profiles for their limitations.

## What it does

- Scans source code locally without executing build tools or application code.
- Collects evidence and bounded relationships for security review.
- Prepares self-contained review bundles for an AI coding agent.
- Exports JSON, SARIF, and Markdown reports.

Scan candidates require review before they become confirmed findings. The CLI works independently of any model provider, agent, or plugin.

## Install

First check for `mehscan` on `PATH` and run `mehscan --version`. Reuse an
available executable; setup tools and downloads are needed only when it is
absent. An explicit version mismatch is reported without installing another
copy. The PowerShell installer is Windows-only.

We recommend GitHub CLI (`gh`) for release installation: its attestation verifier checks that the downloaded archive was built by Mehscan's expected GitHub Actions workflow from the expected source, rather than relying on a checksum alone. Both installers require `gh` with attestation verification support, without GitHub login. Linux/macOS use Bash and Python 3.9+; Windows uses PowerShell 7. These tools are installation dependencies only.

Linux/macOS (no PowerShell):

```sh
bash ./skills/mehscan-security/scripts/install-mehscan.sh --version 0.4.0
```

Windows:

```powershell
pwsh -NoProfile -File ./skills/mehscan-security/scripts/install-mehscan.ps1 -Version 0.4.0
```

The installer verifies release checksums and provenance, then returns the executable path. See the [platform installation instructions](skills/mehscan-security/references/installation.md) for prerequisite setup, Bash/Zsh examples, supported targets, and a source-build alternative without PowerShell. See the [security skill](skills/mehscan-security/SKILL.md) for source commit pinning. Release downloads are also available on the [releases page](https://github.com/meh-security/mehscan/releases).

If `gh` or your platform's installer prerequisites are unavailable or installing them is unsuitable, build from an existing trusted Mehscan source checkout with Rust 1.88 or newer and native C/C++ build tools. The installer does not automatically build or execute an unverified download:

```text
cargo build -p mehscan-cli --release --locked
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
```

A complete review requires a validated response for every request in the manifest. Selected or sampled reviews cover only the reviewed scope. The [report quality skill](skills/mehscan-report-quality/SKILL.md) checks the final handoff for clarity and actionability.

## Documentation

- [Review and reporting formats](docs/output-contract.md)
- [AI reviewer contract](docs/ai-reviewer-contract.md)
- [AI triage contract](docs/ai-triage-contract.md)
- [Latest release notes](docs/release-notes-v0.4.0.md)

## License

Mehscan-owned source is licensed under the [Apache License 2.0](LICENSE). Bundled ast-grep source retains its [MIT license](crates/ast-grep/LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md).
