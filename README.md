# Mehscan

Mehscan is a source security scanner for developers and AI coding agents. It finds security-relevant code, collects evidence for review, and produces reports with findings and follow-up questions.

It runs locally without building or executing your application. Use the CLI on its own, or pair it with the security skill to investigate candidates with your coding agent.

## Features

- Scan a repository or review changed files.
- Follow relevant source, imports and helper implementations during review.
- Prepare review bundles for AI coding agents.
- Keep findings, dismissals and unresolved questions with their supporting evidence.
- Export JSON, SARIF and Markdown reports.

Mehscan supports C, C++, C#, Java, JavaScript, TypeScript/TSX, Python, Go and Rust, with partial [PHP](docs/php-coverage.md) and [Kotlin](docs/kotlin-coverage.md) support. See the [coverage guide](docs/coverage.md) for language and framework limits.

## Installation

Download a package from [GitHub Releases](https://github.com/meh-security/mehscan/releases), or use the installer from this checkout.

**Linux and macOS**

```sh
bash ./skills/mehscan-security/scripts/install-mehscan.sh --version 0.9.0
```

**Windows**

```powershell
pwsh -NoProfile -File ./skills/mehscan-security/scripts/install-mehscan.ps1 -Version 0.9.0
```

The installers require GitHub CLI (`gh`). Linux/macOS also need Bash and Python 3.9+; Windows needs PowerShell 7. See the [installation guide](docs/installation.md) for platform setup and installation options.

To build from source, use Rust 1.88 or newer and native C/C++ build tools:

```sh
cargo build -p mehscan-cli --release --locked
```

The executable is `target/release/mehscan` (`mehscan.exe` on Windows).

## Quick start

Scan a repository:

```sh
mehscan scan path/to/repository
```

Save the candidates as JSON or SARIF:

```sh
mehscan scan path/to/repository --format json > candidates.json
mehscan scan path/to/repository --format sarif-candidates > candidates.sarif
```

Candidates are starting points for investigation. Review them before treating them as confirmed vulnerabilities.

Review changed files:

```sh
mehscan scan path/to/repository --changed-from HEAD --diff-mode files --format candidates
```

See the [Changed review guide](skills/mehscan-security/references/changed-review.md) for local changes, pull requests and release comparisons.

## AI-assisted review

Use the [Mehscan security skill](skills/mehscan-security/SKILL.md) with your coding agent to review a repository or a change. The skill uses your agent's model and Mehscan's source lookup tools to investigate the relevant code.

**Value** is the default review mode. It prioritizes useful security leads and keeps deferred work visible. Choose **Comprehensive** to cover every admitted review item. Findings include supporting evidence; unresolved items identify what still needs investigation.

For manual bundle review:

```sh
mehscan investigate review-bundles path/to/repository --output mehscan-review
```

After your agent has reviewed the bundles, generate a report:

```sh
mehscan report --run mehscan-review --responses mehscan-review/responses-reviewer --format markdown --output mehscan-report.md --reviewer reviewer-id
```

For scripted use, the [local AI worker](docs/review-worker.md) runs a configured reviewer and tracks review progress. The [Codex adapter guide](docs/codex-reviewer.md) covers model setup, dependencies and optional flow diagnostics. The [advisory GitHub Action](docs/github-action.md) supports pull-request and release review.

## Documentation

- [Installation](docs/installation.md)
- [Language coverage and source scope](docs/coverage.md)
- [Review and report formats](docs/output-contract.md)
- [Local AI worker](docs/review-worker.md)
- [Codex reviewer setup](docs/codex-reviewer.md)
- [Review state and history](docs/review-state.md)
- [GitHub Action](docs/github-action.md)
- [Extended SQL and NoSQL coverage](docs/extended-database-coverage.md)
- [Release notes](docs/release-notes-v0.9.0.md)

Optional experimental backends provide additional compiler context for [C# through Roslyn](https://github.com/meh-security/mehscan/blob/main/backends/roslyn/README.md) and [JavaScript/TypeScript](https://github.com/meh-security/mehscan/blob/main/backends/typescript/README.md). They are available in the source repository. Standard scanning requires neither backend.

## License

Mehscan-owned source is licensed under [Apache License 2.0](LICENSE). Bundled ast-grep source retains its [MIT license](crates/ast-grep/LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md).
