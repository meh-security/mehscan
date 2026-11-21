# Mehscan

Mehscan is a source security scanner for developers and AI coding agents. It finds security-relevant code, collects evidence for review, and produces reports with findings and follow-up questions.

It runs locally without building or executing your application. Use the CLI on its own, or pair it with the security skill to investigate candidates with your coding agent.

## Features

- Scan a repository or review changed files.
- Follow relevant source, imports and helper implementations during review.
- Prepare review bundles for AI coding agents.
- Review original source with AI, including security questions beyond scanner candidates.
- Investigate serializer, deserializer and XML parser implementations with language-specific source checks.
- Match a Rust lockfile against a local copy of the RustSec advisory database.
- Keep findings, dismissals and unresolved questions with their supporting evidence.
- Retain local review history in Turso and reuse eligible decisions on unchanged source.
- Review a pinned pull-request diff in GitHub Actions with an optional coverage gate.
- Group related findings while preserving affected callers and conditions.
- Opt in to a bounded Fast audit or a Full audit of the selected results.
- Export JSON, SARIF and Markdown reports.

Mehscan supports C, C++, C#, Java, JavaScript, TypeScript/TSX, Python, Go and Rust, with partial [PHP](docs/php-coverage.md) and [Kotlin](docs/kotlin-coverage.md) support. See the [coverage guide](docs/coverage.md) for language and framework limits.

## Installation

Download a package from [GitHub Releases](https://github.com/meh-security/mehscan/releases), or use the installer from this checkout. The installer selects the latest published release when a download is needed.

**Linux and macOS**

```sh
bash ./skills/mehscan-security/scripts/install-mehscan.sh
```

**Windows**

```powershell
pwsh -NoProfile -File ./skills/mehscan-security/scripts/install-mehscan.ps1
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
mehscan scan path/to/repository --format candidates > candidates.json
mehscan scan path/to/repository --format sarif-candidates > candidates.sarif
```

Candidates are starting points for investigation. Review them before treating them as confirmed vulnerabilities.

Scan changed files for candidates:

```sh
mehscan scan path/to/repository --changed-from HEAD --diff-mode files --format candidates
```

See the [Changed review guide](skills/mehscan-security/references/changed-review.md) for local changes, pull requests and release comparisons.

## Local review memory

Persistent reviews use the same local Turso memory and journal in either mode,
including Changed scope. Keep the same repository key, stream and store for
successive reviews of the same branch and scope. Both modes load applicable
knowledge and can add source observations and admitted decisions when the review
closes, including after Fast or Full.

For rerun savings, a native-only review with the same source, plan and runtime
can reuse settled decisions with zero model calls for those IDs. A fresh work-plan
review loads prior knowledge and still evaluates its named checks. Keep the
original attempt directory to continue saved checks or audit existing results
without repeating the first pass. [Memory and reuse guide](docs/review-worker.md#reuse-on-reruns)

For manual setup, prepare an inventory with `--repository-key`, then run
`mehscan memory location --source-root ROOT --inventory RUN/inventory` to find
the journal and database. Set `MEHSCAN_STATE_HOME` to an absolute directory
outside the checkout to change their location. For one-shot work, use a
temporary journal and close with `state end --memory-mode temporary`.
The [local memory guide](docs/review-worker.md#capture-local-review-memory)
covers preparation, retention and importing older history.
Use [local worker assignments](docs/review-state.md#assign-reviews-to-local-workers)
to reserve distinct reviews, or [Turso sync](docs/review-worker.md#share-retained-context-with-turso-sync)
to share retained context between installations.

## Pull-request review in GitHub Actions

The [GitHub Action](docs/github-action.md) prepares an inventory for the full
current PR diff within the configured scan root. With an authorized reviewer,
it assesses changed source even when the scanner finds zero candidates.
`delta-coverage.json` records the pinned revisions, reviewed paths and remaining
work separately from findings.

For one-shot review with an enforced coverage check, configure the trusted
reviewer, choose `review-mode: comprehensive` and set
`require-complete-delta-coverage: 'true'`. Keep the artifact upload enabled after
failures so incomplete runs can still deliver findings and coverage. See the
[coverage gate setup](docs/github-action.md#delta-coverage).

## AI-assisted review

Use the [Mehscan security skill](skills/mehscan-security/SKILL.md) with your coding agent to review a repository or a change. The skill uses your agent's model and Mehscan's source lookup tools to investigate the relevant code.

| Mode | When to use it | What to expect |
| --- | --- | --- |
| **Value** (default) | Find the most consequential issues within an allowance. | Ranks scanner candidates and named source checks together by impact, exposure, evidence and the next deciding fact. Reports what was covered, what remains and where importance is unknown. |
| **Comprehensive** | Account for a broader admitted scope or finish declared coverage checks. | Runs Value-priority work first, then uses the remaining allowance for admitted follow-up. Reuses applicable source evidence and reports missing native decisions and open checks. |

Both modes use the same source-bound work plan. Named checks can cover important
workflows with zero scanner candidates. Unselected source windows guide planning.
Value defaults to a budget goal.
Comprehensive defaults to a coverage goal for declared checks and reports broader
coverage separately. Configured rates report estimated cost. A USD spending
allowance applies when explicitly requested. [Review coverage](docs/coverage.md#read-coverage-alongside-the-findings) · [Work plans](skills/mehscan-security/references/work-goals.md)

### Follow up on a review

Review stops after the requested work. Use the findings, coverage and
`review-options.md` to choose the next step when one is warranted.

- **Fast** is the recommended first audit after Value when an important existing
  verdict has a specific proof question. It selects a capped set of claims and
  checks the deciding evidence. An empty queue costs zero model calls. Fast is
  opt-in for either mode. [Fast and Full](docs/review-worker.md#optional-second-pass)
- **Named follow-up** is the direct path to answer a saved unresolved check or
  investigate a specific workflow gap. Continue the saved check when its deciding
  evidence is available. For a newly identified gap, name the flow and protected
  effect in a scoped review. [Saved checks](docs/review-worker.md#resolve-named-source-checks) · [Scoped flow follow-up](skills/mehscan-security/references/review-planning.md#scoped-flow-follow-up)
- **Full** independently reassesses every eligible claim in the selected audit
  scope and compares the results. Choose it when each result in that set needs
  a second assessment. It typically spends more calls than Fast and reports
  any work the allowance leaves open. [Audit scope](docs/review-worker.md#choose-which-results-to-check)

### Useful opt-ins

- **Changed scope** applies Value or Comprehensive to a PR, local diff or release
  delta and tracks coverage of the changed source. [Changed coverage](docs/github-action.md#delta-coverage)
- **Named coverage goals** give specific properties or workflows an explicit
  completion target within the allowance. [Coverage goals](skills/mehscan-security/references/work-goals.md#choose-the-goal)
- **Question delegation** can use a cheaper worker for narrow source facts.
  The review owner makes security decisions. [Question delegation](skills/mehscan-security/references/work-goals.md#question-delegation)
- **Domain review** groups related Value cases around real shared source and
  gives each verification question its own decision. It uses a separate domain
  plan. [Domain review](docs/review-worker.md#opt-in-domain-review)

See the worker guide for [supporting-source scope](docs/review-worker.md#ordinary-review-profile)
and the report contract for [grouped findings and applicability](docs/output-contract.md#causal-families-and-applicability).

For manual bundle review:

```sh
mehscan investigate review-bundles path/to/repository --output mehscan-review
```

After your agent has reviewed the bundles, generate a report:

```sh
mehscan report --run mehscan-review --responses mehscan-review/responses-reviewer --format markdown --output mehscan-report.md --reviewer reviewer-id
```

For scripted use, the [local AI worker](docs/review-worker.md) runs a configured reviewer, tracks progress, and records token usage, cached input and timing. The [Codex adapter guide](docs/codex-reviewer.md) covers model setup, dependencies and optional flow diagnostics.

## Documentation

- [Installation](docs/installation.md)
- [Language coverage and source scope](docs/coverage.md)
- [Rust security coverage](docs/rust-security-coverage.md)
- [Review and report formats](docs/output-contract.md)
- [Local AI worker](docs/review-worker.md)
- [Local review memory](docs/review-worker.md#capture-local-review-memory)
- [Codex reviewer setup](docs/codex-reviewer.md)
- [Review state and history](docs/review-state.md)
- [GitHub Action](docs/github-action.md)
- [Extended SQL and NoSQL coverage](docs/extended-database-coverage.md)
- [0.14.0 release notes](docs/release-notes-v0.14.0.md)

Optional experimental backends provide additional compiler context for [C# through Roslyn](https://github.com/meh-security/mehscan/blob/main/backends/roslyn/README.md) and [JavaScript/TypeScript](https://github.com/meh-security/mehscan/blob/main/backends/typescript/README.md). They are available in the source repository. Standard scanning requires neither backend.

Razor and Blazor source is included in default scanning and AI review. Native scans provide specialized HTML checks, and AI review examines the original source without a generator. The optional Roslyn and .NET SDK backend adds C# analysis mapped to original locations; see the [SDK backend setup](https://github.com/meh-security/mehscan/blob/main/backends/roslyn/README.md#optional-razor-and-blazor-sdk-backend).

## License

Mehscan-owned source is licensed under [Apache License 2.0](LICENSE). Bundled ast-grep source retains its [MIT license](crates/ast-grep/LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md).
