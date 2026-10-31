# Mehscan

Mehscan is a source security scanner built for developers and AI coding agents. It identifies security-relevant code, prepares evidence for review, and produces actionable security reports.

Mehscan is under active development. It supports C, C++, C#, Java, JavaScript, TypeScript/TSX, Python, Go, and Rust, with partial PHP and Kotlin JVM coverage. Coverage varies by language and framework; see the [PHP](docs/php-coverage.md) and [Kotlin](docs/kotlin-coverage.md) profiles for their limitations.

See [extended SQL and NoSQL coverage](docs/extended-database-coverage.md) for database query mechanics and remaining language-specific gaps.

An experimental [optional Roslyn backend](backends/roslyn/README.md) adds compiler-backed C# navigation facts from explicitly supplied source and references.

An experimental [optional TypeScript backend](backends/typescript/README.md) resolves selected TS/TSX and JavaScript operands, import aliases and small source helpers. Cached facts guide follow-ups; source-proven fixed Node paths can remove traversal-only questions. Types alone do not establish safety.

Both backends remain experimental, including after merge. Standard installation
does not install them or their dependencies, and default scanning does not require
Node or .NET. To opt in, supply an already provisioned backend and explicit source
context through the CLI options in the linked backend guides.

For review scoping, `mehscan investigate provenance ROOT --inventory RUN/inventory`
collects build-entry, distribution-header and generated/source-map candidates
without a compiler. The security skill confirms scope and preserves deferred IDs;
these hints never assign safe verdicts or change scanner admission.

## What it does

- Scans source code locally without executing build tools or application code.
- Collects evidence and bounded relationships for security review.
- Prepares compact review bundles with source locations and CLI follow-ups.
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
bash ./skills/mehscan-security/scripts/install-mehscan.sh --version 0.8.0
```

Windows:

```powershell
pwsh -NoProfile -File ./skills/mehscan-security/scripts/install-mehscan.ps1 -Version 0.8.0
```

The installer verifies release checksums and provenance, then returns the executable path. See the [platform installation instructions](docs/installation.md) for prerequisite setup, Bash/Zsh examples, supported targets, source commit pinning, and a source-build alternative without PowerShell. Release downloads are also available on the [releases page](https://github.com/meh-security/mehscan/releases).

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

To scan whole changed files relative to a Git revision (available in this source
checkout; not in the released 0.8.0 executable):

```text
mehscan scan path/to/repository --changed-from HEAD --diff-mode files --format candidates
```

Use `mehscan --help` or `mehscan scan --help` for additional options.
Files mode stays within changed files, including when files are renamed or
deleted. For a PR, add `--merge-base --target PR_HEAD_SHA` against the verified
base in a clean checkout of that head. For release deltas, compare explicit old
and new endpoints without `--merge-base`.

## AI-assisted review

Use the [security skill](skills/mehscan-security/SKILL.md) in your coding agent
to review a repository or a change. AI review starts when requested; the scanner
works independently. The skill uses your agent's model, while the optional
[local worker and adapter](docs/review-worker.md) run a configured reviewer.

The current source checkout includes these AI review defaults; they are not yet
available in the released 0.8.0 package:

| Mode | Behavior |
| --- | --- |
| **Value — default AI review** | Prioritizes useful security relationships, preserves explicit unreviewed deferrals, and returns findings, scoped dismissals or specific unresolved questions. |
| **Comprehensive — optional** | Reviews every admitted ID with the same evidence standards. |
| **Detailed flow diagnostics — opt-in** | Adds control and authority-value tables to the bundled adapter with `"boundary_checks": true`. |
| **Targeted revalidation / report-quality review — optional** | Revisits a specific decision-changing fact or checks report actionability. Automatic selective second review remains experimental. |

The bundled worker allows up to six model calls, 24 query units, 512 KiB of
research results and 900 seconds per investigation. These are ceilings;
explicit overrides remain supported. Its Codex adapter defaults to stable schemas
and line-addressed source, with execution traces and cache/usage accounting.
The setup example selects Terra 6.1 medium; other configured models remain supported.
See [reviewer setup and Python dependencies](docs/codex-reviewer.md). Unresolved
and deferred work stays visible; completed execution does not certify an app safe.

For manual bundle review, prepare requests for your agent:

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

For a changed-file AI review, create a scoped inventory, then select exact IDs
through the same bundle workflow:

```text
mehscan investigate review-inventory ROOT --changed-from HEAD --diff-mode files --output RUN/inventory
mehscan investigate review-inventory-list --inventory RUN/inventory --selection value --limit 50
mehscan investigate review-bundles ROOT --inventory RUN/inventory --review-ids ID,ID --output RUN/chunk-1
```

Keep `RUN` outside the source worktree. Changed runs require `--source-root ROOT`
when finalizing or reporting, and reject stale source or Git comparisons.
Follow the [Changed review guide](skills/mehscan-security/references/changed-review.md)
for the required change pass, targeted context and scope limitations. No
candidates does not establish that the diff is safe.

Supply `--repository-key STABLE_ID` at inventory creation for native operation and
triage identity across revisions. Fork PRs use the base product's ID, with an
optional `--source-repository-key FORK_ID` for provenance. Unknown namespaces stay
explicitly unscoped. Matching identity does not authorize reuse of an old verdict;
canonical JSON retains evidence-backed records for all three triage outcomes.

Confirmed SARIF includes a GitHub-compatible primary-location line hash when
bound source is available, alongside native identity. Multiple native paths to
one operation remain separate flows. Git subdirectory scans export repository
paths; GitHub alert ingestion has not yet been tested.

Use `report --sarif-category mehscan/triaged/pr-delta --sarif-run-id attempt-2`
to configure a stable analysis partition and attempt. Reviewer changes do not
change the default category. Changed reports default to a separate category and
remain advisory artifacts; complete bundle work does not establish alert closure.

The [advisory GitHub Action](docs/github-action.md) prepares native inventories
for current PR scope or explicit release deltas with a pinned trusted scanner.
It records endpoint freshness and retains run artifacts; AI review and merge
gating are separate work. The caller workflow requires a reviewed V11 source pin.

The [local state commands](docs/review-state.md) retain generation ownership and
all-verdict decision history, with explicit validated supersession. Changed
source starts unassessed; matching identity alone never carries a dismissal.
The Action can optionally coordinate on one operator-provisioned persistent host.
Distributed hosted persistence and current-result publication remain separate work.
The [local AI worker](docs/review-worker.md) adds explicit completion plans,
source-only changed-effect questions and source-backed pending-evidence resumption.
It accepts a configured reviewer adapter and admits results through native validation.

## Documentation

- [Review and reporting formats](docs/output-contract.md)
- [Local review state and decision history](docs/review-state.md)
- [Local AI worker and pending-evidence resumption](docs/review-worker.md)
- [Changed review release readiness](docs/release-readiness.md)
- [AI reviewer contract](docs/ai-reviewer-contract.md)
- [AI triage contract](docs/ai-triage-contract.md)
- [Extended rule gap analysis](docs/extended-rule-gap-analysis.md)
- [Extended database coverage](docs/extended-database-coverage.md)
- [Latest release notes](docs/release-notes-v0.8.0.md)

## License

Mehscan-owned source is licensed under the [Apache License 2.0](LICENSE). Bundled ast-grep source retains its [MIT license](crates/ast-grep/LICENSE). See [third-party notices](THIRD_PARTY_NOTICES.md).
