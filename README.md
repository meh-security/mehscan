# Mehscan

Mehscan is a local source-code security scanner. It collects evidence for review without building or running the application.

## Supported languages

| Support | Languages |
| --- | --- |
| Supported | C, C++, C#, Go, Java, JavaScript, Python, Rust, TypeScript/TSX |
| Partial | Kotlin, PHP, Ruby |

See the [language and framework coverage guide](docs/coverage.md) for scope and limitations.

## Quick start

Download from [GitHub Releases](https://github.com/meh-security/mehscan/releases) or follow the [installation guide](docs/installation.md).

```sh
# Scan a repository
mehscan scan path/to/repository

# Export candidates for files changed since HEAD
mehscan scan path/to/repository --changed-from HEAD --diff-mode files --format candidates
```

Scanner candidates are leads to investigate. [Output formats](docs/output-contract.md)

## AI-assisted review

Use the [Mehscan security skill](skills/mehscan-security/SKILL.md) with your coding agent. A work plan can include named source checks even where the scanner finds zero candidates.

| Profile | What it does |
| --- | --- |
| **Value** (default) | Investigates the strongest native leads and named source checks within the allowance. |
| **Comprehensive** | Starts with Value priorities, then uses the remaining allowance for broader admitted work. Reports open checks and unreviewed scope. |

The workflow is **scope and recall → plan → investigate → follow up → audit → report and retain**. Follow-up and audit are optional. [Review stages](docs/review-worker.md#review-stages)

- **Broaden coverage** with Comprehensive up front or use `--continue-comprehensive` from a saved repository Value attempt on the same pinned source. The continuation shares the original allowance and reuses eligible work. [Continue into Comprehensive](docs/review-worker.md#continue-value-into-comprehensive)
- **Resolve a named check** when the deciding evidence is available. [Saved checks](docs/review-worker.md#resolve-named-source-checks)
- **Audit an existing result** with Fast for concrete proof questions or Full for an independent reassessment of the selected results. [Fast and Full](docs/review-worker.md#optional-second-pass)

For scripted review, see the [local worker](docs/review-worker.md) and [reviewer setup](docs/codex-reviewer.md).

For a configured project, `mehscan project prepare` returns a `project_run` file. The journal and worker accept that reference. After admission, use the reference returned by the worker with `mehscan report --project-run FILE`. [Prepare and continue a project review](docs/standalone-source.md)

## Local review memory

Persistent reviews use local Turso memory in both profiles. Keep the same repository key, stream, and store. Fresh plans load applicable knowledge. Unchanged native reruns with a matching plan and runtime can reuse eligible decisions with zero model calls. Keep the original attempt directory to continue saved work. [Memory and reruns](docs/review-worker.md#reuse-on-reruns)

Use a [saved project configuration](docs/standalone-source.md) to review staged exports and downloads with a stable project key. To share retained review context across installations, run a [self-hosted Turso sync server](docs/turso-sync-server.md).

## Pull-request review in GitHub Actions

Use either profile on a pinned PR diff. The configured reviewer can examine changed source with zero scanner candidates. An optional coverage gate tracks remaining work. [GitHub Action setup](docs/github-action.md)

## License

Mehscan-owned code is licensed under [Apache License 2.0](LICENSE). Bundled ast-grep retains its [MIT license](crates/ast-grep/LICENSE). [Third-party notices](THIRD_PARTY_NOTICES.md)
