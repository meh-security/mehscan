# Mehscan

Mehscan is an AI-native source security scanner. Its deterministic Rust engine
enumerates security-relevant evidence and builds only bounded relationships it
can support from source. Ambiguous security meaning remains explicit review
work rather than being presented as a proven vulnerability.

## Status

The 0.3.0 release adds bounded PHP coverage and improves portable report handoffs;
see [the 0.3.0 release notes](docs/release-notes-v0.3.0.md).

Mehscan is under active development. Current language coverage includes:

- initial C and C++ native application coverage, including read-only
  build-profile context from an authoritative `compile_commands.json` or,
  when it is absent, conservative literal CMake, Meson, and Bazel definitions;
  build tools are never executed, conflicting targets/build systems and dynamic
  configuration remain unknown, and exact local
  buffer-capacity/string-termination, signed-to-size memory use,
  same-scope heap-release/early-exit contracts, narrowing-to-divisor,
  derived-domain-limit, and
  fixed-width-multiplication-to-memory relationships, plus bounded
  architecture-limit-to-macro-allocation, callback-stack-lifetime, and C++
  scalar/array allocation-family and standard unique-owner analysis, plus
  libxml2 external-entity option relationships that distinguish complete
  `XML_PARSE_NO_XXE` protection from network-only `XML_PARSE_NONET`, exact
  libarchive entry-to-disk relationships with independent dot-dot,
  absolute-path, symlink, and privilege-restoration semantics, and bounded
  same-path native check/use relationships with atomic-create and
  no-follow controls, a CVE-proven destination-offset plus copy-extent
  relationship that requires both image-copy axes to fit before the write,
  loaded dimension products connected to exact allocation/copy extents with
  pre-computation overflow guards, and decoded parser extents connected to
  remaining-input-sensitive reads with non-wrapping bounds checks,
  plus a corpus-proven Drogon C++ boundary that keeps
  verified route authentication separate from principal-to-resource
  authorization;
- C# and ASP.NET Core;
- Java;
- JavaScript, TypeScript, and TSX across server, browser, and serverless code;
- Python;
- partial PHP native API coverage for request superglobals and JSON bodies,
  bounded PDO/mysqli connections and statement values, cURL URL/TLS options,
  command execution, emitted HTML, filesystem operations, unserialization,
  and dynamic code; see [the PHP profile](docs/php-coverage.md)
  for the bounded flow model and unsupported framework behavior;
- Go;
- Rust.

The scanner uses checked-in ast-grep components and Tree-sitter grammars. It
does not require a separately installed ast-grep executable.

## Install

From PowerShell 7, use the installer bundled with the
[`mehscan-security` skill](skills/mehscan-security/SKILL.md):

```powershell
./skills/mehscan-security/scripts/install-mehscan.ps1 -Version 0.3.0 -SourceDigest TRUSTED_RELEASE_COMMIT
```

GitHub CLI (`gh`) with `attestation verify` is required, but GitHub login is
not. The installer downloads public release assets and an attestation bundle,
then checks SHA-256, cryptographic provenance, the expected repository and
release workflow, source tag, hosted runner policy, archive membership,
release manifest, and executable version before returning an absolute CLI
path. Known releases also enforce a source commit distributed with the skill;
`-SourceDigest COMMIT` pins another explicitly requested version using an
independently trusted commit. Without a commit pin, verification establishes
the source tag and build identity but does not guarantee tag immutability.

Downloads are bounded and verification failures stop installation. GitHub CLI
manages trust roots; network access is still required. There is no custom
signature-verifier or checksum-only fallback. If no exact platform asset is
published, build from source instead. The 0.3.0 release matrix builds Windows
x86_64, Linux x86_64, macOS x86_64, and macOS aarch64 archives. These assets
become available only after all release jobs pass and the release is published.
Replace `TRUSTED_RELEASE_COMMIT` with the full release commit obtained through
trusted release review. The current skill pin file contains 0.2.0; the 0.3.0
pin is distributed separately after its merged release commit is known.

## Build

Rust 1.88 or newer is required.

```text
cargo build
cargo test --all-targets
```

To build the CLI from source, use `target/release/mehscan` (`mehscan.exe` on Windows):

```text
cargo build -p mehscan-cli --release
target/release/mehscan --help
target/release/mehscan --version
```

Before packaging a release, run the self-contained CLI acceptance test:

```powershell
./scripts/test-e2e.ps1
```

It scans a checked-in fixture, builds every review bundle, validates one
synthetic response per bundle, and emits canonical JSON and SARIF. This proves
the local transport and reporting contracts; it does not substitute for model
quality evaluation against the private corpora.

## Scan

```text
cargo run -p mehscan-cli -- scan path/to/repository
cargo run -p mehscan-cli -- scan path/to/repository --format json
cargo run -p mehscan-cli -- scan path/to/repository --format candidates
cargo run -p mehscan-cli -- scan path/to/repository --format sarif-candidates
cargo run -p mehscan-cli -- scan path/to/repository --jobs 8 --timings
cargo run -p mehscan-cli -- scan path/to/repository --include-tests
cargo run -p mehscan-cli -- scan path/to/repository --changed-from HEAD --format candidates
cargo run -p mehscan-cli -- scan path/to/repository --changed-from HEAD --diff-mode impact --format candidates
cargo run -p mehscan-cli -- investigate --help
```

With a built or installed executable, the equivalent commands begin with
`mehscan`, for example:

```text
mehscan scan path/to/repository --format candidates
mehscan scan path/to/repository --format sarif-candidates > mehscan-candidates.sarif
```

## Build a release preview archive

From PowerShell 7 on Windows, Linux, or macOS, build the host release
executable, create the allowlisted archive and checksum, and smoke-test the
extracted package:

```powershell
.\scripts\build-preview.ps1
```

Artifacts are written to `target/release-artifacts/`. Use `-OutputDirectory`
to copy them elsewhere, `-Version` for an explicit preview version, or
`-SkipBuild` to package an already-built release executable. `-SkipSmoke` is
available for packaging diagnosis, but should not be used for a release gate.

Official release archives are built from version tags by GitHub Actions, not
uploaded from a developer workstation. The release workflow tests the pinned
source and independently builds, smoke-tests, checksums, and attests archives
for Linux, macOS, and Windows. Verify a downloaded archive with:

```text
gh attestation verify mehscan-v0.3.0-linux-x86_64.zip -R meh-security/mehscan
```

Code analysis uses available host parallelism by default, capped at 32 workers.
Use `--jobs N` for a reproducible override. Dependency, build, generated, cache,
and minified trees are filtered. Tests and fixtures are excluded from SAST by
default but may still be considered by non-code scanners; `--include-tests`
enables full code analysis for those sources.

Conventional `singleheader` and `single-header` trees are treated as generated
amalgamations, so maintained source is not parsed a second time through a
distribution artifact. In repositories with maintained C/C++ source, ordinary
secondary-language build, CI, documentation, packaging, support, and root
release-script observations remain in raw scan evidence but are omitted from
the default AI review queue. Pass `--include-review-material true` to review
those surfaces explicitly. Shipped secondary-language application components
and `tools` directories are not excluded by this policy.

Directory scans honor repository-local `.gitignore`, nested `.gitignore`,
`.ignore`, and `.git/info/exclude` rules. Global user Git ignore configuration
is deliberately excluded so the same checkout has the same scan scope on each
machine. Mehscan's built-in dependency, cache, generated-output, and copied
ast-grep exclusions remain mandatory. An explicitly supplied single-file scan
still analyzes that file.

Changed-code scans have two explicit modes. The default `full` mode analyzes
the complete repository, then returns evidence and security paths touching the
changed lines. `--diff-mode impact` analyzes changed files plus bounded local
context and direct importers. Both preserve their scope and result policy in
JSON, candidate, and SARIF metadata. Deletions, renames, central entrypoints,
and project-wide configuration changes return all full-scan results because a
local result filter would be unsafe. Use `--files-from PATH` instead of
`--changed-from REF` when another tool supplies the changed-file list.

## Result model

Mehscan keeps three result boundaries distinct:

```text
Evidence       an observed security-relevant fact
Candidate      a bounded relationship requiring review
Finding        a confirmed final result
```

JSON output preserves the evidence inventory, coverage, diagnostics, and
bounded security paths. Candidate output is compact review input. Scan SARIF
2.1.0 uses `review` results and code flows without pretending that every
candidate is a confirmed vulnerability. After AI review, `mehscan report`
produces canonical finding JSON, confirmed-issue SARIF, and a human-readable
Markdown handoff:

```text
mehscan report --run mehscan-review --responses mehscan-review/responses-reviewer --format json --output mehscan-findings.json --reviewer reviewer-id
mehscan report --run mehscan-review --responses mehscan-review/responses-reviewer --format sarif --output mehscan-results.sarif --reviewer reviewer-id
mehscan report --run mehscan-review --responses mehscan-review/responses-reviewer --format markdown --output mehscan-report.md --reviewer reviewer-id --include-dismissed true
```

The final output contract and field boundaries are documented in
[Mehscan review and reporting contract](docs/output-contract.md).

For portable handoffs, `review-bundles` and `report` accept `--scope-label TEXT`,
`--project NAME` and `--revision REF`. Bundle labels persist in the manifest;
report labels appear in canonical JSON, SARIF run properties and Markdown.
Identify intentional fixtures and selected-file scans explicitly. Labels are
caller-provided metadata; source revisions and deployment are not verified by
the renderer. Aggregated findings retain every distinct explanation for the
selected verdict, so several affected fields at one sink remain visible.

The Markdown projection consolidates confirmed instances when their behavioral
title, capability, and remediation match, even across different rule IDs. The
summary counts instances rather than unique vulnerabilities, and every instance retains its own
location, severity, confidence, and evidence-backed description. Canonical JSON
and SARIF remain ungrouped machine projections.

Titles and remediation follow the specific security invariant, using shared
cross-language policy instead of broad category defaults. New bundle manifests
retain scan coverage and source-scope limitations for the final report; legacy
runs explicitly disclose when that metadata is unavailable.

Reachability, conditional availability, literal values, request context,
protection observations, and provenance remain contextual facts. They annotate
evidence and do not silently erase it.

## Agent skill

The repository includes an installable [`mehscan-security`](skills/mehscan-security/SKILL.md)
skill. It teaches a coding agent how to locate the CLI, select deterministic or
AI-assisted scan output, review every item in a semantic bundle, validate model
responses, and report findings without treating raw candidates as confirmed
vulnerabilities. Its conditional native reference preserves C/C++-specific
memory, parser, lifetime, ownership, and protection semantics without implying
compiler-grade analysis or cross-language rule-count parity.

The skill is optional: the CLI and every output format work without an agent,
plugin, MCP server, or model provider. Copy or install the
`skills/mehscan-security` directory into the skill location used by your agent.
The release archive also includes [`mehscan-report-quality`](skills/mehscan-report-quality/SKILL.md)
for an independent actionability check of the final Markdown handoff after
triage; it does not replace source-level security review.

## AI review contracts

The scanner can prepare bounded evidence for an AI reviewer. The public
contracts define the required verdict, confidence, verification checks, and
response validation:

- [AI reviewer contract](docs/ai-reviewer-contract.md)
- [AI triage contract](docs/ai-triage-contract.md)

Provider prompts, benchmark truth, model comparisons, vulnerable application
corpora, and internal tuning methodology are intentionally maintained outside
this public product tree.

For a complete local AI-review input, build bounded bundles:

```text
mehscan investigate review-bundles path/to/repository --output mehscan-review --max-reviews 20 --max-bytes 524288
```

Each request is self-contained. A complete run requires one validated response
for every request listed by `mehscan-review/manifest.json`; sampled reviews must
not be presented as full-application results. Request files use compact JSON to
avoid spending storage and model input on indentation; the manifest remains
human-readable.

## License

Mehscan-owned source is licensed under the [Apache License 2.0](LICENSE).

The checked-in ast-grep source retains its original MIT license in
[`crates/ast-grep/LICENSE`](crates/ast-grep/LICENSE). See also
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
