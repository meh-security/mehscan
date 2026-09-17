# Mehscan 0.3.0

Mehscan 0.3.0 adds bounded native PHP source analysis and improves report
handoffs across languages. Scans remain static: evidence and review candidates
are not confirmed vulnerabilities until their supplied context is adjudicated.

## PHP coverage

- Parse PHP and mixed HTML/PHP without running PHP or Composer; recognize native
  request reads and command, SQL, HTML output, filesystem, deserialization and
  dynamic-code boundaries while excluding local API lookalikes.
- Recognize compatible associative-array and static object-property access to
  native JSON request bodies, retaining the decoder and raw-read provenance.
- Resolve a conservative native PDO/mysqli connection from one mandatory
  discovered `__DIR__`-anchored configuration include. Unknown receivers,
  uncertain includes and intervening replacement stop this summary.
- Recognize local PDO parameterization on the same prepared statement.
  Preparing SQL that already contains interpolated input is not protection.
- Retain bounded cURL handle and destination-option relationships, and review
  peer/hostname verification settings against the same executed handle.
- Follow text accumulation, raw conditional arms and bounded same-arm handoffs;
  unknown mutation, references and unresolved joins remain explicit limits.

PHP coverage is partial. Framework readers, templates, persistence, general
call graphs and arbitrary cross-file flow are outside these summaries. See
[the PHP coverage profile](php-coverage.md). Tests, examples, generated material
and vendor dependencies retain the ordinary exclusion policy.

## Review and report quality

- Review guidance checks decoder/access compatibility, helper mutation, exact
  callable ownership and demonstrated input origins, while preserving directly
  shown unsafe branches and request-derived dynamic property values.
- Helper context excludes neighboring callable declaration tokens without
  excluding real calls, recursion or policy bindings.
- Canonical aggregation retains every distinct explanation for the selected
  verdict at a shared sink, so all affected input fields remain visible in JSON,
  SARIF and Markdown. Counts, locations and provenance are preserved.
- Portable scope, project and revision labels can be supplied at bundle creation
  or report rendering. Scope travels into JSON, SARIF run properties and
  Markdown; generated manifests identify scanned source files and intentional
  review-material inclusion. Labels do not prove deployment or verify a ref.
- Both bundled skills require exact-operation explanations, conditional policy
  impact, complete aggregated operands and explicit standalone scope labels.

Original positive, safe, mutation and lookalike fixtures accompany the changes.
Selected real-application source regressions informed coverage and review
quality; this is not a full CWE parity or whole-application recall claim.
Severity defaults are not validated impact rankings, and reviewer confidence
is not a calibrated probability.

## Distribution and verification

Tag-triggered GitHub Actions builds, smoke-tests, checksums and attests four
platform archives: Windows x86_64, Linux x86_64, macOS x86_64 and macOS aarch64.
Publication requires every platform job and the complete archive/checksum set.
Each archive includes the CLI and both convenience skill snapshots.

The installer verifies public downloads using GitHub CLI and a local attestation
bundle without GitHub login. Checksum, repository, workflow, tag, source digest,
hosted-runner, archive, manifest and executable-version checks remain enforced;
there is no checksum-only or custom-cryptography fallback.

For a fresh 0.3.0 install, explicitly pass `-Version 0.3.0 -SourceDigest COMMIT`
using the independently reviewed full tagged source commit. Its trusted pin is
distributed in a follow-up skill update after publication: a release commit
cannot contain its own hash. Marketplace plugin publication is separate from
this CLI release and is not implied by the bundled skill snapshot.
