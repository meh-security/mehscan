# Mehscan 0.2.0

Mehscan 0.2.0 adds deliberately bounded C and C++ application analysis and a
complete human-reporting workflow. It remains a source-only scanner: target
projects are not compiled or executed.

## Native analysis

- C and C++ parsing, build-profile context, conditional availability, and
  exact local source/sink/control relationships.
- Native memory and parser invariants for buffer capacity and termination,
  signed sizes, narrowing and arithmetic extents, remaining input, loaded blob
  length, destination regions, ownership, invalidation, and post-return use.
- Systems-specific archive, filesystem race, format-string, libxml2, and C++
  authentication-versus-resource-authorization review signals.
- C++ allocation-family and standard RAII ownership recognition without a
  compiler-grade type, alias, CFG, call-graph, or taint engine.
- `investigate native-call-sites` for bounded call-syntax navigation when an
  existing review question needs that exact fact.

## Review and reporting

- Semantic review bundles keep deterministic paths separate from ordinary API
  observations and expose exact established, controlled, and unresolved facts.
- Canonical post-triage finding JSON, confirmed-issue SARIF, and human-readable
  Markdown are generated from validated reviewer responses.
- Markdown uses behavior-first titles and consolidates repeated root causes
  while preserving each finding location and decision metadata.
- The shipped `mehscan-security` skill includes conditional native review
  semantics; `mehscan-report-quality` checks final Markdown actionability.

## Scope and performance

- Tests, fixtures, samples, generated outputs, common dependency trees, and
  generated `singleheader` amalgamations are excluded from default production
  analysis.
- In native repositories, secondary-language build, CI, documentation,
  packaging, support, and root release-script observations remain raw evidence
  but become opt-in AI review material.
- Real-application closure covered client, server, parser, archive, image,
  network, and C++ web targets. The simdjson stress target completes scan and
  review-bundle generation in about ten seconds after generated amalgamations
  are excluded.

## Deliberate limits

Mehscan does not claim whole-program reachability, compiler-grade type or range
reasoning, arbitrary alias resolution, general interprocedural taint, or
complete detection of native memory-safety CVEs. Raw evidence and review counts
are not vulnerability counts. Confidence describes certainty in a review
decision; impact severity remains a separate field and may use the documented
fallback when no deterministic impact mapping exists.

The release workflow accepts a `v0.2.0` tag only after the tagged commit is
reachable from `main`; CI runs locked tests, builds and smoke-tests the Windows
x86_64 archive, publishes its SHA-256 checksum, and records artifact
provenance.
