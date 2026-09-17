# Unreleased PHP coverage and review improvements

This is a development candidate, not a published version. PHP support remains
partial; see [the PHP coverage budget](php-coverage.md).

- Recognize bounded native JSON request-body fields and static object properties,
  retaining decoder/read provenance.
- Resolve one mandatory discovered `__DIR__`-anchored native PDO/mysqli
  connection config without guessing relative include-path semantics.
- Recognize a local literal PDO preparation with separate execute values.
  Preparing interpolated SQL does not protect it.
- Retain one local native cURL handle and its URL options; inventory native
  peer/hostname TLS verification settings without inferring final TLS policy.
- Follow PHP text accumulation and bounded same-arm branch handoffs, while
  stopping at unknown mutation, references and unresolved joins.
- Preserve manifest coverage/scope metadata, canonical response validation,
  dismissed evidence locations and native operation-specific report guidance.
- Describe confirmed TLS issues with certificate/hostname validation guidance.
- Exclude recognized neighboring callable declarations from lexical helper
  references while preserving same-line calls, recursion and policy bindings.
- Align the shared review contract and both skills on decoder/access
  compatibility, helper mutation and demonstrated input origins, preserving
  directly shown unsafe branches and request-derived dynamic property values.

Original positive, safe, mutation and lookalike regressions accompany these
summaries. Fixture findings and native API observations are not application
vulnerability totals. Framework, template, persistence and general cross-file
coverage are outside this candidate's contract.

The final bounded optimizations preserve selected review payloads and reduce
the earlier PHP flow overhead. Release readiness still requires platform CI
and packaging, then selecting a new release version.
Do not republish an existing version or treat development artifacts as attested
release binaries.
