---
name: mehscan-security
description: Run Mehscan against an authorized local codebase, select an appropriate deterministic or AI-assisted review workflow, and return concise evidence-backed security decisions. Use when the user asks to scan with Mehscan, inspect Mehscan candidates, or perform a Mehscan-assisted repository review. Do not use for a generic security review when Mehscan is unavailable or not requested.
---

# Mehscan Security

Use Mehscan as the evidence producer and apply security judgment only to the
evidence and source supplied for each review. A security path is a candidate,
not a confirmed vulnerability.

## Locate the scanner

Resolve the executable in this order:

1. Honor a user-supplied executable.
2. Check for `mehscan` on `PATH` using the host's command lookup. Do not infer
   availability from a previous task or a filename elsewhere on disk. If present,
   check its version and use its absolute path; do not install Mehscan or setup
   tools. If an explicitly requested version differs, or a source digest cannot
   be established, report the mismatch instead of implicitly replacing it.
3. In a Mehscan source checkout, check `target/release/mehscan` (or
   `mehscan.exe` on Windows).
4. If no executable is available, read
   [references/installation.md](references/installation.md) for host-specific
   prerequisite setup and invocation. On Linux/macOS use
   `bash scripts/install-mehscan.sh` (Bash and Python 3.9+, no PowerShell).
   On Windows use `scripts/install-mehscan.ps1` with PowerShell 7 (`pwsh`).
   Each installer selects the
   latest exact OS/architecture public release asset without GitHub login,
   downloads its attestation bundle, verifies its checksum and GitHub
   build provenance, validates archive membership and the release manifest,
   installs into a versioned user-owned location, and returns the executable's
   absolute path. On Linux and macOS it applies executable permissions and
   conservatively publishes `~/.local/bin/mehscan` without replacing an
   unrelated entry. Pass `--version` (PowerShell: `-Version`) only when the user
   requested a particular release and `--install-directory` (PowerShell:
   `-InstallDirectory`) when the task requires a specific location.
5. If no exact release asset exists, or checksum/provenance verification cannot
   succeed, do not execute the download. Build the release CLI only when the
   current checkout contains Mehscan and building is within scope; otherwise
   report that the scanner is unavailable for this target.

Recommend GitHub CLI (`gh`) for release installation because its attestation
verifier establishes the expected build workflow and source provenance; a
checksum alone only establishes agreement with the supplied checksum file.
GitHub CLI is optional for using Mehscan or building from trusted source, but
both release installers require `gh` with `attestation verify`, without GitHub
login. Linux/macOS installation requires Bash and Python 3.9+; only the Windows
installer requires PowerShell 7. Public HTTPS downloads have byte, redirect, origin, and
time limits. GitHub CLI verifies the local bundle using its trusted Sigstore
roots and enforces the repository, signer workflow, source tag, and hosted
runner policy. Known releases also enforce the source commit pinned in
`references/release-pins.json`; for another explicitly requested release, pass
`--source-digest` (PowerShell: `-SourceDigest`) only when an independently trusted exact source commit is
available. A commit discovered solely from the downloaded bundle is not an
independent pin. Update the pin file only from trusted release review.

The installer fails closed when the
target, checksum, provenance, archive, manifest, or version cannot be verified.
Do not replace GitHub CLI with agent-written signature verification, treat a
checksum alone as provenance, or fall back to execution after any failed check.
If GitHub CLI is missing or too old, recommend installing or upgrading it with
the platform instructions and explain its provenance-verification purpose.
If that is unsuitable, use an existing trusted Mehscan checkout to run
`cargo build -p mehscan-cli --release --locked` when building is within scope,
then check the built binary's `--version` and use its absolute path. This is an
agent-selected fallback, not an automatic installer downgrade. If no trusted
checkout or build toolchain is available, report the missing prerequisite and
scanner unavailability. Never execute the rejected release archive. Trust-root
metadata may still require network access even though the bundle is local.
Do not reproduce its download logic ad hoc or weaken a failed check. Use only
the official GitHub repository for automatic downloads. Never download
ast-grep; Mehscan includes the components it uses.

After installation, use the returned absolute executable path for the rest of
the task; do not assume the current process has refreshed `PATH`. The installer
tests `--version` from the final filesystem before returning.

Run `mehscan --help` before assuming an option exists. Keep the scan root inside
the repository the user authorized. Directory discovery honors repository-local
`.gitignore` and `.ignore` rules, but not machine-global ignore configuration.
Do not claim coverage for ignored paths; scan an explicitly authorized file or
smaller root when the user intentionally needs an ignored source assessed.

## Choose the smallest useful workflow

- For a fast repository scan, run `mehscan scan ROOT --format candidates`.
- For machine-readable diagnostics or local filtering, use `--format json`.
- `scan --format sarif-candidates` emits unconfirmed candidate SARIF (`sarif`
  is a legacy alias). Do not upload it as a final vulnerability report unless
  the consumer explicitly wants review leads.
- Add `--include-tests` only when the user wants test, fixture, and sample code
  assessed as executable application material.
- In repositories with maintained C/C++ source, the default AI review queue
  treats ordinary secondary-language build, CI, documentation, packaging,
  support, and root release scripts as review material. Their raw scan evidence
  remains available; use `--include-review-material true` only when the user
  wants those operational or development surfaces adjudicated too. Do not
  describe this default as excluding shipped secondary-language application
  components or `tools` directories, which remain reviewable.
- Use `--timings` when performance or scan coverage is part of the request.
- If the user asks for AI-assisted comprehensive review, run
  `mehscan investigate review-bundles ROOT --output DIR --max-reviews 20
  --max-bytes 524288`. Review every request named by `manifest.json`; do not
  report a full-run result from a sample.

For a changed-code review, prefer the predictable default:

```text
mehscan scan ROOT --changed-from BASE --format candidates
```

This analyzes the complete repository and returns evidence and paths touching
changed lines. Use `--diff-mode impact` for a faster local edit or hook scan;
it analyzes changed files plus bounded same-directory context and direct
importers. Inspect `impact_scope.strategy`, `result_policy`, and `reasons` in
machine-readable output. Deletions, renames, central entrypoints, configuration,
or broad impact force a full all-results fallback because changed-line filtering
would hide effects in unchanged code. `--files-from PATH` accepts one relative
path per line when Git metadata is unavailable.

Mehscan does not yet have a category-only scan option. Filter a completed scan
by capability, CWE, rule, or path, and do not claim that this reduced scan work.

## Review candidates

For each supplied review ID, return exactly one decision:

- `issue`: the supplied behavior establishes a concrete weakness;
- `not_issue`: supplied evidence establishes safety, inapplicability, or that an
  ordinary API/syntax observation has no reportable security relationship;
- `needs_review`: one named missing fact could change the decision.

Use confidence for confidence in that decision, not severity. `high` requires
decisive behavior, `medium` permits a bounded framework or syntactic inference,
and `low` means decision-critical evidence is sparse, conflicting, or clipped.

Treat `open_questions` as confidence context, not mandatory checks. Only a
concrete fact in `decision_facts.unresolved` may support `needs_review`; copy
that exact fact into `checks`. When `decision_facts.unresolved` is empty, make a
decisive `issue` or `not_issue` judgment from the supplied evidence. A bounded
ordinary API-boundary observation may be `not_issue` at medium confidence
without claiming that the surrounding component is generally safe.

Keep checks verbatim, but make the summary actionable: name the producer,
handler, model validator, or configuration artifact to obtain, the exact value
or control to inspect, and the outcomes that would change the verdict. If a
path is not supplied, request the artifact for the named component and field
rather than inventing a file path or repeating a generic attacker-control question.

Answer concrete unresolved facts before requesting more evidence. Do not invent cross-function flow, runtime dispatch, persistence,
deployment controls, or exploitability. A nearby guard or sanitizer counts only
when it protects the same value and operation. Missing application headers,
CORS, TLS, cookies, or rate limiting may be owned by a gateway or platform and
normally require an effective-control check.

A scanner relationship label does not override contradictory supplied facts.
Evidence scope is per review ID. Use only that review's candidate, evidence,
facts, review basis and decision facts. Another review in the same bundle cannot
supply a missing origin, producer, control or branch, even in the same file or
with the same variable name. A directly shown request read, cookie loop or
request dump reaching HTML can establish an issue without a deterministic path;
an observation label does not negate its source excerpts. Observed control syntax
is inventory until the same operand, owner, operation and branch are protected.
When the captures or excerpts affirmatively show different operands, owners, or
operations with no supplied bridge, use `not_issue` for that named relationship
and describe the mismatch. Do not use supplemental syntax lookup to repair a
decision-ready payload or infer the missing bridge.

Evidence tagged `review-admission-marker` is different from an ordinary API
inventory observation. It means Mehscan deterministically established the
security-relevant boundary and effect named by a `review-invariant:*` tag, but
the normal sink/path model could not express the complete review question. Do
not dismiss it because no conventional sink or source-to-sink path fired. The
marker is still not a vulnerability verdict: decide only the named invariant,
using `issue` for a concrete violated invariant and `not_issue` for affirmative
disproof or an effective applicable control. Keep unrelated possible weaknesses
outside that review.

Marker families remain intentionally specialized. For example, authorization
markers establish a server mutation and ask whether the same subject, action,
and resource are authorized. Credential-lifecycle markers ask whether password,
passcode, MFA, authenticator, recovery-code, credential, or API-key changes
enforce the required current-subject proof, recovery authority, or step-up
authentication. Dynamic interpreter reviews establish an exact dynamic operand
and make its origin or constraint decision-critical. Do not transfer the
authorization test to credential lifecycle, injection, deserialization,
redirect, SSRF, trusted-HTML, template, or process-execution reviews; use each
review's named operand and invariant.

Operation-policy reviews also keep object binding, request integrity, and
fail-open behavior separate. For object binding, identify the exact
request-controlled object, binding/copy operation, persisted target and writable
security-sensitive fields; an interface, DTO name, validation annotation, or
unrelated explicit setter is not an allowlist. Apply exclusions, serializer
fields, bind-never metadata, explicit mapping, or field-level authorization only
when the supplied executable configuration covers that exact operation and
field. Do not report automatic binding merely because a handler accepts a typed
request object; require the supplied persistence or model-write boundary.

For CSRF/request integrity, require browser-managed victim authority plus an
applicable state-changing operation. Apply a token or strict origin check only
when its attachment and rejection behavior cover the exact route; authentication
and SameSite assumptions are not substitutes. For fail-open review, follow the
shown decision result, branch, catch, response, or callback to the protected
effect. Logging, telemetry, sending a response, setting a status, or calling a
challenge helper is not enforcement when the supplied code continues. A local
terminating return or throw protects only the branch and operation it actually
stops.

For authoritative-value binding, keep the caller-supplied value, selected
resource, server-loaded or quoted value, units/currency, version and financial
effect separate. A variable named `price`, a catalog lookup, or a payment SDK
call does not prove that the exact write or charge uses the applicable
authoritative value. Direct persistence of an established request field as a
paid amount is decision-ready unless supplied facts show comparison, rejection,
and use of the server value for that effect. A server-loaded value used directly
at the effect is affirmative local control for amount integrity, while product
selection, discounts, staleness and cross-service authority remain separate
questions when the supplied code does not establish them.

For resource state transitions, keep the persisted current state, requested
next state, affected resource, transition policy and rejection path separate.
Status names, enums and a helper named `canTransition` do not prove that the
exact edge is permitted. An applicable explicit transition map plus a return or
throw before mutation is affirmative local control. Direct persistence of a
request-supplied state remains decision-ready when no such enforcement is
shown; when a referenced policy helper is missing, retrieve its exact
definition before deciding.

For shared-state limits, keep the loaded persisted value, caller-requested
delta, local limit check, derived value and write separate. A comparison that
rejects insufficient balance or capacity can implement the business rule while
still racing with another request. Treat concurrency as enforced only when the
supplied adapter facts establish one conditional write, compare-and-swap, or an
applicable row lock inside a transaction. Names such as `transaction`, `lock`
or `atomic` are retrieval leads, not proof. Conversely, atomicity does not prove
that the chosen numeric limit is the correct business policy.

### Generated and framework-registered routes

For any authorization or resource-access review involving routes, handlers,
resolvers, generated CRUD, or framework policy, read
[references/authorization-routing.md](references/authorization-routing.md).
Apply its framework-neutral operation matrix first, then only the section for
the detected framework. The same method/path/action, control scope, registration
order, and resource must line up; authentication or a sibling-route guard is not
object authorization for the reviewed operation.

When a Mehscan rule or review fact explicitly labels a registration as generated
CRUD, do not decide from the generator excerpt alone. Treat the label as proof
that server operations are generated, read the framework/package subsection to
enumerate only its established operations, and retrieve the bounded controlling
route-registration scope required by the reference before deciding.

When the bundle lacks decisive method-level context, the reference permits one
bounded lookup around the named registration and its controlling scope. This is
a same-review routing clarification, not a search for new findings or general
data flow. A confirmed issue must name a concrete uncovered operation and its
security impact.

When `decision_facts.unresolved` names an exact missing syntactic artifact that
can change the decision, use the investigation API before leaving it unresolved.
Prefer `source`, `enclosing`, `symbol`, `imports`, and `references` for ordinary
navigation. For an exact AST shape, `mehscan investigate structural ROOT
--language LANG --pattern PATTERN [--path FILE] [--limit N]` is available for
every supported language. Scope it to the named file whenever possible and use
the smallest pattern that answers the existing question. A structural match is
ephemeral syntax inventory: it cannot create a finding, establish data flow,
runtime binding, reachability, or make a control applicable to a different
operation. Empty, truncated, or parse-failed results do not prove absence.

Before claiming injection, match the producer's representation to the consumer
operation. For example, PHP's default object-mode `json_decode` does not make
array indexing a valid request-to-sink bridge; check the supplied decoder mode
and property or index access rather than treating every JSON read as equivalent.
Preserve a directly shown unsafe branch when that branch assigns request input
and sends it to the sink; the condition need not itself be attacker-controlled.
Injection does not require unsafe input on every execution path. In code
equivalent to `if (enabled) value = request.field; sink(value)`, the enabled
branch establishes a conditional weakness unless supplied facts disprove that
branch; an uninitialized value or failure in the other branch does not protect it.
A dynamic selector also need not be attacker-controlled when the selected value
comes from the shown request object. Distinguish the selector from that value.

An unknown helper is neither a sanitizer nor proof that the old value survives.
Check argument/reference, alias and mutation semantics, including calls inside
compound assignment. PHP helpers may accept arguments by reference; mutable
objects in other languages may also change. A neighboring declaration answers
this only when its exact callable and owner match. If the supplied relationship
is not established and `unresolved` is empty, dismiss that bounded relationship
without claiming that the output is safe. Do not discard a relationship when
the language semantics or supplied helper body establish that the value survives.

Server metadata, session fields and framework properties need a shown producer
and relevant attacker influence. `SCRIPT_NAME` alone does not establish
attacker-selected attribute-breaking content. Apply this check to the exact
value; it does not negate separately shown request input or a policy failure.

Keep verdict summaries specific to the reviewed operation: a nearby success
response does not describe an exception response, and a variable serialized in
JSON has no established request origin unless this review supplies its producer.
For conditional policy failures, state applicability and the shown consequence;
for example disabled certificate checks affect HTTPS and can undermine trust in
the returned status, without establishing an attacker-selected URL.

For C/C++, the native reference also describes a specialized bounded call-syntax
inventory. Use it for exact callee and argument questions; use the general
structural operation for other language-specific AST shapes. Neither operation
establishes taint, call reachability, runtime binding, or a new finding, and
truncated or parse-skipped results do not resolve the fact.

When a review is for C or C++, or uses a native memory, parser, lifetime,
ownership, archive, or XML capability, read
[references/native-c-cpp.md](references/native-c-cpp.md). Apply it to the named
invariant only; do not demand managed-language rule parity or infer general
memory safety from one protected relationship.

Unlinked native file I/O calls, runtime algorithm-selection calls, and
compile-time format macros normally remain raw evidence rather than standalone
review jobs. Promote them only when the scan supplies a concrete security
relationship or policy violation.

For bundle responses, echo the exact `bundle_fingerprint`, provide every
`review_id` once, and include `checks` on every result. Use an empty array for
`issue` and `not_issue`; for `needs_review`, copy only decisive missing facts
from the supplied unresolved set. Validate each response:

```text
mehscan investigate review-bundle-triage --bundle REQUEST --responses RESPONSE
```

Do not ask the reviewer to emit repair metadata. When one parseable result
fails contract validation, generate one replacement result for that exact ID
and use `review-bundle-repair`; the CLI records the failed and replacement
identities and revalidates the complete response. Never repair a valid response
to change its security decision, and never repair an already repaired response.

Retain a newly discovered security question in `reviewer_origin_leads` only
when supplied or retrieved source shows a concrete dangerous operation or
security invariant distinct from the admitted review. Include the exact source
location, explicitly cited artifact IDs, the security relevance, and why it is
separate. A keyword, comment, helper name, generic concern, or restatement of an
existing check is not a lead. Keep leads out of the originating verdict and
present them as unvalidated follow-up work rather than scanner findings.

When the review runner supports structured output, generate a request-specific
schema with `mehscan investigate review-response-schema --bundle REQUEST --output SCHEMA`.
Older versions can use the packaged `scripts/new-review-response-schema.ps1` helper.
It constrains the fingerprint, allowed IDs and exact result count; it cannot
enforce unique IDs or semantic correctness. The CLI validator remains required.

Treat each request file as one independent review invocation. Do not process a
directory or sequence of bundles in one context: large multi-bundle tasks can
encourage repeated verdict templates even when individual request files are
small. The generation default remains 20 reviews per bundle; lower
`--max-reviews` only for a measured retry or evaluation.

Within one review, execute supplied lookup requests in order and stop when the
returned evidence resolves the decision-critical question. Do not spend a
secondary reference lookup after an earlier exact source lookup already proves
the issue or applicable control. Record only lookups that were actually run.
If an attempted lookup exposes the exact next decisive file or identifier,
the response contract permits one follow-on `source` or `references` escalation.
Copy the supplied missing-fact question, use the smallest exact locator and
record its outcome. Do not use this allowance for generic repository search.

If a fresh complete-bundle retry still borrows facts across review IDs, regenerate
the same authorized root with `--max-reviews 1` and the same context/material
policy. Review only the affected IDs as a separately scoped audit before
escalating. Confirm their review objects are unchanged; the scanner generates
new bundle fingerprints. Never rebind singleton responses into an older bundle
or describe this targeted audit as a complete run. Isolation reduces scope
contamination; it does not supply missing facts or eliminate reasoning errors.

Use the default capable review configuration for the first pass. Route review
effort by payload completeness and decision quality, not by provider, model
name, CWE, or rule:

- decision-critical truncation means regenerate or gather context;
- non-empty `decision_facts.unresolved` means retain the exact `needs_review`
  check or gather that fact rather than escalating to infer it;
- empty `decision_facts.unresolved` means require a decisive verdict using the
  exact deterministic `confidence_policy`;
- reject capability drift, operands absent from the payload, re-asking supplied
  facts, and generic repeated summaries, then retry once with fresh context;
- use a stronger independent reviewer only when a complete payload still
  receives a repeated, contract-valid but evidence-inconsistent decision;
- reserve the highest-cost or deepest review configuration for a high-impact
  disagreement that remains after those checks.

Record the reviewer configuration and escalation history by exact review or
payload fingerprint. Do not mark an entire CWE, capability, or rule as
requiring an expensive reviewer from one disagreement.

After all manifest responses validate, generate the canonical machine report,
its SARIF projection, and the human-readable Markdown report. Use the exact
reviewer-specific response directory rather than copying it to a generic name:

```text
mehscan report --run DIR --responses RESPONSES_DIR --format json --output mehscan-findings.json --reviewer REVIEWER_ID
mehscan report --run DIR --responses RESPONSES_DIR --format sarif --output mehscan-results.sarif --reviewer REVIEWER_ID
mehscan report --run DIR --responses RESPONSES_DIR --format markdown --output mehscan-report.md --reviewer REVIEWER_ID --include-dismissed true
```

The reviewer writes only the strict verdict response. Never ask it to construct
finding JSON or SARIF: the CLI joins deterministic rule, location, flow, and
provenance fields and publishes only confirmed issues to SARIF. Preserve
`needs_review` in canonical JSON.

Embed intentional fixture/application scope and the selected-source limitation
in the report itself, rather than relying on a sidecar. If the CLI help exposes
`--scope-label`, `--project` and `--revision`, set them during `review-bundles`
so the manifest carries the same metadata into all projections. They can also
be supplied to `report` for an existing run; use identical labels for every
format. Revision labels are supplied provenance, not independently verified
facts. With older CLIs, retain an explicitly labeled handoff index and sidecar.

## Validate scanner changes proportionately

When the task changes Mehscan itself, choose tests from the affected contract:

- During iteration, run the narrow unit or integration target that directly
  exercises the changed rule, classifier, admission policy, or renderer.
- For shared core schemas or report construction, run the core crate tests once
  after the focused test passes. For language-specific analysis, run that
  language's focused corpus or fixture tests; do not add unrelated language
  suites merely for parity.
- Run tests for every directly affected crate and strict linting for changed
  Rust crates before handoff. Run the entire workspace or expensive real-corpus
  matrix for release gates, cross-language or shared-engine changes, or when a
  focused failure suggests wider impact.
- Do not rerun an unchanged broad suite after a documentation-only, skill-only,
  response-only, or report-rendering-only step. After a correction, rerun the
  failed target and only the smallest dependent gate whose inputs changed.

Record which level was run and why. Test cost never justifies skipping a
directly affected contract.

## Report

Treat `mehscan-findings.json` as the canonical report, SARIF as its IDE/CI
projection, and `mehscan-report.md` as the human handoff. The Markdown report
puts unresolved items and their exact checks first, followed by confirmed
issues and the affirmative reasons for dismissed candidates. Evidence counts
and candidate counts are not vulnerability counts. Confirmed Markdown issues
with the same behavioral title, capability, and remediation are presented as
one repair group even when their rule IDs differ; the summary counts finding
instances rather than independently deduplicated vulnerabilities, and
every instance retains its own location and decision metadata.

New bundle manifests retain coverage totals and source-scope limitations for
report projection. Legacy runs remain readable and explicitly disclose missing
coverage metadata. Operation-specific titles and repairs are shared across
languages; unknown invariants must not receive an unrelated category default.

Directory discovery prunes conventional `singleheader` and `single-header`
amalgamation trees as generated distribution artifacts. Do not claim those
duplicates were analyzed; coverage applies to the maintained source trees.

When the user asks whether the final Markdown is useful or actionable, apply
the separate `mehscan-report-quality` skill to the generated report.

For deliberately scoped triage, use `mehscan report --run DIR --allow-partial true`
or `mehscan investigate review-bundle-summary --run DIR --allow-partial true`.
Only missing response files are skipped. Each submitted bundle must still be complete
and valid. Output identifies completed versus total bundles/reviews; unreviewed
bundles are not dismissed and this is not a complete application assessment.

The response envelope is `{"schema_version":"1.0","bundle_fingerprint":"EXACT_REQUEST_FINGERPRINT","results":[{"review_id":"EXACT_REVIEW_ID","decision":"issue","confidence":"high","summary":"Specific supported conclusion","checks":[]}]}`.
Repeat the result object for every request review ID, exactly once.
