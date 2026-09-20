# AI triage contract

Status: cross-language MVP contract, 2026-08-27.

## Conclusion from live output review

Mehscan currently has two different AI-input qualities:

| Artifact | Suitable for a final model decision? | Why |
| --- | --- | --- |
| Language-neutral review job | Yes, within its stated open questions | Contains role-labelled facts, exact excerpts, provenance, a stable fingerprint, and a compact response contract |
| Candidate report | Not by itself | Contains a strong bounded relationship, terminal locations, steps, context, protections, and uncertainties, but no source excerpts |
| Evidence or investigation unit | Usually no | Represents an observation or review lead, not necessarily a relationship |
| Relationship funnel | No | Aggregate routing telemetry only; counts are not findings |
| Coverage and diagnostics | No | Qualify completeness and confidence but do not establish a weakness |

The current crAPI identity scan produced 188 observations, six bounded paths, and
six candidates. The first CWE-78 candidate clearly identifies the persisted
user-controlled construction, the process-execution sink, a local assignment,
and three bounded uncertainties. It does not include the actual statements.
Giving only this JSON to a stream model asks it to decide from rule names and
engine summaries, which is not sufficient for a reliable final verdict.

The existing investigation API makes an agent loop viable: retrieve bounded
source around the source and sink, inspect the enclosing symbol, and expand
references only when a named uncertainty is decisive. A one-shot model payload
still needs the scanner to assemble that context.

For an exact unresolved syntax question, `investigate structural` accepts an
ephemeral ast-grep pattern for every supported language. It is supplemental
navigation, not new scan evidence: matches do not establish flow, reachability,
runtime binding, or control applicability. Repository-wide queries skip malformed
files, return them in `skipped_files`, and set `truncated`; an explicitly selected
malformed file fails clearly. Reviewers should prefer a named `--path` and must
not treat an incomplete empty result as proof of absence.

## Trust boundary

Deterministic output states what was observed and what bounded relationship was
proved. AI triage decides whether the supplied evidence establishes an issue.
Neither side may silently upgrade proximity, matching names, or a funnel count
into a flow.

Use these decisions:

- `issue`: the evidence establishes a concrete weakness;
- `not_issue`: affirmative evidence disproves it or establishes an effective
  protection;
- `needs_review`: a named missing fact could change the decision.

Confidence is independent of severity:

- `high`: decisive behavior is directly shown;
- `medium`: well supported with a bounded syntactic or framework inference;
- `low`: sparse or ambiguous evidence.

The final human-facing result should contain only decision, confidence, primary
location, a one- or two-sentence explanation, and—only for `needs_review`—the
smallest checks that can change the decision. Internal promotion states,
flow-status labels, path IDs, and verification matrices remain useful for
engine policy and debugging but should not be model-authored final output.

## Review rules

1. A source, sink, protection, or configuration observation is not a finding by
   itself.
2. A security path is a reviewable bounded relationship, not a confirmed
   vulnerability.
3. `unreachable` and `excluded` can affect the verdict only when their
   syntactic proof applies to the relevant behavior. `unknown` is not disproof.
4. A sanitizer or authorization observation counts only when the evidence ties
   it to the candidate in the correct context.
5. Missing application configuration is not proof of missing effective policy.
   For headers, TLS, CORS, cookies, rate limits, and similar controls, identify
   whether the application, framework, proxy, gateway, ingress, mesh, platform,
   or client owns the effective behavior.
6. Do not invent cross-function flow, persistence, runtime dispatch, framework
   binding, exception behavior, or deployment configuration.
7. Every verification request names an exact artifact or runtime behavior and
   explains what result changes the decision.
8. A C# call whose framework symbol resolution remains ambiguous is not an
   admissible framework/API observation. It must not reach a review payload as
   several speculative sinks. Import, alias, fully-qualified, constructor, and
   receiver-qualified evidence without a locally declared shadow remains
   admissible.
   Across supported languages, an imported API alias rebound by a parameter of
   the enclosing callable is a lookalike and is not admissible API evidence.
9. Before returning `needs_review`, answer each relevant open question from the
   supplied excerpts. Do not request a generic flow trace or control inspection
   when the payload already shows it; name only the exact unresolved artifact or
   effective runtime/deployment value.
10. Open questions are reviewer-facing verification checks, never scanner
    uncertainty identifiers. A deterministic bounded path already establishes
    the admitted syntactic relationship, so the payload does not separately ask
    whether the bounded source reaches the sink. It asks only about the exact
    unresolved binding, executable branch, runtime dispatch, origin, or control.
11. Missing linked protection is interpreted by control ownership. SQL
    parameterization, path containment, destination validation, template trust,
    output encoding, and resource authorization must apply to the same
    source-derived value in application behavior. Headers, TLS, request handling,
    and similar deployment policy may instead be owned by an authoritative
    framework, proxy, gateway, ingress, mesh, or platform layer; repository
    absence alone does not prove absence there.

## Current model-facing schema

C# neighborhoods already expose the preferred compact contract:

```json
{
  "neighborhood_id": "rn-...",
  "decision": "issue | not_issue | needs_review",
  "confidence": "high | medium | low",
  "summary": "No more than two sentences.",
  "checks": []
}
```

`checks` is populated only for `needs_review`. A response set must retain the
job fingerprint and provide exactly one result per neighborhood. This is a good
external contract and should remain smaller than the engine's internal state.

Large packs may be evaluated as a declared sample of complete semantic bundles.
Every selected bundle must receive exactly one valid response per review. Do
not run or report the full-pack summary until every bundle in the manifest is
complete, and never present a sampled verdict count as adjudication of the full
application.

## Implemented scanner-side review jobs

`mehscan investigate review-jobs ROOT` now emits language-neutral review input.
Each item is either a proven security-path review or an explicitly non-path
evidence neighborhood and carries:

- stable ID and input fingerprint;
- candidate type and CWE candidates;
- primary location;
- role-labelled facts with short exact excerpts and evidence IDs;
- path steps, protections, reachability, availability, and uncertainty when
  present;
- only the open questions that can change the verdict;
- the existing compact triage contract.

Security-path and observation reviews also carry `review_basis`. It is
deterministic rule metadata, not a model-authored conclusion. Path bases carry:

- exact source, sink, and protection rule IDs;
- rule titles and provenance notes when the rule comes from the catalog;
- evidence tags and bounded capture expressions, with security-sensitive
  literals redacted;
- the admitted bounded-relationship claim and propagation provenance;
- rule-authored investigation, verification, and exclusion guidance; and
- an explicit reminder that missing linked protection is not proof that an
  effective framework or deployment control is absent.

Observation bases preserve the same compact per-rule semantics without
manufacturing a source-to-sink relationship. They identify the review as a
bounded non-path observation, state what syntax or API boundary was actually
seen, and retain authored `investigate`, `verify`, and `exclude` guidance. For
example, an unsafe Rust construct explicitly says that syntax alone does not
establish a violated invariant, attacker reachability, or security impact.
Repeated rules are deduplicated so a neighborhood does not pay repeatedly for
identical rule metadata.

Reviews now also expose `decision_facts`, which separates short facts already
established by the payload, linked effective-control evidence, and the exact
questions that remain unresolved. This is not a scanner verdict. A path may
state that a bounded relationship and its terminals are established; an
observation explicitly states that it does not establish a path. A
`needs_review` response must copy one or more supplied unresolved questions
into `checks`, so it cannot replace supplied facts with a generic request to
inspect them again.

Model-facing truncation is structured. `truncation.occurred` records any
bounded clipping, `roles` distinguishes primary from auxiliary context, and
`decision_critical` is true only when primary source, sink, or control context
was clipped. Auxiliary enrichment limits alone are not a reason for low
confidence or `needs_review`.

The shared confidence rubric applies to every decision: high means decisive
behavior or the precise absence of a decisive fact is directly established;
medium means one bounded framework, purpose, ownership, or syntactic inference
remains; low means decision-critical evidence is sparse, conflicting, or
truncated. `needs_review` is therefore not automatically low confidence.

This gives inexpensive models framework and rule semantics such as
`missing-algorithm-allowlist`, `poison-null-byte/check-before-transform`,
`cookie-authenticated-state-change`, and `hardcoded-key` without leaking the
expected benchmark verdict.

Security paths contain bounded excerpts around terminals and intermediate
ranges. Non-path observations are grouped by file and enclosing symbol, retain
their evidence IDs, and contain one bounded source window rather than a raw
repository dump. Configuration-looking identifiers pull in non-secret
repository defaults and references. Values for password, secret, token,
credential, private-key, and API-key settings are never added as configuration
facts. Source, entrypoint, resource, guard, sanitizer, validation, and literal
observations can enrich those groups but do not become standalone verdict jobs
unless the group has an unused sink, sensitive operation, or security
configuration anchor.

Path reviews also receive bounded related context when exact source names make
it available:

- `helper_definition_context` contains at most 40 lines from an exact named
  helper or model/configuration declaration;
- `import_context` records the exact import used by the candidate;
- `dependency_context` records the repository-declared package version while
  explicitly not claiming the effective resolved/runtime version;
- `registration_context` records up to two exact framework route registrations
  for the named handler; and
- `framework_context` records exact framework imports, entrypoints, or small
  manifest declarations in the nearest application scope. It identifies the
  stack for review and does not claim that the framework is active at runtime.

This enrichment is lexical and name-bounded, not a call graph. A review gets at
most 12 exact-name related facts, divided across definitions,
imports/dependencies, and registrations, plus at most eight scoped framework
facts. Framework declarations are indexed once per bundle build and reused by
path and observation reviews. Security-sensitive definition literals are
redacted while their structural declaration remains visible. Ambiguous
same-name definitions remain context rather than resolution claims, and parser
failures never fail review construction merely because optional related context
could not be found.

Observation reviews use the same exact-name helper lookup when their captures
reference a callable or named constant outside the candidate file. Anonymous
lambda parameters and local/object variables are not helper definitions. This
keeps cross-file implementations such as a redirect URL builder visible without
claiming call resolution or taint propagation.

C# observation reviews can also reuse the established stored-output
neighborhood facts. For Razor raw-output leads this supplies exact
`bound_remote_input`, property assignment, persistence, model-property,
view-composition, conventional controller action, repository retrieval, model
navigation, and relevant EF retrieval-configuration excerpts. For repository
SQL observations, `exact_caller_context` supplies at most two exact C# call
sites with their bounded enclosing methods. These roles remain lexical review
context; they improve a model's final verdict without manufacturing a
deterministic security path or claiming general interprocedural taint.

C# database observations distinguish a typed query API from locally visible
dynamic SQL construction. Concatenation, interpolation, formatting and bounded
same-callable aliases produce a `bounded_dynamic_query_composition` review even
when no controller or repository handoff resolves. Unknown production origin
is decision-critical for that review: it remains `needs_review` until supplied
facts establish attacker influence or an affirmative fixed, constrained or
allowlisted origin. A resolved request-to-query path can promote the same code
to an issue; a missing path does not turn dynamic construction into a safe fact.

Generic local names such as `model`, `options`, and `order` are not treated as
cross-file helper identities. Razor UTF-8 BOMs are tolerated when resolving an
`@model` declaration.

Configuration questions distinguish control ownership. An explicit setting
tagged `recommendation:fix-application` asks whether later application
configuration supersedes that exact value; the reviewer must not assume that a
proxy or gateway overrides password, lockout, session-cookie, or `HttpOnly`
semantics. The generic authoritative-layer/deployed-value question remains for
controls that frameworks or infrastructure can genuinely own.

Every built-in `security_configuration` rule must provide all three parts of
the decision boundary: `investigate` identifies the relevant security purpose,
`verify` names the smallest authoritative artifact or runtime behavior that can
settle it, and `exclude` prevents a verdict from API/configuration syntax alone.
The shared TLS, hash, cookie, JWT, and CORS guidance anchors apply this contract
consistently to their language variants. Sensitive-operation rules use the same
shape; for Rust unsafe and FFI boundaries, verification centers on the actual
invariant and wrapper contract rather than the presence of `unsafe` or `extern`.

A second bounded layer may add at most eight repository facts when the first
context exposes an exact name or binding:

- `feature_gate_context` records exact challenge/feature descriptors;
- `feature_gate_policy_context` records the repository implementation that
  interprets those descriptors, while explicitly leaving deployed state
  unproved;
- `configuration_binding_context` connects an exact dotted configuration path
  to repository defaults or startup use without claiming its runtime value;
- `template_binding_context` records an exact sibling component template raw
  binding; and
- `exact_reference_context` records short exact references in candidate files.

Only one lexical helper expansion is allowed. Exact references are limited to
candidate files, template lookup is limited to the named sibling component,
configuration paths must be dotted identifier paths, and large files remain
excluded. These facts are context, not cross-function flow, attacker control,
dependency semantics, or deployed configuration proof.

`mehscan investigate review-triage ROOT --responses PATH` validates exactly one
compact decision for every emitted path and observation review against the job
fingerprint. The fingerprint covers exact facts and both forms of
`review_basis`, so changing reviewer-visible rule semantics invalidates stale
responses. The existing C# neighborhood JSON remains a separate format.

Review pages contain at most 100 items. The output contains `offset`,
`total_reviews`, and `next_offset`; these remain useful for inspection and APIs,
but an arbitrary page is not an AI reasoning boundary.

`mehscan investigate review-bundles ROOT --output DIR` scans the admitted set
once and groups it by review kind and capability while retaining the exact CWE
union as category metadata. Paths and
observation-only neighborhoods are never mixed. One semantic category is one
model request unless its compact JSON exceeds `--max-bytes` (512 KiB by
default) or it contains more than `--max-reviews` items (20 by default), in
which case only that category is split into deterministic parts. The item
limit accepts 1 through 100 for controlled experiments and retry tuning. No
tokenizer dependency is required.

Request files use semantic names rather than sequence numbers:

```text
full--path--authentication--cwe-347--p01--7f31ac92.json
full--observation--html-output--cwe-79--p01--29cc32e1.json
full--observation--http-request-data--review-only--p01--83ec091a.json
full--observation--authentication--multi-cwe-8--p01--34b52609.json
```

The final eight hexadecimal characters are derived from the complete bundle
fingerprint. `manifest.json` records the full identity, category, part count,
exact byte size, review IDs, raw UTF-8 context-text bytes, and exact repeated
context-text bytes. The latter two fields cover source-bearing fact excerpts
and evidence captures before JSON escaping. They are stable regression metrics,
not tokenizer estimates: token cost depends on the selected model, and repeated
text can be necessary when the same excerpt has a different location or role.
Requests are written as compact JSON beneath `requests/`; indentation is not
useful model context and previously accounted for roughly 37% of the largest
preserved Juice Shop request's file bytes. The human-readable manifest and an
empty `responses/` directory are created beside them.

### Payload compaction decision

A local benchmark over 900 preserved request artifacts (1,226 path reviews and
2,552 observation reviews) found that context text occupied about 22% of path
bundle bytes and 19% of observation bundle bytes. Exact repeated context text
accounted for about 8.4% and 3.1% of total request bytes respectively. Most path
repetition was intentional: for example, one source line can be both source and
intermediate context, or identical configuration text can occur at distinct
locations. Rule titles and notes were negligible in the largest requests.

Representative preserved runs showed the same order of magnitude across the
implemented stacks:

| Corpus | Reviews | Request size | Context text | Exact repetition |
| --- | ---: | ---: | ---: | ---: |
| Juice Shop (JavaScript/TypeScript) | 119 | 1.81 MiB | 17.4% | 4.4% |
| Orchard Core (C#) | 347 | 5.98 MiB | 44.5% | 12.2% |
| crAPI (Java) | 47 | 0.60 MiB | 20.3% | 3.2% |
| govwa (Go) | 34 | 0.42 MiB | 13.3% | 3.6% |
| DSVW (Python) | 3 | 0.07 MiB | 47.6% | 0.1% |
| Vulnerable API (Python) | 9 | 0.08 MiB | 6.7% | 1.7% |

These are byte-composition measurements, not verdict-quality or token-count
measurements. The selected corpora also have different rule mixes, so compare a
corpus with its own future run rather than treating the percentages as language
rankings.

Consequently schema-level excerpt dictionaries and reference indirection are
deferred. They would make each review harder for a model to read, save only a
minority of bytes, and require role/location reconstruction. The bundle remains
self-contained and byte-bounded. Use the manifest metrics to detect growth; if
repetition becomes material, first reduce irrelevant neighborhood selection,
then benchmark model verdict parity before changing the request schema.

Primary path and observation excerpts have an additional 16 KiB per-fact cap.
Ordinary multi-line context is unchanged. When a generated or minified line is
larger than that cap, the excerpt is centered on the actual evidence location;
this both reduces payload and avoids the older failure mode where the first
64 KiB of a line was returned even when the security observation occurred
later. `context_truncated: true` preserves that limitation for the reviewer.
In the preserved Orchard run, 32 primary excerpts exceeded 16 KiB; applying the
cap removes about 1.38 MiB of raw context, roughly 23% of that run's request
bytes, before JSON escaping. This is the material easy saving identified by the
benchmark.

Every bundle repeats the model goal and compact triage contract. A response
echoes `bundle_fingerprint` and contains exactly one result for every
`review_id`. `review-bundle-triage` rejects an unknown, duplicate, missing, or
invalid result. An interrupted or incomplete request is retried as one bundle;
there is no per-item merge state or conflicting-replacement protocol.

`mehscan investigate review-bundle-summary --run DIR [--responses DIR]`
requires every response named by the manifest, validates each complete bundle,
and emits the diagnostic run summary. Issue decisions merge across path and
observation streams only for the same capability, exact primary range, and
rule-defined invariant. The original per-review decisions remain present.

Consumer output is generated by the same executable after validation:

```text
mehscan report --run DIR --responses RESPONSES_DIR --format json --output mehscan-findings.json
mehscan report --run DIR --responses RESPONSES_DIR --format sarif --output mehscan-results.sarif
mehscan report --run DIR --responses RESPONSES_DIR --format markdown --output mehscan-report.md --include-dismissed true
```

Canonical JSON retains confirmed findings and unresolved reviews. Final SARIF
contains confirmed issues only; deterministic scan SARIF remains explicitly a
candidate format. Markdown prioritizes unresolved reviews and their decisive
checks, then presents confirmed and dismissed summaries for human handoff. The
complete field contract is documented in
[`output-contract.md`](output-contract.md).

Before bundle construction, evidence already owned by an admitted deterministic
path is not repeated as a weaker top-level observation sink. A mixed
observation group remains reviewable when it has a distinct configuration or
sensitive-operation anchor; only its path-owned sink is removed from that
observation payload. Other source and policy context remains visible. This is
cross-stream evidence correlation, not general finding deduplication, and it
does not suppress either the deterministic path or a distinct observation.

Observation reviews receive the same bounded repository-context vocabulary as
path reviews where it is available: evidence-captured definitions, exact helper
definitions, one lexical second hop, exact registrations and consumers,
configuration bindings and lifecycle facts, feature gates, sibling template
bindings, and exact Express template/configuration excerpts. These remain
non-flow facts. They help the reviewer answer the supplied security question
without pretending that proximity proves attacker influence or control
effectiveness.

The triage contract requires a reviewer to confirm that a requested artifact is
actually absent before returning `needs_review`. A response must not ask to
inspect a helper, route, producer, consumer, configuration, validation, or
protection excerpt already included in `facts`; it must reason from that excerpt
and choose a final decision when the excerpt is decisive. This is a reviewer
discipline, not automatic promotion by the engine.

Explicitly anonymous C# authentication and registration endpoints may receive
three bounded facts: the complete endpoint operation, the controller-level
authorization default, and the exact matching Razor form. The reviewer is then
asked whether the public boundary is intentional and whether the operation
performs privilege-bearing work beyond ordinary sign-in or self-registration.
These application-owned policy facts replace the generic deployed-control
question for that review; they do not prove arbitrary runtime authorization or
cross-function role behavior.

Request-controlled C# Identity role assignment is a distinct path review. A
bounded path is admitted only when an ASP.NET-bound model decision
syntactically controls a typed `UserManager<T>.AddToRoleAsync` call. A rejecting
guard that reads another property from the same bound model is shown as
`ineffective_protection_context`, because client-submitted state cannot prove
the caller's role. Exact endpoint, controller authorization metadata, bound
model, and matching form facts are attached. An explicit server-owned
`[Authorize(Roles = ...)]` or covering `User.IsInRole(...)` guard is retained as
control evidence and prevents this candidate shape.

`review-tasks` and `review-progress` remain available as low-level page
diagnostics, but they are not the recommended model orchestration workflow.

On completion, triage reports both issue instances and conservative
`issue_groups`. Security-path issues merge only when file, enclosing sink
symbol, capability, and CWE set are identical. Observation-only issues never
merge because they do not carry a proved relationship. Grouping is presentation
and workload reduction; the original result list is always preserved.

Complete security paths are admitted first. Production observation neighborhoods
follow in security relevance order. Paths whose components are named
`codefixes`, `code-fixes`, or `hacking-instructor` remain in deterministic scan
coverage but are excluded from AI jobs as non-deployed source payloads. Use
`--include-review-material true` for an explicit teaching/corpus review; those
items sort after production neighborhoods. `review_material_excluded` records
how many review items the default policy omitted.

When a repository contains maintained C/C++ source, ordinary observations from
secondary-language build, CI, documentation, packaging, support, and root
release scripts use the same review-material boundary. Raw evidence remains in
scan JSON, deterministic security paths remain admitted, and the explicit flag
restores the omitted observation jobs. This policy deliberately does not treat
shipped application directories or a generic `tools` tree as nonproduction.

## Validation

Evaluate AI-input changes separately from deterministic scanner truth:

1. Freeze the review-job fingerprint and expected deterministic contents.
2. Use Luna medium as the default validation reviewer. When a second tier is
   justified, use Sol medium at most; do not spend on Astra for this gate.
   Luna low can be observed as an extra stress test, but is not a compatibility
   target.
3. Validate schema compliance, one result per job, and absence of invented
   flows or controls.
4. Score decision correctness and whether requested checks are minimal and
   decisive.

`tests/fixtures/review-guidance-contract` is the lightweight contract corpus.
It emits one non-path observation in each supported language (C#, Java,
JavaScript, TypeScript, TSX, Python, Go, and Rust), with no paths. Tests require
every emitted basis to preserve non-empty `investigate`, `verify`, and
`exclude` guidance, freeze fingerprint
`path-reviewpack-a14dcc36c2f21497`, and prove that changing reviewer-visible
basis text changes the fingerprint. A catalog-level parity test prevents a new
security-configuration rule from omitting any part of that guidance.

`mehscan evaluate review-prepare ROOT` adds a separate final-verdict gate. Its
default `cross-language-review-verdicts.yml` manifest selects exact current
path or observation reviews while keeping expected decisions out of the model
request. `review-score --responses PATH` requires one compact result per case,
rejects stale pack identities, and compares the submitted decision and
confidence with the hidden manifest bounds. This complements the older
AI-only/evidence-assisted/candidate-assisted finding evaluation; it does not
replace repository-level recall or precision measurement.
5. Keep scanner precision/recall metrics separate; model agreement alone does
   not redefine benchmark truth.

For a context-compaction change, use a matched-review parity gate:

1. Match old and new objects by stable review ID; exclude and explain admission
   changes instead of treating different inventories as parity.
2. Include both contexts affected by the size limit and ordinary multi-line
   controls. The model receives only each review object and its contract, with
   no repository browsing or hidden source.
3. Lock all old decisions before reviewing the new variants. Compare decision,
   confidence, decisive checks, malformed input, and whether the supplied
   excerpt contains its anchor evidence.
4. Require zero input-quality regressions. A model agreement is supporting
   evidence only; deterministic tests must separately prove byte bounds and
   evidence-location coverage.
5. Record request bytes and context bytes from `manifest.json`. Do not estimate
   model tokens from bytes because tokenizer behavior is provider-specific.

The 2026-08-28 Orchard context-cap checkpoint matched ten reviews: six affected
minified/generated observations and four ordinary SQL, filesystem, redirect,
and deterministic-path controls. Luna medium produced exact decision and
confidence parity for nine. The remaining Vue observation improved from
low-confidence `needs_review` to high-confidence `not_issue` because the new
window included the evidence capture that the old first-64-KiB slice omitted.
There were no regressions or malformed inputs. These outcomes validate payload
sufficiency, not the security truth of the model decisions.

The reusable `mehscan-triage` Codex skill implements this reviewer guidance for
interactive use. It compensates for missing candidate excerpts by requiring
bounded investigation queries, but it does not remove the need for a
self-contained language-neutral review-job payload for one-shot or streaming
models.

Bounded origin/consumer enrichment may add `reference_use_context`,
`stored_write_origin_context`, `configuration_lifecycle_context`,
`endpoint_registration_context`, `endpoint_handler_context`, and
`endpoint_handler_helper_context`. The helper role is a single exact Spring
controller-receiver-to-implementation hop used to explain the behavior behind
a literal route policy; it is not a call graph. At most six such facts are
attached per review. They require exact repository shapes and remain lexical,
non-runtime context: they do not claim deployed configuration, package
implementation, or cross-function taint flow.

`protection_context` is reserved for a potentially effective control linked to
the path. A syntactically present check that the deterministic relationship
already proves ineffective is emitted as `ineffective_protection_context` and
is also named in `review_basis.deterministic_facts`. Examples include checking
a suffix before a later filename transformation, substring path containment,
and policy text without executable validation. Reviewers must reason about
ordering and enforcement rather than treating every guard-shaped excerpt as a
sanitizer.
