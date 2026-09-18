# Kotlin quality checkpoint

Kotlin is a **partial JVM profile**. The selected cases below exercise its
implemented boundaries; they do not establish whole-application recall or
parity with the established Java, Python, JavaScript, Go and C# profiles.
Full parity remains a release gate, not a claim made by this checkpoint.

## Applications

| Application | Pinned revision | Purpose |
| --- | --- | --- |
| [Vulnerable Petclinic](https://github.com/secure-software-engineering/spring-petclinic-kotlin) | `3206fed5d8d827ffa85eb73d5e31a5136cf18519` | Quoted HQL String injection and an Int interpolation control; source-reviewed, not built or executed. |
| [Upstream Petclinic](https://github.com/spring-petclinic/spring-petclinic-kotlin) | `da08609c277f95c37dd91187867f74dbad1090f8` | Production-package discovery and parsing reference; zero admitted boundary reviews is not a clean-app certificate. |
| [Official Ktor samples](https://github.com/ktorio/ktor-samples) | `1c9df7cf102d638eadaf545fcce4c0ec5ccad334` | JVM digest and fixed build-time command controls; deliberately admitted teaching sources, not deployed vulnerabilities. |
| [Original quality app](../tests/fixtures/kotlin-quality/README.md) | Branch fixture | Runnable vulnerable and safe Spring/JPA/JdbcTemplate endpoints; no third-party source copied. |
| [Original JDBC controls](../tests/fixtures/kotlin-jdbc/app.kt) | Branch fixture | Statement execution and prepared SQL vulnerable/safe pairs; static source controls, not a running application. |
| [Original filesystem controls](../tests/fixtures/kotlin-files/README.md) | Branch fixture | Read/write path influence, normalization, allowlist and content/path separation; source-only controls. |
| [Original receiver controls](../tests/fixtures/kotlin-receivers/README.md) | Branch fixture | Local/member identity and custom fixed-path helper controls; source-only. |
| [Original import controls](../tests/fixtures/kotlin-imports/README.md) | Branch fixture | Custom wildcard Runtime exclusion and canonical JVM import variants; compiled, custom control alone executed. |
| [Original JDBC factory controls](../tests/fixtures/kotlin-jdbc-factories/README.md) | Branch fixture | Inferred Statement/Connection raw, fixed and bound SQL pairs plus a constant lookalike; compiled and directly tested with H2. |
| [Original prepared ownership controls](../tests/fixtures/kotlin-prepared-ownership/README.md) | Branch fixture | Exact alias execution, unrelated binding exclusion, reset/rebind and conditional or preparation-only behavior; compiled and directly tested with H2. |
| [Original JVM URL controls](../tests/fixtures/kotlin-network/README.md) | Branch fixture | URL/URI factories, raw/fixed/allowlisted reads, lazy construction and coroutine I/O; compiled and directly checked against disposable loopback targets. |
| [Seqra mixed Spring demo](https://github.com/seqra/java-spring-demo/tree/66421a37ae573543c0a71e7b7689adf26f44cf38) | `66421a37ae573543c0a71e7b7689adf26f44cf38` | MIT-licensed intentionally vulnerable mixed Java/Kotlin source; three selected original Kotlin files compiled with validation dependencies and two direct loopback method checks; the Kotlin fetch is included in the latest selected oracle. Whole-app build and deployed MVC exposure are unverified. |

External source stays outside the public repository. Discovery now admits
Petclinic production packages containing `samples` below `src/main/kotlin`:
29 vulnerable and 26 upstream Kotlin files, instead of only two build scripts
per application. The Ktor selection admits 170 Kotlin files and one JavaScript
file; five Swift files remain unsupported. All admitted files parse successfully.

## Independent cases and runtime checks

The initial oracle was established from source before model comparison: four positive
cases and seven negative controls. Positives are Petclinic String-to-HQL,
original-app String-to-HQL and request-selected executable/arguments, and the
Ktor HTTP Digest provider's MD5 default. The last case concerns legacy
credential hashing in teaching source, not verified deployment exposure.
Negative controls include typed integer query interpolation, separately bound
query values, a fixed executable, SHA-256 and fixed build-time command arrays.

Petclinic's complex `Owner` controller argument is normally an implicit Spring
model attribute. Its inherited writable `lastName` reaches the repository;
the supplied binder excludes `id`, not `lastName`. Exact model, superclass,
controller and binder excerpts are included for review. This is source context,
not a native cross-file taint path or verified runtime repository dispatch.
See [Spring model binding](https://docs.spring.io/spring-framework/reference/web/webmvc/mvc-controller/ann-methods/modelattrib-method-args.html).

The original fixture builds with Temurin 17.0.20.1 and Gradle 9.7.0. The SQL
checkpoint verified fifteen loopback checks. A benign injected predicate returns both seeded
records through the unsafe query; the bound query returns none for the same
text. A quote breaks the unsafe query but remains data in the bound query.
The JdbcTemplate pair also proves predicate injection returns two records,
while positional binding returns none for the same text and handles a quote.
Numeric text is rejected with HTTP 400; a valid integer works. Command checks
execute only the benign `whoami` command. These results validate the fixture,
not the external Petclinic or Ktor applications.

## Model and report gate

Fresh Luna and Terra 5.6 evaluations use medium reasoning, identical bounded
requests, no tools and mechanically validated response schemas, review IDs,
fingerprints and confidence policies. Agreement is compared with the independent
oracle; agreement by itself is insufficient. Eleven selected review instances
are substantially smaller than the established cross-language evaluation.

Early agreement concealed a shared Petclinic false negative. Later fresh runs
exposed a numeric-query false positive and an implicit-model-binding miss.
These motivated exact integer-operand facts, callable isolation and explicit
canonical Spring binding context. The failures remain recorded in the local
evaluation history; they are not removed from the oracle.

Reports are generated from canonical responses in JSON, SARIF and Markdown,
then checked independently for count reconciliation, scope, owner attribution,
concrete impact, remediation and verification. Runtime claims distinguish the
original fixture from source-only external corpora. Weak-digest remediation
respects HTTP Digest protocol compatibility.

The initial checkpoint's final fresh comparison agrees on **11/11 cases**. Each model matches all
eleven independent labels: four true positives, seven true negatives, zero
false positives and zero false negatives. Selected-case precision and recall
are both 100%; these are not whole-application metrics. The fourteen responses
across seven bundles all pass mechanical validation. Earlier failures still
matter: fresh-run repeatability across a broader corpus remains a release gate.
All six final report audits are ready for engineering handoff: five pass and
one passes with a sample-scoped review-kind correlation caveat, with no report
defect identified. Audit readiness does not certify language-wide coverage.

The full offline workspace test run passes, followed by focused Kotlin tests
after the final context changes. Formatting and patch checks pass. The original
app's smoke script at the initial JVM checkpoint reproduced eleven runtime checks.

## JDBC expansion

The profile now admits exact declared JDBC Statement, Connection and Spring
JdbcTemplate receivers, including import aliases and lexical shadow checks.
SQL text is captured separately from bound value arguments. Explicitly typed
callback operands and direct lambdas do not become JdbcTemplate SQL captures.
Numeric-query constraints also apply to these JDBC boundaries.

The independent oracle adds six cases before model evaluation: unsafe and bound
JdbcTemplate queries in the runnable app, plus unsafe/fixed Statement and
unsafe/bound prepared SQL in the static controls. The expanded selection has
seventeen cases: seven positive and ten negative. Prepared SQL positives include
subsequent execution in the supplied method; preparation alone must not be
reported as verified runtime query effects. Fresh comparison and report audits
are evaluated against the expanded labels, not the initial checkpoint's totals.

The expansion also admits four previously unobserved prepared calls in the
official PostgreSQL Ktor sample: create, read, update and delete. Independent
source inspection shows fixed private companion SQL constants with placeholders
and separately bound values. These four labels were assigned after discovery in
the first expansion run, without using model verdicts as the oracle. They are
included in the subsequent fresh run's predefined twenty-one-case oracle:
seven positive cases and fourteen negative controls. Exact constant-definition
facts now expose those literals while respecting local shadows and class ownership.

Both expansion comparisons match all **21/21 independent labels**: seven true
positives, fourteen true negatives, zero false positives and zero false negatives
per model. The subsequent run uses the complete predefined oracle and validates
owner, rule and source location before counting a label. All twenty model
responses across ten bundles pass mechanical contract checks. This remains
selected-case precision/recall, not whole-application recall or full Kotlin parity.
All eight final expansion report audits pass and are ready for engineering
handoff. SQL titles distinguish direct Statement execution, JdbcTemplate
execution and SQL construction before preparation. Scope labels distinguish
original static controls from the runtime-tested fixture and external samples.

The expanded app builds and passes fifteen runtime checks. Focused Kotlin unit,
native integration, capability/provenance and execution-context checks pass,
as do formatting and patch checks. The earlier full workspace pass predates
this JDBC expansion; the focused checks cover the changed Kotlin branches.

## Filesystem expansion

The adapter now follows bounded request influence through canonical Path
factories and owned Path resolve/normalize/absolute-path transformations to
file read/write path operands. These operations do not establish confinement.
Unknown path helpers, mutable aliases and callable boundaries stop propagation.
The request-controlled content of a fixed-target write is not a CWE-22 path.

Nine predefined labels extend the corpus to thirty cases: twelve positive and
eighteen negative. Six source controls cover unrestricted read/write, normalized
resolution without containment, fixed read, allowlisted read and fixed-target
content write. The runnable app adds unrestricted read/write and allowlisted read.
It builds and passes twenty runtime checks: traversal retrieves a disposable
sibling file and replaces it through the unsafe routes; the safe route rejects
the same traversal and accepts its fixed selector. The generated file tree is
removed after its own process stops, with cleanup-path verification.

Fresh model agreement and report audits use the predefined thirty-case oracle;
both models match **30/30 labels**: twelve true positives, eighteen true
negatives, zero false positives and zero false negatives each. All thirty-four
responses across seventeen bundles pass mechanical validation. All ten report
audits pass and are ready for engineering handoff. These remain selected-case
metrics and do not replace the remaining parity gates.

The focused Kotlin, native integration and execution-context checks pass. A
regression also ensures known incompatible Path/text argument shapes do not
become deterministic paths. Regenerating the full selected corpus after this
guard confirms identical review fingerprints and exact request bytes, so the
validated model responses still apply to the final code.

## Explicit receiver precision

Four additional original source controls exercise explicit `this.field` when
a same-named local has a different type. The native scanner admits the real
EntityManager query and Path read, excludes the fake query receiver, and does
not invent a path through a custom method that returns a fixed file path.
These controls are parsed, not built or executed.

The first fresh model round exposed a shared false positive: both reviewers
treated the custom member's `resolve(name)` as a JVM Path operation because
the observation packet omitted its declaration. Agreement was perfect but
both models matched only two of three admitted labels.
Report audits accepted those canonical reports with presentation warnings;
they assess reporting quality and do not replace the vulnerability oracle.
The corrected packet supplies the exact member declaration and its unambiguous
same-file type;
imported or shadowed definitions are not borrowed. This adds review context,
not native helper-effect inference or a forced verdict.

Fresh reviews of the revised bytes match all three predefined admitted labels
for both models, and both new report audits pass and are ready for handoff.
The fourth control is a native exclusion check, not a model-reviewed case.
All seventeen earlier bundles remain byte-for-byte unchanged, preserving their
validated thirty-case results. The combined selected oracle is therefore
**33/33 labels per model**: fourteen positive and nineteen negative, with no
selected false positives or false negatives. All twelve report audits pass.
This small corpus still does not establish parity with broader language profiles.

The twelve focused Kotlin unit tests and eight native integration tests pass.
They cover both directions of local/member type confusion, explicit member
assignment, unrelated local assignment, ambiguous receivers in extensions,
lambdas and anonymous objects, ordinary versus extension-property accessors,
and exclusion of imported or shadowed helper-type context.
The full workspace/all-targets locked offline sweep passes. A final constructor
scope refinement follows that sweep: a compiled original probe confirms that
a direct nested class can supply a constructor field's type before the class
body's byte range. The regenerated packet selects that nested definition,
not its file-level namesake. The focused unit/native checks pass again after
this refinement, and all twenty judged bundles retain identical request bytes.

## Import and review-scope precision

Original Runtime controls add three positive labels: fully qualified, explicitly
imported and aliased JVM execution. A fourth, excluded control imports a custom
Runtime through a foreign package wildcard and returns fixed text. All four
files compile with Kotlin 2.4.10/JDK 17; only the custom control was executed.
Separate compiler probes confirm that built-in integer/String type annotations
have different resolution behavior from the JVM Runtime default import.

The first import comparison matched its three labels but attributed one finding
to the adjacent harmless method. Kotlin path-review excerpts now stop at the
owning function, as observation excerpts already do. Correct verdicts alone do
not establish correct reports.

A subsequent full fresh thirty-six-case round exposed another precision failure:
Luna reported request content written to a fixed destination as an integrity
violation, without evidence of an application policy. Terra dismissed it.
Luna matched 35/36 labels (one false positive); Terra matched 36/36. The file
report's independent Luna audit was not ready for handoff. The write rule now
explicitly separates target-path selection from content and requires supplied
policy evidence before alleging another integrity/authorization violation.
The earlier failure remains in evaluation history; no oracle label was changed.

The MD5 report also clarifies that a dynamic algorithm expression can fall back
to MD5 without every invocation using it. Unknown literal metadata is retained,
and the report describes the fallback rather than inventing a constant value.

The next full fresh comparison uses all revised request bytes and the predefined
**36-case oracle**. Both models match every label: seventeen true positives,
nineteen true negatives, zero false positives and zero false negatives each.
Agreement is 36/36; selected-case precision and recall are 100%, not
whole-application metrics. All forty-two responses across twenty-one bundles
pass mechanical contract validation.

All fourteen independent report audits are ready for handoff: thirteen pass
and one passes with a minor warning to identify the precise HTTP Digest
configuration/provider and test artifacts for compatibility verification.
The earlier fixed-write report failure is corrected without changing its label.
Fresh repeatability at broader coverage remains a gate despite this passing run.

Thirteen focused Kotlin unit tests, nine native integration tests, two catalog
capability/provenance checks and the specialized execution-context check pass.
The CLI builds offline; formatting and patch checks pass. The full workspace
sweep recorded above predates this import/context refinement; it was not rerun
for this checkpoint. The existing twenty runtime checks apply to the unchanged
quality app, not to the external applications or real import-control handlers.

## JDBC factory expansion

Canonical Connection `createStatement`, DriverManager `getConnection` and
declared DataSource `getConnection` factories now establish bounded receiver
identity. Immutable local aliases and direct chains are supported; unknown
helpers, mutable inferred values, field initializers and callable handoffs stop
inference. Declared nullable receivers through `!!` retain their prior support.
This establishes API identity, not prepared execution or protection ownership.

Four original admitted controls add two positive and two negative labels before
model evaluation. The separately excluded lookalike performs no JDBC operation.
All compile with Kotlin 2.4.10/JDK 17. Nine direct H2 checks reproduce benign
predicate injection in both raw SQL routes, fixed-query and bound-value behavior,
valid selection, quote handling and the constant lookalike. This verifies test
methods, not HTTP deployment or the external Ktor application.

The official Ktor PostgreSQL initializer supplies a fifth new, negative label:
its inferred Statement executes a fixed private companion table-creation SQL
constant. Its packet includes the exact constant and isolated `init` block.
These predefined labels expand the selected oracle to forty-one cases: nineteen
positive and twenty-two negative. A fresh full comparison and report audits
evaluate the revised requests rather than reusing earlier verdicts.

Both fresh model comparisons match **41/41 predefined labels**: nineteen true
positives, twenty-two true negatives, zero false positives and zero false
negatives each. Agreement is 41/41. All forty-six responses across twenty-three
bundles pass mechanical validation. Selected precision/recall remain 100%; this
does not measure whole-application recall or establish framework-wide parity.

All sixteen independent report audits are ready for handoff: fourteen pass and
two pass with minor warnings. The warnings ask for exact HTTP Digest verification
configuration/test artifacts and explicit method names in the grouped command
finding's heading or verification instructions. Both factory-control audits pass.

Fourteen focused Kotlin unit tests, ten native integration tests, two catalog
capability/provenance checks and the specialized execution-context check pass.
The offline CLI build, formatting and patch checks pass. A final nullable-receiver
guard leaves all twenty-three request bundles and their manifests byte-identical,
so the fresh responses apply to the final implementation. The previous full
workspace sweep predates this expansion; this checkpoint uses focused checks.

## Prepared use ownership

Both path and observation review packets now include exact same-callable
binding, reset, close and execution uses of an admitted preparation and its
immutable local aliases. Each fact stays attached to its own preparation's
evidence ID. Bindings on another object or another real statement are not
borrowed; nested callable handoffs stop collection. Conditional execution
remains source context, not guaranteed execution or a native protection summary.

Four predefined original labels extend the oracle to forty-five cases: twenty-one
positive and twenty-four negative. The raw alias-execution case is not protected
by binding an unrelated object. Fixed placeholder SQL resets and rebinds its own
value safely. Fixed preparation-only SQL closes without execution. The caller
can enable the conditional raw route. All four compile with Kotlin 2.4.10/JDK 17;
eight direct H2 checks exercise injection, bound values after reset, valid values,
quote handling, both conditional branches and preparation-only closure.
These are direct test methods, not an HTTP deployment assessment.

Fresh full model comparison and report audits use the revised request bytes
and all forty-five predefined labels; earlier forty-one-case responses are not
silently reused for changed packets.

Both fresh models match **45/45 predefined labels**: twenty-one true positives,
twenty-four true negatives, zero selected false positives and zero false
negatives each. Agreement is 45/45; all fifty responses across twenty-five
bundles pass mechanical validation. These remain selected-case metrics.

The fresh report audit run completed eight of eighteen audits before the
account's model usage limit stopped the remaining jobs. Seven completed audits
pass and one passes with the previously recorded HTTP Digest verification
warning; all eight are ready for handoff. The remaining ten, including the new
prepared ownership reports, are unverified. Earlier audit results are not
substituted for this round. Completing those audits remains a release gate.

Fifteen focused Kotlin unit tests, twelve native integration tests, two catalog
capability/provenance checks and the specialized execution-context check pass.
The offline CLI build, formatting and patch checks pass. Eight direct H2 checks
pass for the new controls. The earlier full workspace sweep predates this change.

## JVM URL expansion

The profile now has eleven rules, including canonical JVM URL resource reads
and lazy connection construction. Bounded same-function request influence
passes through one-String URL/URI constructors, `URI.create`, `toURL` and
immutable local aliases. URL objects do not become command/SQL string paths,
and known incompatible constructor arguments are rejected. Unknown helpers,
mutable inferred values, field initialization and callable handoffs stop inference.

Seven admitted original cases are source-adjudicated before model comparison:
four positive resource-access cases and three negative controls. The raw URI
read, legacy URL constructor read, connecting/reading route and coroutine
fetch accept the request URL. The fixed and allowlisted routes keep the target
server-owned. The construction-only route returns a class name without I/O.
The excluded lookalike returns constant text. All compile with Kotlin 2.4.10/JDK
17; ten direct loopback checks confirm those behaviors, including a request
counter proving that construction alone sends no request. Native source-to-sink
paths stop at the coroutine boundary; its review receives exact caller context.

The pinned Seqra fetch now produces an outbound-request observation. Its packet
contains both the request-body caller and the query-parameter caller with an
omitted trailing default, plus the exact request DTO. Unique typed caller context
allows omitted trailing defaults, while ambiguous overloads and unsupported named
calls remain excluded. The three original Kotlin production files compile against
cached Kotlin 2.4.10, Spring 7.0.9, coroutines 1.10.2 and JDK 17; two direct
controller-method checks retrieve a disposable loopback response through the
coroutine service. These validation dependencies differ from the repository's
declared full stack. This does not establish that the full mixed application builds
or that MVC binding/deployment works.

Seven manually source-adjudicated fixture decisions render successfully in JSON,
SARIF and Markdown: four issue instances and three dismissals, reconciled against
canonical counts; SARIF contains the four issue results. Reviewer metadata explicitly
identifies manual source adjudication with loopback controls, not model evaluation.
No fresh Luna/Terra comparison or independent report audit was available under the
account usage limit. Historical 45-case agreement remains a prior checkpoint,
not a measurement of the expanded profile. Fresh evaluation and audit of the new
network cases remain release gates.

Seventeen focused Kotlin unit tests, thirteen native integration tests, two
catalog capability/provenance checks and the specialized execution-context check
pass. The catalog contains 328 validated rules. CLI build, formatting and patch
checks pass. The earlier full workspace sweep predates this expansion.

Candidate reporting, declarative cross-language surface checks and review-job
contract tests also pass. Four optional external-corpus review-job tests remain
ignored by their existing policy; they are not counted as new verification.

## Remaining release gates

The historical quota-interrupted gates above are superseded by the fresh
expanded model and report checks below. Broader language parity remains open.

The additional Seqra source probe scans twenty-four files with no parse failures.
Its Kotlin controller supplies both a String request parameter and a request-body
DTO to `UrlFetchService.fetch`. The service passes the URL through
`URI.create(url).toURL().openConnection()` inside `scope.launch`, connects and
reads the response, without a destination policy in the supplied source.
The initial probe admitted nine other reviews but no outbound-request review for
that Kotlin fetch. The JVM URL expansion above adds that observation and exact
caller context. Full cross-file/coroutine flow and deployment coverage remain
unproven; the probe is separate from the historical model comparison.

- Broader independently adjudicated positive/negative cases across the
  [remaining framework and flow gaps](kotlin-coverage.md#remaining-parity-gaps),
  especially additional JDBC factory identities and prepared execution/protection
  ownership, Ktor request flow, protections and helper effects.
- Fresh repeatability and precision at the breadth of the established profiles;
  a small successful slice cannot certify comparable language recall.
- Keep Kotlin explicitly partial until those gaps are covered. Multiplatform
  syntax parsing does not certify Android, Kotlin/JS or Kotlin/Native security.

## Fresh expanded AI and report checkpoint — 2026-09-17

The expanded oracle contains **53 predefined source labels**, with 26 positive
and 27 negative cases. It includes the previous 45 cases, seven original URL
controls and the pinned Seqra Kotlin fetch. Seqra's three Kotlin files are an
explicit source selection; the other mixed-language reviews from the whole
repository are not silently counted as Kotlin coverage.

Fresh `gpt-5.6-luna`, `gpt-5.6-terra` and `gpt-5.6-sol`, each at medium reasoning,
all match **53/53 labels**, with zero selected false positives or false negatives.
Three-model agreement is 53/53. A separate fresh Luna/Terra round also matches
53/53 labels for each model and agrees on all 53. Neither earlier verdicts nor
oracle answers are supplied to model prompts. The repeat began with 22 precision
controls and subsequently covered the remaining 31; its controls are not copies
of the primary responses.

Selected precision and recall are 100% for all five passes. These are measurements
of admitted cases, not whole-application recall or comparable framework breadth.
All 140 model responses over 28 distinct bundles pass exact fingerprint, ID,
confidence-policy and complete-set validation, covering 265 decision instances.
The [original fixture oracle](../tests/fixtures/kotlin-review-oracle.json) publishes
41 source-adjudicated fixture labels independently of the model results.

Report audits exposed actual handoff defects: conditional I/O caveats obscured
confirmed URL consumers; caller/consumer locations and grouped review IDs were
missing; overriding scope captions appended conflicting inherited labels; and
the evaluation caption incorrectly described Spring paths in the Ktor selection.
The handoff now distinguishes URL reads and connection use, cites bounded
operation/caller context, retains instance review IDs and replaces inherited
labels of the same kind. Scope statements distinguish isolated fixture builds
and checks from production deployment and third-party whole-application builds.
Source availability is compile/build inclusion, not execution frequency; typed
caller context is source evidence, not verified runtime dispatch.

All **55 final report sets** pass mechanical count/location reconciliation,
canonical-decision preservation and Markdown issue-ID checks. Independent audits
cover all five security passes across eleven nonempty corpora. The first final
audit round marked 54 ready; the remaining Ktor repeat report had the erroneous
framework caption. All five Ktor reports were corrected and freshly re-audited,
and all pass. Combined with the unchanged reports' audits, **55/55 are ready**.
Earlier failures and warnings remain in the evaluation history; they are not
substituted for changed artifacts. Earlier Digest follow-up specificity warnings
remain useful guidance even when a subsequent auditor accepts the handoff.

All **49 isolated runtime checks** pass again: twenty Spring fixture checks,
nine JDBC factory checks, eight prepared ownership checks, ten URL checks and
two direct pinned Seqra controller-method checks. No claim is made that the
third-party applications build in their original full stacks or are exposed in
production. The [machine-readable results](kotlin-quality-results.json) record
the response contract checks, report checks and final workspace test outcome.

The final full offline workspace/all-target sweep passes: **965 passed, zero
failed and 41 ignored**. Ignored checks are existing optional external-corpus
tests and are not counted as passed. The focused caller-trace and grouped-ID
regressions, CLI label replacement checks, formatting and patch checks pass.
An overlapping earlier retry hit a Windows executable linker lock; the final
sequential sweep completes successfully and is the authoritative result.

The selected JVM model, repeatability and report gates are complete. Broader
framework/platform coverage and established-language breadth remain the open
parity gates listed above; Kotlin remains an explicitly partial JVM profile.
