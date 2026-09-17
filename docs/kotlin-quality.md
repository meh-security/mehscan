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

## Remaining release gates

- Correct default-import identity under explicit wildcard imports. A cached
  Kotlin compiler probe selects a harmless custom `Runtime` through its package
  wildcard, while the scanner currently admits it as JVM process execution.
  The receiver metrics above do not cover this newly identified identity gap.
- Broader independently adjudicated positive/negative cases across the
  [remaining framework and flow gaps](kotlin-coverage.md#remaining-parity-gaps),
  especially inferred JDBC factory identities and prepared execution/protection
  ownership, Ktor request flow, protections and helper effects.
- Fresh repeatability and precision at the breadth of the established profiles;
  a small successful slice cannot certify comparable language recall.
- Keep Kotlin explicitly partial until those gaps are covered. Multiplatform
  syntax parsing does not certify Android, Kotlin/JS or Kotlin/Native security.
