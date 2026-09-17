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
| [Original quality app](../tests/fixtures/kotlin-quality/README.md) | Branch fixture | Runnable vulnerable and safe Spring/JPA endpoints; no third-party source copied. |

External source stays outside the public repository. Discovery now admits
Petclinic production packages containing `samples` below `src/main/kotlin`:
29 vulnerable and 26 upstream Kotlin files, instead of only two build scripts
per application. The Ktor selection admits 170 Kotlin files and one JavaScript
file; five Swift files remain unsupported. All admitted files parse successfully.

## Independent cases and runtime checks

The oracle was established from source before model comparison: four positive
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

The original fixture builds with Temurin 17.0.20.1 and Gradle 9.7.0. Eleven
loopback smoke checks pass. A benign injected predicate returns both seeded
records through the unsafe query; the bound query returns none for the same
text. A quote breaks the unsafe query but remains data in the bound query.
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

The final fresh comparison agrees on **11/11 cases**. Each model matches all
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
app's committed smoke script reproduces all eleven runtime checks.

## Remaining release gates

- Broader independently adjudicated positive/negative cases across the
  [remaining framework and flow gaps](kotlin-coverage.md#remaining-parity-gaps),
  especially JDBC/JdbcTemplate, Ktor request flow, protections and helper effects.
- Fresh repeatability and precision at the breadth of the established profiles;
  a small successful slice cannot certify comparable language recall.
- Keep Kotlin explicitly partial until those gaps are covered. Multiplatform
  syntax parsing does not certify Android, Kotlin/JS or Kotlin/Native security.
