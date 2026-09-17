# Kotlin coverage and gaps

Kotlin support is a partial JVM profile. Mehscan parses `.kt` and `.kts` without
running Kotlin, Gradle or application code. Language filters accept `kotlin`,
`kt` and `kts`; investigation provides Kotlin outlines.

The ordinary source policy applies: tests, generated files and outer example
directories are excluded unless explicitly included. Under `src/main/kotlin`
or `src/main/java`, package segments named `samples` or `examples` remain
production source. Build scripts are parsed but their observations must be
distinguished from application runtime behavior.

## Supported surfaces

| Surface | Ownership and APIs | Evidence |
| --- | --- | --- |
| Command execution | Canonical `Runtime.getRuntime().exec(command)`, including the default JVM import | Process sink; CWE-78 |
| File read | Canonical `Files.readAllBytes(path)` and `readString(path)` | Read sink; CWE-22 |
| File write | Canonical `Files.write(path, content)` and `writeString(path, content)` | Write sink; CWE-22 |
| Digest selection | Canonical `MessageDigest.getInstance(algorithm)` | Algorithm configuration; CWE-327 |
| URI parsing | Canonical `URI.create(url)` | Parsing fact; CWE-918 |
| Persistence queries | Declared `javax.persistence.EntityManager` or `jakarta.persistence.EntityManager`; `createQuery` and `createNativeQuery` | Query sink; CWE-89 |
| JDBC SQL | Declared `java.sql.Statement` execution/batch text and `java.sql.Connection` prepared SQL construction | Query boundary; CWE-89 |
| Spring JDBC | Declared `org.springframework.jdbc.core.JdbcTemplate`; query, queryForList, queryForObject, update and execute SQL arguments | Query sink; CWE-89 |
| Spring MVC scalar inputs | Direct mapped methods of canonical `Controller`/`RestController` classes; annotated String request inputs | Request source; CWE-20 |

JVM boundaries recognize fully qualified names, exact imports and import
aliases. Short names from multiple wildcard imports are rejected conservatively.
A foreign package wildcard can replace the default JVM `Runtime` name, so that
short name is not admitted without an explicit import. Fully qualified,
explicitly imported and aliased JVM names remain supported. The compiler-tested
Kotlin built-in String/integer type behavior is distinct from JVM default imports.
Use-site ownership checks account for parameter/local/property/type shadows,
lambda parameters, loop bindings and catch bindings. Unknown or reassigned
persistence receivers do not inherit a typed field's identity.
Explicit `this.field` receivers resolve only to direct properties of the owning
class or object; a same-named local cannot supply or hide the member's type.
Receiver lambdas, anonymous objects, extension functions and extension
properties do not borrow the enclosing class's
`this` identity. Qualified `this` labels and inherited member resolution remain
unmodeled.
Observation reviews of explicit member receivers include the exact member
declaration and, where unambiguous, its same-file declared type. Imported,
wildcard-conflicted and shadowed type definitions are not borrowed. These are
review excerpts, not inferred helper effects or new deterministic paths.
Direct nested types also resolve in primary-constructor signatures; their
qualified ownership is retained in the review context.

Bounded same-function Spring scalar paths connect request inputs to command,
query and filesystem-path operands through identifiers, immutable `val` aliases, concatenation and
ordinary, braced or raw string templates. Propagation stops after eight levels,
at unknown helper results, mutable bindings, reassignment and callable boundaries.
SQL captures refer to query text, not separately bound JDBC values. Prepared
SQL construction is a review boundary; verify subsequent execution before
claiming runtime query effects. Explicitly typed callbacks and direct lambdas
are excluded from JdbcTemplate SQL matching. Fixed queries with separately
bound values and numeric request types do not
become string-injection paths. Literal excluded branches and statements after
direct return/throw carry explicit unreachable execution context.

Filesystem paths preserve input through canonical `Path.of`/`Paths.get`
factories and owned Path `resolve`, `resolveSibling`, `normalize` and
`toAbsolutePath` operations, including import aliases. Unknown factory/helper
results and mutable aliases stop propagation. Direct `this.field` Path receivers
use the same member ownership checks as SQL boundaries. Path normalization is not an
effective root-containment control. File-write content is a distinct operand
from the target path and does not create a CWE-22 path by itself.
See the [JVM Path API](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/nio/file/Path.html).

Persistence observation reviews can include exact typed caller methods, caller
binding policies, model declarations and a direct model superclass. Interface
context requires a unique direct implementation and declared type. This is
bounded review context, not proof of runtime dispatch or cross-file value flow.
Spring's default model-attribute binding is subject to binder policy and other
argument resolvers; the supplied excerpts must establish the relevant property.

A sink is a review lead, not a finding. URI parsing is not destination
authorization. Strong and weak digests are inventoried; only a weak choice with
a security-sensitive consumer establishes the cryptographic concern. A command
argument vector does not authorize a request-selected executable, and JVM
`Runtime.exec` does not automatically invoke a shell.

## Remaining parity gaps

- Inferred JDBC factory receivers, prepared-statement execution/protection ownership,
  JdbcTemplate overloads beyond the bounded patterns, Exposed and additional
  persistence APIs; complete protection and branch-join summaries.
- Ktor route inputs, output/redirect/upload policies, application-call ownership
  and framework-specific value flow; Spring WebFlux, implicit model-property
  source paths, authentication and authorization policy.
- ProcessBuilder, File extension APIs, OkHttp/Ktor clients, HTML encoding/output,
  deserialization, XML, TLS and JWT configuration.
- Elvis/smart-cast/destructuring propagation, helper effects, scope functions,
  coroutine/lambda handoffs and mixed Java/Kotlin relationships.
- Compiler-backed identities, imported superclass/interface resolution beyond
  the bounded context collector, overloads, safe calls, references, dependency
  metadata and Gradle source-set classification.
- Android intents/WebView/components/storage, Kotlin/JS and Kotlin/Native APIs.
  Parsing multiplatform Kotlin does not establish platform-specific coverage.

See the [quality checkpoint](kotlin-quality.md) for pinned applications, source
oracles, runtime checks, model comparison and the release gate. A small passing
native corpus does not establish parity with the broader established profiles.
