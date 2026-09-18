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
| URL resource read | Canonical declared URL, one-String URL constructor or URI factory/constructor followed by `toURL`; `openStream()` and zero-argument `getContent()` | Resource sink; CWE-918 |
| URL connection construction | Same canonical URL identities; zero-argument `openConnection()` | Lazy construction lead; CWE-918, requires connect/read consumer |
| Persistence queries | Declared `javax.persistence.EntityManager` or `jakarta.persistence.EntityManager`; `createQuery` and `createNativeQuery` | Query sink; CWE-89 |
| JDBC SQL | Declared `java.sql.Statement` execution/batch text and `java.sql.Connection` prepared SQL construction | Query boundary; CWE-89 |
| Spring JDBC | Declared `org.springframework.jdbc.core.JdbcTemplate`; query, queryForList, queryForObject, update and execute SQL arguments | Query sink; CWE-89 |
| Spring MVC scalar inputs | Direct mapped methods of canonical `Controller`/`RestController` classes; annotated String request inputs | Request source; CWE-20 |
| ProcessBuilder | Canonical constructor/direct start or declared/immutable-local builder `start` | Process execution lead; CWE-78, construction alone is inert |
| File access | Canonical declared/immutable-local `java.io.File`, unambiguous standard `readText`, `readBytes`, `inputStream`, `writeText`, `writeBytes`, `outputStream` | Read/write lead; CWE-22, content and target remain distinct |
| Object decoding | Canonical ObjectInputStream `readObject`/`readUnshared`, declared Jackson 2/3 ObjectMapper `readValue` | CWE-502 lead, requires controlled object materialization/policy |
| XML | Declared or bounded JAXP factory-created DocumentBuilder/SAXParser `parse`, factory feature/access configuration | CWE-611 lead, requires effective unsafe entity/access policy |
| TLS | Declared HttpsURLConnection `setHostnameVerifier` | CWE-295 configuration lead, requires bypass behavior and effective use |
| Servlet redirect | Declared javax/jakarta HttpServletResponse `sendRedirect` | CWE-601 lead, requires unsafe destination influence |
| Network consumers/clients | Declared/factory URLConnection `connect`/`getInputStream`/`getContent`; declared Java HttpClient `send`/`sendAsync`, OkHttpClient `newCall` | CWE-918 lead; lazy OkHttp calls require execution |
| Ktor inputs | Declared ApplicationCall or exact imported routing DSL in canonical Application/Route extensions; query/path indexing and `receiveText` | Request source; CWE-20 |
| Ktor responses/client | Owned call `respondRedirect`, explicit `respondText`/`respondBytes` with canonical ContentType.Text.Html (including canonical `withCharset`); declared HttpClient string-URL requests | CWE-601/CWE-79/CWE-918 leads; named arguments supported and plain text excluded |

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
ordinary, braced or raw string templates. Elvis alternatives retain possible
value influence, except a literal non-null left operand excludes its fallback;
literal null uses only its fallback. Propagation stops after eight levels, at
unknown helper results, mutable bindings, reassignment and callable boundaries.
SQL captures refer to query text, not separately bound JDBC values.
Statement identities also follow canonical Connection `createStatement`
factories, including direct chained calls and bounded immutable local aliases.
Connection identities follow canonical DriverManager `getConnection` and
declared DataSource `getConnection` factories. Inference includes local `init`
block values; it stops at unknown helpers, mutable inferred values, field
initializers and callable handoffs. Factory identity is not a protection or
proof that a prepared query executes. PreparedStatement's inherited SQL-text
overloads are not treated as ordinary Statement execution.
See the [JDBC Connection contract](https://docs.oracle.com/en/java/javase/25/docs/api/java.sql/java/sql/Connection.html).

Prepared SQL construction is a review boundary; verify subsequent execution before
claiming runtime query effects.

For admitted preparation calls, reviews include bounded exact same-callable
binding, reset, close and execution uses of the original receiver and immutable
local aliases. A different statement's bindings are not borrowed. These facts
retain source locations and require review of enclosing conditions and resets;
they are not native execution/protection summaries. Field storage, mutable
aliases, helper returns and lambda handoffs remain outside this use collector.

Explicitly typed callbacks and direct lambdas
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
approval. URL/URI factories preserve bounded same-function input through
immutable local aliases to URL operands. Known incompatible Path/URI/URL values
do not become one-String constructor arguments, and URL factory propagation
does not turn URL objects into command or SQL text. Typed callback handoffs,
unknown helpers, mutable inferred values and field initialization stop inference.
URL resource reads perform I/O; `openConnection()` only constructs a connection
object, so its review must establish a connect/read consumer. Scheme, resolved
address, port and redirect policy require separate review.
See the [JVM URL contract](https://docs.oracle.com/en/java/javase/25/docs/api/java.base/java/net/URL.html).

Strong and weak digests are inventoried; only a weak choice with
a security-sensitive consumer establishes the cryptographic concern. A command
argument vector does not authorize a request-selected executable, and JVM
`Runtime.exec` does not automatically invoke a shell.

## Remaining parity gaps

The XML policy follow-up validates DOCTYPE rejection and distinct factory
ownership through bounded source review and isolated direct-call controls.
Exact operation facts name only declared XML anchors; related configuration
evidence is context. This does not add native policy-effect propagation or
prove safety of other XML features, resolvers or configuration lifecycles.

- JDBC factory receivers beyond the bounded canonical factories, prepared-statement execution/protection ownership,
  JdbcTemplate overloads beyond the bounded patterns, Exposed and additional
  persistence APIs; complete protection and branch-join summaries.
- Ktor routing/argument-resolver families beyond bounded exact DSL ownership,
  upload and authentication/authorization policies, HTML encoders/output APIs beyond respondText/respondBytes
  and client request-builder effects; Spring WebFlux, implicit model-property
  source paths, authentication and authorization policy.
- ProcessBuilder mutation/argument-list effects and File extension overloads,
  client factories/builders beyond declared client receivers, URL proxy,
  context/custom-handler constructor overloads and URLConnection identities,
  HTML encoding and additional output APIs,
  deserialization type/filter policies, XML configuration effects, TLS trust
  managers/global defaults and JWT configuration.
- Compiler smart-cast/destructuring propagation, helper effects, scope functions,
  coroutine/lambda handoffs and mixed Java/Kotlin relationships.
- Compiler-backed identities, imported superclass/interface resolution beyond
  the bounded context collector, overloads, safe calls, references, dependency
  metadata and Gradle source-set classification.
- Android intents/WebView/components/storage, Kotlin/JS and Kotlin/Native APIs.
  Parsing multiplatform Kotlin does not establish platform-specific coverage.

See the [quality checkpoint](kotlin-quality.md) for pinned applications, source
oracles, runtime checks, model comparison and the release gate. A small passing
native corpus does not establish parity with the broader established profiles.
