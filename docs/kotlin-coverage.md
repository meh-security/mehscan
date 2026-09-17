# Kotlin coverage and gaps

Kotlin support is partial. Mehscan parses `.kt` and `.kts` files without running
Kotlin, Gradle, or application code. Kotlin files use the ordinary repository
exclusion policy; `*Test.kt`, `*Tests.kt`, and `*.generated.kt` are excluded
unless `--include-tests` is supplied. The investigation API provides Kotlin
outlines, and CLI language filters accept `kotlin`, `kt`, and `kts`.

The initial profile inventories explicitly qualified JVM API calls:

| Surface | APIs | Evidence |
| --- | --- | --- |
| Command execution | `java.lang.Runtime.getRuntime().exec(command)` | Process sink; CWE-78 |
| File read | `java.nio.file.Files.readAllBytes(path)`, `readString(path)` | Read sink; CWE-22 |
| File write | `java.nio.file.Files.write(path, content)`, `writeString(path, content)` | Write sink; CWE-22 |
| Digest selection | `java.security.MessageDigest.getInstance(algorithm)` | Algorithm configuration; CWE-327 |
| URI parsing | `java.net.URI.create(url)` | Parsing fact; CWE-918 |

Captures preserve exact input expressions and source locations. Comments,
ordinary string contents, and unqualified lookalikes do not produce these
boundaries. Files declaring a local `java` binding are conservatively excluded
from JVM API matching, including unrelated scopes. This is structural analysis,
not compiler-backed symbol resolution; project classes can still conflict with
JVM package names.

A matched sink is a review lead, not a vulnerability finding. URI parsing does
not establish destination authorization. Digest selection is inventory for
both strong and weak algorithms and does not establish security-sensitive use.

## Gaps and next steps

- **API identity:** imported short names, import aliases, default JVM imports,
  typed receivers, constructors, overloads with extra arguments, safe calls,
  method references, and extension functions need semantic ownership checks.
- **Value flow:** Kotlin request sources, `val`/`var` bindings, string templates
  (including raw strings), destructuring, Elvis expressions, smart casts,
  scope functions (`let`, `run`, `apply`, `also`, `with`), lambdas, and coroutines
  do not yet have a Kotlin source-to-sink summary. No Kotlin security-path
  coverage is claimed by this profile.
- **Server frameworks:** Spring MVC/WebFlux and Ktor routing, request inputs,
  authentication, authorization, HTML output, redirects, and uploads are absent.
- **Persistence/network:** JDBC query and prepared-statement ownership, Exposed,
  JPA, OkHttp, Ktor clients, serialization, XML, TLS and JWT controls are absent.
- **Android/multiplatform:** intents, WebView, exported components, content
  providers, Android storage, Kotlin/JS and Kotlin/Native APIs are absent.
- **Build/project context:** Gradle source sets, generated Kotlin naming beyond
  the ordinary exclusions, dependency identity, mixed Java/Kotlin cross-file
  propagation, and compiler version compatibility are not modeled.

Prioritize imported API identity and regression pairs first, then Spring/Ktor
sources and bounded local flow. Add fixtures for safe siblings, reassignment,
shadowing, branch joins, interpolation and scope functions before claiming
framework or relationship coverage. The checked-in initial fixtures cover
all five rules, scripts, inert text, package shadowing and repository policy.
