# Language coverage and source scope

Mehscan reads source without building or running the application. It combines
syntax, recognized APIs and bounded source relationships to prepare security
questions. Language support does not imply complete framework, compiler or
runtime analysis.

## Languages

| Source | Review surfaces and limits |
| --- | --- |
| C and C++ | Memory extents, arithmetic, allocation, release and selected ownership relationships. Macros, build conditions, custom allocators/deleters and virtual dispatch may need source review. The standard scanner does not resolve a complete compiler type or lifetime model. |
| C# | Recognized data, interpreter, resource and server-operation APIs, with HTTP attributes associated with their owning methods. Dependency injection, effective permission handlers and Razor or generated code can require further source; an attribute is not proof of enforcement. |
| Java | Recognized JVM APIs, database calls, resource access and server operations. Overloads, injected providers, reflection and effective framework policies remain bounded by the available source and API recognition. |
| JavaScript and TypeScript/TSX | Recognized interpreters, database operations, resources, credentials and server actions. Static import/export navigation helps find implementations; it does not prove active dependency injection or runtime dispatch. Vue, JSX/TSX and embedded templates can have partial syntax or output-context coverage. |
| Python | Recognized database APIs, interpreter/resource operations and selected credential effects, including supported async cursors and ORM-backed password writes. Dynamic dispatch, arbitrary context managers and application-specific account APIs may need manual investigation. |
| Go | Recognized SQL/NoSQL, formatted HTML, HTTP and credential relationships, with bounded package/receiver binding. A matching function name or callback argument does not establish an executed operation. Framework wiring and relationships beyond these bindings remain review questions. |
| Rust | Recognized SQL, resource operations, typed HTTP clients, selected ownership/state and credential-renewal relationships. Macro expansion, general trait dispatch, database persistence and cross-object atomicity are not inferred from syntax alone. |
| PHP | A partial profile for recognized native and framework APIs. Arbitrary includes, indirect calls and injected or untyped receivers can prevent a relationship from being recognized. See [PHP coverage](php-coverage.md). |
| Kotlin | A partial JVM profile for recognized typed APIs. Compiler overload/extension resolution, inferred factories, ORM models and reactive execution remain limited. See [Kotlin coverage](kotlin-coverage.md). |

The [database coverage guide](extended-database-coverage.md) lists supported
receiver and query shapes in more detail. Optional compiler backends are separate
from standard scanning and do not make unsupported relationships complete.

C++ buffer wrappers can hide memory effects behind constructors, braced returns
or standard algorithms. The scanner does not generally summarize those effects
across arbitrary types and callers. A buffer copy in source can therefore lack a
review question even when a related low-level API is recognized elsewhere.

## Choose the source you intend to review

Directory scans honor repository ignore files and built-in dependency/build
exclusions. Ordinary SAST also excludes conventional tests, specs, fixtures,
samples and generated or bundled sources. This includes `libtest` and `libtests`
directories. Names are source-scope conventions, not evidence that code is safe.

Use `mehscan scan ROOT --include-tests` to include supported nonproduction source
in SAST when that is the intended scope. Built-in dependency/build exclusions
remain in force. Choose a maintained source directory deliberately when a larger
repository also contains copied SDKs, tutorials or generated distributions;
results then describe that directory, not the entire product.

## Read coverage alongside the findings

Scan JSON, candidate output and review manifests retain coverage and scope.
Unsupported, ignored and parse-failed counts identify limits to inspect. A
parse-failed file can contain recoverable source: evidence outside invalid syntax
may still be retained. Neither the diagnostic nor a surviving candidate proves
that the rest of that file was understood.

No candidates can mean that represented relationships are protected, that no
applicable operation was found, or that relevant source was outside recognition
or scope. It is not an AI review or a clean bill of health. Similarly, a missing
question cannot become a model dismissal.

Value review prioritizes the admitted questions and preserves explicit deferrals.
Comprehensive includes every admitted question; it does not add missing language
semantics or reopen excluded source. Findings, dismissals and unresolved checks
are scoped to the exact operation and conditions reviewed. Keep a deciding
missing caller, policy, helper or effect as a follow-up question rather than
assuming either vulnerability or safety.
