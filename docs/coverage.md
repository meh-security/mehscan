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

C and C++ copy-count analysis follows selected source-defined constructors and
free helpers into standard memory operations. Typed C++ braced returns can carry
the same relationship across files. A matching lower bound closes subtraction
only; source accessibility, allocation success and other conversions remain
separate questions. Volatile reads do not reuse an earlier value check.

Arbitrary wrappers, overload resolution, implicit member lookup, virtual calls
and cross-function ranges remain limited. A buffer copy in source can therefore
lack a review question even when a related low-level API is recognized elsewhere.

Selected C++ vector lifetime reviews connect an explicitly typed `std::vector`
reference in a loop to persistent keyed storage, mutations and element addresses
passed to outward insertion calls. The review checks whether the callee retains
the pointer, whether it is used later, and whether duplicate-entry or capacity
guards keep it valid. Local vectors that survive a loop also connect
`back()`/`front()` references to
outward insertion calls. Review distinguishes independent owning copies from
retained views and checks the referenced storage's actual move behavior.
These are selected same-file relationships. Inferred container types,
arbitrary aliases, other containers and a complete
control-flow or lifetime model remain outside that recognition.

C++ exceptional-cleanup reviews connect direct `new` insertions into a local
standard raw-pointer vector with an explicit earlier throw in the same loop.
Review checks pending allocations from prior iterations, cleanup and handlers,
and the successful ownership handoff. Arbitrary containers, inferred allocation
helpers and exceptions from ordinary calls remain outside this recognition.

Rust raw-slice analysis follows selected null field initializers from safe
constructors, including a defined raw-record transfer, into a safe accessor of
the same owned type. A rejecting null check closes only the non-null invariant.
Arbitrary trait dispatch, cross-file state changes, macro expansion, alignment,
initialization and general unsafe-code correctness remain outside that proof.

Selected Rust initialized-prefix reviews follow source-defined `Vec<u8>` effects
from a safe buffer constructor through stored-position transfer and length
publication. Capacity, initialized length and the order and extent of writes
are separate questions. The implementation witness does not establish every
trait implementation. Recognition currently requires supported local definitions
in one file; arbitrary wrappers, cross-file dispatch and other containers remain
limited. Unknown external initialization stays a review question.

Rust raw-memory review also connects owned vectors to raw reconstruction,
bitwise copies to pending ownership, and safe raw-pointer/slice APIs to their
memory preconditions. Metadata, allocation layout, initialized representation,
copy ranges and ownership remain separate questions. Supported direct operations
and source-defined copy helpers retain their source and binding evidence.
Arbitrary pointer aliasing, generated code and whole-program soundness remain
outside these bounded relationships.

Rust policy reviews share prepared type, import/re-export, helper and macro
source context. Definitions are not universal trait-dispatch or macro-expansion
proof. Unknown implementations and configuration remain explicit, and optional
context does not change the selected operation's availability.

Rust filesystem review distinguishes returned file contents from path-control
evidence. Value defers operations on proven locally generated temporary paths
to Comprehensive, which retains file-identity and downstream-content questions.
Caller-selected temporary directories and mutable or unresolved paths remain
reviewable. File opens used solely to sync a handle remain in scan evidence
without becoming content-read reviews.

## Choose the source you intend to review

Directory scans honor repository ignore files and built-in dependency/build
exclusions. Ordinary SAST also excludes conventional tests, specs, fixtures,
samples and generated or bundled sources. This includes `sample`, `example`,
`libtest` and `libtests` directories. Names are source-scope conventions, not
evidence that code is safe.

Rust directory scans also follow supported static Cargo targets and source-module
declarations. Established module exclusions apply to evidence and review helper
lookup. Unknown features, targets, generated modules and ambiguous inclusion stay
explicit in review context. Source availability does not establish runtime
reachability or caller authority. Mehscan does not run Cargo, build scripts or
procedural macros to select a convenient configuration.

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
Comprehensive uses conservative eligibility: it retains uncertain security
relationships but can exclude an ordinary read when native source facts establish
its local provenance without an identified consequential relationship. Unresolved
path provenance, observed runtime environment mutation or a connected
security-sensitive effect keeps the question eligible. An exclusion does not
establish content trust or deployment authority. Exclusions are visible scope
decisions, not dismissals; raw scan evidence and Value IDs remain available. The
two queues need not be strict subsets of one another.

Comprehensive reviews every admitted question; it does not add missing language
semantics or reopen excluded source. Findings, dismissals and unresolved checks
are scoped to the exact operation and conditions reviewed. Keep a deciding
missing caller, policy, helper or effect as a follow-up question rather than
assuming either vulnerability or safety.

An optional [second pass](review-worker.md#optional-second-pass) checks selected
first-pass results. It does not extend scanner recognition or certify application
safety. Read its scope and not-checked counts alongside the final findings.
