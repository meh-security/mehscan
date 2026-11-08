# Deserialization source-review checks

Use for library implementation code and custom serializers, converters, parsers,
decoders or input-processing hooks for JSON, XML, YAML, ASN.1, binary objects and
similar formats, including source assignments with zero native questions.
Ordinary library usage starts with Mehscan's native questions and the basic
[parser/resource checks](categories/parser-resource.md); load deeper checks when
a concrete unresolved implementation relationship needs them. Select checks for
the actual operation. Follow the relevant producer, guard and consumer; a checklist
match is a hypothesis requiring fresh source evidence.

Apply these checks and their language companions by reading source and reasoning
about the call chain, branches, state changes and bounds. Comparison cases below
are inputs to reason through, not payloads to execute. Derive work and allocation
growth from loops, recurrences and storage operations. Do not build or execute
the reviewed project, run tests, benchmarks or fuzzers for these checks.

## Select the implementation and boundary

Record the public API, version, input contract, target type, enabled features,
options and extension hooks. Establish whether external or only trusted data
is supported. Identify control over bytes, chunks, schemas, type IDs, references
or a valid public API call sequence. Trace input through parser state and
materialization to the first consequential consumer or cleanup.

For implementation-specific checks, load only the relevant companion:

For XML, use [XML checks](xml-parser-checks.md) and their matching platform
section in place of a general language companion's JSON-specific examples.
For example, a System.Xml reader implementation needs `xml-parsers` and
`xml-dotnet`; load `deserialization-dotnet` additionally only when its binding,
converter or ownership checks address an actual remaining relationship.

| Source/runtime | Companion | Worker guidance name |
| --- | --- | --- |
| C and C++ | [Native decoders](deserialization-native-checks.md) | `deserialization-native` |
| C# / .NET | [.NET decoders](deserialization-dotnet-checks.md) | `deserialization-dotnet` |
| Java / JVM libraries | [Java decoders](deserialization-java-checks.md) | `deserialization-java` |
| JavaScript, TypeScript and TSX | [JavaScript decoders](deserialization-javascript-checks.md) | `deserialization-javascript` |
| Python | [Python decoders](deserialization-python-checks.md) | `deserialization-python` |
| Go | [Go decoders](deserialization-go-checks.md) | `deserialization-go` |
| Rust | [Rust decoders](deserialization-rust-checks.md) | `deserialization-rust` |
| PHP | [PHP decoders](deserialization-php-checks.md) | `deserialization-php` |
| Kotlin | [Kotlin decoders](deserialization-kotlin-checks.md) | `deserialization-kotlin` |

Select by the implementation actually reached, not just the caller's extension.
A Kotlin caller using Jackson needs its JVM path; a managed wrapper reaching a
native decoder needs that ownership/bounds relationship. Start with one matching
companion and load another only when a consequential cross-language edge needs it.
These guides extend source reasoning; they do not expand native detector coverage
or imply that every framework or format is supported.

## Checks and deciding controls

1. **Length or count reaches an allocation or access.** Bind the decoded value
   to its exact reservation, resize, copy or index. Check signedness, narrowing,
   checked arithmetic and byte/element/code-unit conversions before the effect.
   Establish `0 <= cursor <= logicalLength <= capacity`, then validate the extent
   against `logicalLength - cursor`. Accessible SIMD padding and initialized
   semantic input are separate bounds. Compare a short payload with an overstated
   header, an exact-boundary value and a valid small value. A remaining-input
   guard can exclude a missing-payload allocation without imposing a total quota.
   After growth or replacement, follow the buffer actually used by the consumer;
   resizing a field does not update a previously captured array or pointer.

2. **Repeated updates revisit a growing collection.** Follow decoded keys,
   conversion and hash/equality into duplicate detection, replacement or merging.
   Include ordered collections, non-string keys, long common prefixes and size
   thresholds. Count entries or bytes revisited across the whole call chain.
   Compare unique names with repeated changed values near the end of a wide
   object. Indexed replacement or an effective pre-insertion bound can close
   that claim; an equality shortcut may hide it for unchanged values.

3. **Partial input repeats work without progress.** Trace cursor rollback,
   retained prefixes, reparsing and buffer copies for split tokens, escapes and
   length prefixes. For success, incomplete input, EOF and fatal error, identify
   consumed bytes, saved progress or bounded fallback. Compare identical bytes
   in one chunk and many chunks. A saved cursor or amortized growth can bound
   work; an `await` or cancellation parameter alone does not.

4. **Compact input amplifies work or retained storage.** Follow declared sizes,
   number/OID conversion, decompression, aliases, speculative alternatives and
   late metadata to the first expensive operation. Include temporary buffers,
   codec workspace, queued values and cache entries across calls. Compare equal
   byte sizes with different structure; count attempts/allocations as size grows.
   Locate the limit on the quantity actually consumed, before that effect.
   Ordinary storage proportional to accepted input needs a concrete violated
   budget or other disproportionate consequence to support a resource finding.
   Include dimensions inferred from separate nested collections: linear input
   can produce a much larger rectangular allocation before ragged shapes fail.

5. **A recursive edge escapes the relevant budget.** Follow ordinary binding,
   skipped values, converters, nested parsers and graph references, then any
   validation, equality, output or destruction implicated by the claim. Check
   whether nested operations reset one logical budget. Compare deep versus wide
   values and repeated references versus distinct nodes. Shared charging,
   bounded iteration or visited-node tracking can close the selected traversal;
   a parser depth cap does not automatically cover later stages.

6. **Equivalent paths admit different tokens or values.** Compare contiguous
   versus segmented, fast versus fallback and read versus skip paths at truncated
   encodings, escapes, NUL, surrogate, numeric-range and delimiter boundaries.
   Follow the decoded name/value into lookup or typed conversion. Compare
   duplicate/escaped names, case variants, rounding and trailing roots through
   the validator and actual consumer. A bypass needs both interpretations and
   the affected security decision; permissive syntax alone is insufficient.

7. **Input selects a type, hook or external resource.** Trace tag/discriminator,
   class/binder lookup, constructors, setters, callbacks, converters and entity
   or schema resolvers to the first effect. Check allowlisting before activation,
   including nested type arguments. Compare a rejected selection and an allowed
   pure-data target. Name the actual hook and authority; type lookup alone does
   not prove arbitrary construction or code execution.

8. **Failure leaves observable partial state.** Trace object publication and
   aliases during population, omitted/null/default members, reordered dependent
   fields and late validation. Check cursor, depth, staged members and budget
   charges together on rollback. Compare a fresh target with a prepopulated
   target and an early rejecting control. An exception need not undo mutation;
   a defect claim needs the violated contract or consequential observer.

9. **Reuse, reentry or cancellation crosses an ownership boundary.** Follow
   pooled buffers, parser/resolver state, borrowed views and thread-local caches
   through every exit and nested call. Identify the owner and reset/disposal
   point. Compare fresh use, reuse after failure and a nested call with the
   documented isolation mechanism. For disclosure, demonstrate an initialized
   stale range reaching an observer. For memory safety, establish the violated
   extent, validity or lifetime invariant in the actual unsafe/FFI path.

10. **Decoded data reaches output or persistent metadata.** Bind attacker control
    to new cache keys and their owner/eviction policy before alleging cache
    growth. Follow reserialization, raw writer calls, projection, errors and
    logs to the receiving context. Compare bounded/reused keys or the intended
    escaped projection. Disclosure needs sensitive data and an observer;
    injection needs an interpreting sink. Load the relevant output guide.

## Assess and report

State the controlled dimension or valid caller sequence, exact operation,
failed invariant, earliest effective guard, activation conditions and narrow
effect. Distinguish library contract failure from exposure in a deployed caller.
Carry the trusted-input contract, optional features and extension obligations.
For XML use [XML parser checks](xml-parser-checks.md), available as `xml-parsers`,
for stage-specific loading, namespace interpretation and XML work controls.
For YAML/reference formats inspect expansion and resolver activation; for
C/C++ or FFI load [native memory](buckets/native-memory.md).

Support the conclusion with the inspected producer, deciding control and effect.
Distinguish managed exceptions, process failure and memory corruption through
their actual source paths. A source-established mechanism can support a review
verdict without runtime reproduction; an unavailable deciding helper or contract
remains an explicit evidence gap.

Use the existing proposal/finalization workflow. Keep a named missing helper,
guard or configuration explicit. Close only the inspected relationship; an
empty proposal list does not certify the decoder.

For the selected scope, record which applicable checks were assessed, their
deciding source or missing fact, and what remains unexamined or inapplicable.
Guide loading and a category count are not completed review. Keep refuted
mechanisms as supporting coverage rather than creating extra jobs to increase
counts. A library invariant can establish a defect without an application exploit;
a claimed authorization or interpretation bypass needs the actual consumer and
security decision. Separate that missing context from a missing local helper.
