# .NET deserialization source-review checks

Use with the [shared checks](deserialization-checks.md). Bind the package/runtime,
target type, reader options, generated/reflection metadata, converter and reference
handler. Start with the assessed library's own reader, resolver, formatter and
target types; the System.Text.Json APIs below are examples, not prerequisites.
For System.Text.Json distinguish `JsonSerializer`, `Utf8JsonReader`, `JsonDocument`
and `JsonNode`; inspect the actual path before crediting a guarantee.
Reason through the comparison cases using the implementation and its callers;
these checks require no target execution or test harness.

1. **Check duplicate and extension-data work.** Follow member lookup and the
   selected dictionary/node's insertion or replacement operation. For
   `[JsonExtensionData]`, bind the actual extension-data target. Compare unique
   keys, repeated changed values, case variants and a prepopulated target under
   default and parameterized construction. Inspect `JsonObject.SetItem` and the
   backing collection's index/hash path before alleging linear replacement.
   Trace `AllowDuplicateProperties` to each relevant converter and target on
   the assessed version; an option name does not establish check coverage.

2. **Check streaming progress and retention.** Follow `BytesConsumed`, retained
   prefixes, buffer copies, read-ahead and no-progress fallback. Compare the same
   token through span, segmented sequence, stream and pipe entry points actually
   supported. Inspect `StreamReadBufferState` or its version-specific equivalent;
   pipe consumed/examined positions require their own check. For async enumerable
   use, inspect early disposal/cancellation and who retains yielded values.
   A fallback that fills/grows amortized can refute repeated-prefix work.
   For pooled or exposed arrays, follow the current stream length, slice Count
   and Position into the reader's logical end. Allocated capacity and retained
   bytes from an earlier call must not become the current semantic input.

3. **Check metadata, references and actual activation.** Trace configured
   `$type` selection through the derived-type map and fallback converter.
   `Type.GetType`, a binder and object construction are separate operations.
   With out-of-order metadata enabled, inspect buffering before type selection.
   Bind `$id`/`$ref` tables to one operation, including custom shared resolvers.
   Compare rejected/allowed types, early/late metadata and fresh/reused resolvers.

4. **Check converters, callbacks and population.** Follow generated or reflective
   dispatch into `Read`, factories, constructors, setters and callbacks. Inspect
   nested deserialization for option/depth propagation and reentrant state
   isolation. Compare Replace/Populate, fresh/existing targets, absent/null
   members and late failure. Establish which alias or hook can observe partial
   state; required-member and constructor checks protect their own stages.
   Compare sibling overloads to verify that caller-supplied resolvers, converters
   and restrictions reach the same effective dispatch rather than a default.

5. **Check low-level extents and lifetimes.** Compare escaped/unescaped and
   contiguous/segmented token paths at encoding and numeric boundaries. For
   `Unsafe`, `MemoryMarshal`, pointers and native codecs, prove the authoritative
   logical/initialized extent, conversions and owner lifetime at each access.
   Follow `JsonElement` to its `JsonDocument` or clone and pooled arrays through
   rejection/disposal. A managed bounds/disposal exception alone does not show
   native memory corruption or disclosure.

6. **Check persistent caches and output.** Bind new entries to actual Type,
   schema or converter keys and their owner. Arbitrary field names alone do not
   establish new Type-cache entries. Follow output through this library's
   projection, ignore/include annotations, converter and escaping policy.
   Compare ordinary warm reuse or escaped output with the proposed effect.

Apply the same checks to Newtonsoft.Json, XML/DataContract and binary codecs
using their actual binders, callbacks, state APIs and resource resolvers.
Carry any documented trusted-input restriction into the conclusion.

Source navigation: [System.Text.Json design guarantees](https://github.com/dotnet/runtime/blob/main/src/libraries/System.Text.Json/docs/ThreatModel.md),
[pinned implementation](https://github.com/dotnet/runtime/tree/614e7dafc09bcf359e8ce4f166b28189db14c364/src/libraries/System.Text.Json/src/System/Text/Json),
[converter contract](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/converters-how-to),
[population contract](https://learn.microsoft.com/en-us/dotnet/standard/serialization/system-text-json/populate-properties).
These locate deciding code; re-establish behavior on the assessed revision.
