# C and C++ deserialization source-review checks

Use with the [shared checks](deserialization-checks.md) and
[native memory](buckets/native-memory.md). Bind the decoder version, C/C++ ABI,
integer types, compile-time options, allocator, input owner and entry point.
Distinguish DOM, SAX/event, incremental and in-place APIs. Reason through cases
from source and callers; these checks require no target execution or harness.

1. **Check logical extents before arithmetic and access.** Trace read results,
   slices and decoded lengths into pointer arithmetic, allocation and copy/index
   counts. Establish cursor and remaining bytes before subtraction or narrowing;
   check products in their actual operand type. Compare truncated fields, exact
   boundaries and independently decoded dimensions. SIMD padding, a terminator
   and allocated capacity do not establish valid semantic input. Follow a later
   consumer that can interpret retained bytes beyond the current logical end.

2. **Check ownership through in-place parsing and growth.** Follow RapidJSON
   ParseInsitu, simdjson document/string views, StringRef, spans and string_view
   to the input buffer, parser and allocator they borrow. Inspect reuse, move,
   destruction and asynchronous retention. Compare an owned copy with a returned
   borrowed field. After realloc or container growth, follow every pointer/view
   actually used; updating one owner does not refresh aliases. A retained pointer
   needs a later use before alleging a lifetime defect.

3. **Check work across parsing and materialization.** Trace declared counts,
   token tables, duplicate lookup, hash/equality and custom from_json/adapters.
   Compare repeated changed names, long common prefixes, unique names and ragged
   versus rectangular arrays. Separate input scanning from indexed replacement
   and deferred DOM construction. Count revisited ranges or multiplied storage;
   ordinary proportional parsing without a violated budget is not enough.

4. **Check incremental progress and depth at each stage.** Follow saved offsets,
   retained prefixes and copies on incomplete input, EOF and error. Compare whole
   and split tokens by reasoning through the same bytes. Bind iterative parsing
   flags to the actual selected entry point; do not transfer them to recursive
   converters, ignored-value paths, validation, serialization or destruction.
   Locate the shared pre-descent charge or explicit bounded stack where relevant.

5. **Check callbacks, external resources and partial failure.** Trace registered
   SAX handlers, custom converters, XML entity/resource loaders and YAML tags to
   their actual effects and activation options. Compare rejection before the
   callback with failure afterward. Follow cleanup of partially built nodes and
   caller-visible aliases across error codes, exceptions and allocation failure.
   A parse error does not undo an earlier write or published partial object.

6. **Check interpretation and terminal validation.** Compare explicit-length and
   NUL-terminated APIs, escaped/raw names, duplicate handling, number overflow,
   transcoding and trailing-root policies. For lazy/on-demand APIs, follow the
   actual field accesses and final error checks before crediting full validation.
   An interpretation bypass needs the validator and consuming decision; memory
   corruption needs the actual invalid extent or lifetime, not merely bad JSON.

Source navigation: [RapidJSON DOM and in-place parsing](https://rapidjson.org/md_doc_dom.html),
[RapidJSON parsing controls](https://rapidjson.org/md_doc_sax.html),
[simdjson ownership and input contracts](https://github.com/simdjson/simdjson/blob/master/doc/dom.md).
Use these to locate the assessed version's deciding implementation. A named
library or documented example does not prove the caller meets its preconditions.
