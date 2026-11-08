# JavaScript and TypeScript deserialization source-review checks

Use with the [shared checks](deserialization-checks.md) for JavaScript,
TypeScript and TSX, including Node, browser and worker paths. Bind the actual
decoder/import, runtime, options, reviver or schema transformer and receiving
context. TypeScript types and casts do not validate runtime input. Reason through
the comparison cases from source; no target execution or harness is required.

1. **Check parsing separately from executable activation.** Follow JSON.parse
   revivers, YAML constructors/tags, framework transformers, class factories
   and binary extension decoders to the selected callback and first effect.
   Compare ordinary parsed data with explicitly registered hooks or dynamic
   evaluation. JSON.parse is not eval; accepting a constructor-like string alone
   does not execute it. Bind any type-name-to-constructor mapping before claiming
   arbitrary activation, and carry wrapper restrictions through nested calls.

2. **Check decoded keys at the actual assignment or merge.** Follow __proto__,
   constructor/prototype paths, escaped equivalent names and duplicate keys into
   recursive merge, setters and later property lookup. Ordinary JSON parsing
   does not itself establish prototype pollution. Compare own-data-property
   handling, null-prototype dictionaries or Map with the actual recursive write.
   Show the changed prototype/property reaching a consequential consumer before
   claiming authorization bypass or code execution.

3. **Check numeric and schema interpretation.** Trace JSON number conversion,
   integer precision, custom bigint handling, coercion, defaults and unknown-key
   stripping into the value actually used. Compare raw versus transformed values
   and rejection versus returned schema data; checking a validation result while
   consuming the original object can be a different path. Bind duplicate-name or
   rounded-ID differences to the validator and its protected decision.

4. **Check streaming work and aggregate storage.** Follow text decoding, retained
   chunks, string concatenation, repeated JSON.parse calls, recursive revivers,
   alias expansion and collection insertion. Compare one chunk with split tokens
   and compact aliases with expanded objects. A streaming interface or async
   iterator does not prove progress or a bound before buffering/materialization.
   Distinguish ordinary input-proportional storage from repeated-prefix work,
   expanded graphs or dimensions multiplied into allocations.

5. **Check buffer views and publication.** Bind Buffer/Uint8Array byteOffset and
   byteLength to the decoder's logical input. Passing view.buffer can expose a
   wider backing allocation. Compare copied input with slice/subarray views and
   pooled or allocUnsafe storage. Follow reuse, transfer/detachment and native
   addon/Wasm boundaries to a later read or observer. A managed RangeError alone
   is not memory corruption; a native path needs its own extent/lifetime proof.

6. **Check hooks, failure state and output.** Trace reviver/transformer side
   effects, partially mutated merge targets, shared caches and abort/error paths.
   Check whether cache keys come from bounded schema/type metadata or arbitrary
   incoming names. Follow decoded values through stringify, raw JSON, HTML,
   templates and logs into the interpreting sink. Compare escaped data with raw
   insertion; parsing JSON does not make it safe for every output context.

Source navigation: [ECMAScript JSON parsing](https://tc39.es/ecma262/multipage/structured-data.html#sec-json.parse),
[Node Buffer views and backing storage](https://nodejs.org/api/buffer.html#buffers-and-typedarrays).
Inspect the actual dependency's schema, merge and extension implementations;
do not transfer JSON.parse guarantees to other decoders or downstream writes.
