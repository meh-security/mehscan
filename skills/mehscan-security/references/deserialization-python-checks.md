# Python deserialization source-review checks

Use with the [shared checks](deserialization-checks.md). Bind Python version,
the imported decoder and implementation, loader/options, hooks and target model.
Distinguish plain data parsing from pickle, marshal, object-building loaders and
application model construction. Comparison cases are source reasoning, not
payloads to run; these checks require no target execution or harness.

1. **Check code-capable formats and actual hooks.** Follow pickle reducers,
   find_class, persistent_load, custom dispatch and object restoration to a
   callable and its authority. For YAML bind the exact Loader, registered
   constructors and tag handling; a helper named safe does not establish those
   bindings. Compare a data-only path with code-capable restoration. Native
   pickle's untrusted-input contract is unsafe; restrictions need their actual
   implementation and cannot be inferred from a wrapper's name. JSON decoding
   without custom hooks is a different mechanism.

2. **Check JSON and model conversion hooks.** Trace object_hook,
   object_pairs_hook, parse_int/parse_float/parse_constant and custom decoders,
   then model validators, coercion and default factories. Compare raw parsed data
   with the validated/transformed object actually consumed. Follow type tags,
   imports, constructors and setters separately. An annotation or a successful
   validation call does not prove the caller uses its returned value.

3. **Check duplicates, numbers and framing.** Bind decoded duplicate names to
   hook/dict behavior, numeric conversion to its effective version and custom
   handler, and raw_decode's end offset to the caller's terminal check. Compare
   trailing roots, large integers, nonfinite values and escaped names through the
   actual consumer. A runtime integer-conversion limit must cover the selected
   hook; do not transfer it to an arbitrary replacement converter.

4. **Check parser work, graphs and quotas.** Follow full read/readall before
   loads, incremental scanners, recursive model construction, YAML aliases and
   binary length/count fields. Compare one versus many chunks, deep versus wide
   data and shared versus duplicated graph traversal. Derive repeated work and
   retained storage from the code; safe tag construction does not establish an
   expansion/depth budget. Require a disproportionate effect or violated budget
   before promoting ordinary large input to a resource finding.

5. **Check borrowed input and native extensions.** Trace memoryview, bytearray,
   mmap, readinto, pooled decompression and C-extension slices to logical length,
   initialization and owner lifetime. Compare owned immutable input with views
   retained across resize, reuse or close. A Python exception is not proof of
   native corruption; follow the C/FFI implementation when that decides safety.

6. **Check failure publication and persistent effects.** Follow __setstate__,
   validators and custom collection updates to partially visible objects, caches,
   files or other effects before a later rejection. Compare fresh objects with
   shared/prepopulated targets and pure-data decoding. Memo/reference tables and
   parser instances need their actual per-call/reset contract. Trace decoded
   values to the relevant interpreter, template or output context separately.

Source navigation: [pickle trust and restoration](https://docs.python.org/3.13/library/pickle.html),
[JSON decoder hooks and contracts](https://docs.python.org/3.13/library/json.html),
[PyYAML loader selection](https://github.com/yaml/pyyaml/blob/main/lib/yaml/__init__.py).
Re-establish the assessed runtime and dependency path; documentation for another
version or a pure-Python implementation does not prove a native extension's body.
