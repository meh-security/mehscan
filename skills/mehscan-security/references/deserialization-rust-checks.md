# Rust deserialization source-review checks

Use with the [shared checks](deserialization-checks.md) and
[Rust boundaries](rust-boundaries.md). Bind the format decoder, Serde/derive
versions, Cargo features, target type, visitors and input ownership. The format
implementation and destination visitor jointly determine work and allocation.
Reason through the comparison cases using the implementation and its callers;
these checks require no target execution or test harness.

1. **Check speculative binding work.** For untagged enums, follow buffered
   `Content` replay through candidate variants and nested failed attempts.
   Count the recurrence when distinguishing fields are checked after a nested
   value. Compare overlapping recursive alternatives with a tagged schema or
   early discriminator. A fixed set of nonrecursive alternatives may be only
   a bounded multiplier. Inspect custom `deserialize_with` effects that replay.

2. **Check recursion at each stage.** Follow the decoder budget through
   visitors, seeds, nested parsers and enabled `unbounded_depth` behavior.
   Inspect skipped values separately: iterative skipping can accept deep input
   without recursive stack growth. Follow later Debug/Display/Serialize/Drop
   only where implicated. Compare materialized and ignored content, then a
   shared-budget or iterative control. Name any promised input-depth contract
   separately from protection of the parser's own stack.

3. **Check allocation hints and aggregate growth.** Bind `SeqAccess`/`MapAccess`
   `size_hint` to the selected visitor's cautious capacity logic, element size
   and actual reserve. Compare an overstated hint with little payload and a
   normal bounded collection. An initial allocation cap does not constrain
   eventual size, child allocations or many simultaneously live containers.
   Inspect custom visitors and binary formats independently.

4. **Check borrowed and unsafe representations.** Distinguish transient,
   borrowed and owned `visit_str`/`visit_bytes` variants and reader-backed owned
   output. At RawValue/layout casts, raw slices, pointer writes and `set_len`,
   prove validity, capacity, initialized prefix and owner lifetime for each
   encoded branch. Compare escaped/unescaped strings and safe copied output.
   Use `rust-memory` for the actual unsafe invariant; safe-call soundness does
   not require an invented remote deployment.
   Track aliases across reserve/reallocation and read-filled buffers separately
   from capacity. A replaced Vec or owner does not refresh a previously captured
   pointer, and spare initialized storage need not belong to this decoded value.

5. **Check target and feature semantics.** Compare duplicate fields in derived
   structs, maps and `Value`, including aliases, flattening, defaults and custom
   key conversion. Follow numeric range/precision and enabled
   `arbitrary_precision`, `raw_value`, `preserve_order` or custom hashers.
   Verify the actual value used by the consumer; one target's rejection does
   not establish another target's policy.

6. **Check framing and resumability.** Follow whole-document helpers to terminal
   checks; direct `Deserialize::deserialize` may require the caller's
   `Deserializer::end`. Stream iterators intentionally read sequences. Compare
   a second root, incomplete token and valid document through the actual slice
   or reader implementation. Inspect byte offsets, tail preservation and error
   reuse. Keep a bounded error, unwinding panic and process abort distinct.

Source navigation: [serde_json decoder/read paths](https://github.com/serde-rs/json/tree/8c535a260ce561eaab4111aafc29038eb9f77ff3/src),
[untagged derive](https://github.com/serde-rs/serde/blob/0db9b3b504bcb0a7fa9cf001429869519afd3e9a/serde_derive/src/de/enum_untagged.rs),
[collection visitors](https://github.com/serde-rs/serde/blob/0db9b3b504bcb0a7fa9cf001429869519afd3e9a/serde_core/src/de/impls.rs),
[borrowing contract](https://serde.rs/lifetimes.html).
Use the current assignment's types/features to establish applicability.
