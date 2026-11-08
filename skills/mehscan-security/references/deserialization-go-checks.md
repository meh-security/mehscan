# Go deserialization source-review checks

Use with the [shared checks](deserialization-checks.md). Bind the toolchain,
import path, build experiments, options and destination type. Establish whether
`encoding/json` uses a legacy implementation or a compatibility wrapper around
v2; the wrapper's option set and the v2 API can produce different semantics.
Reason through the comparison cases using the implementation and its callers;
these checks require no target execution or test harness.

1. **Check decoded-name and numeric interpretation.** Trace duplicate names,
   invalid UTF-8, case matching and custom map-key conversion into the actual
   field/value. Compare escaped names and v1/v2 option sets. Compare `any`/float
   with exact integers, `json.Number` and custom numeric methods at precision
   boundaries. A security bypass needs the validator's value, consumer's value
   and affected decision; a compatibility difference alone is insufficient.

2. **Check merge and failure mutation.** Compare fresh and prepopulated structs,
   maps, slices and non-nil interfaces, including absent/null and repeated
   members. Trace syntax prevalidation separately from binding, semantic errors
   and callback failures. Follow which existing fields or aliases survive a
   late failure. Credit rollback only where the actual implementation provides it.

3. **Check the value boundary and buffered tail.** Follow `Decoder.Decode`,
   `Unmarshal`, `UnmarshalRead` or `UnmarshalDecode` to their terminal checks.
   Compare a second root, garbage tail and a valid single document. For a
   stream API, inspect the caller's permitted-tail policy. Track `Buffered` or
   `UnreadBuffer` lifetime and reader read-ahead. Locate size limits before
   any wrapper materializes a raw value.

4. **Check custom-method consumption and ownership.** Follow `UnmarshalJSON`,
   `UnmarshalJSONFrom`, `encoding.TextUnmarshaler` and registered methods into
   exact consumption, option/depth propagation, fallthrough and mutation before
   failure. Check the documented copy obligation when retaining input. Compare
   nested decoding with a shared logical budget and a fresh decoder that resets
   it; do not assign custom-method behavior to ordinary binding.

5. **Check token-state and aggregate budgets.** Trace the jsontext nesting
   stack, duplicate namespaces, buffer growth and skipped values through errors
   and reuse. Inspect whether policy changes are allowed in an active namespace.
   Compare token/value APIs and fragmented versus contiguous input. Depth
   protection alone does not bound width, long scalars or retained stream items.

6. **Check unsafe and generated fast paths.** Follow borrowed strings/buffers,
   pooled decoders, unsafe conversions, generated code and assembly into logical
   extent, initialization and owner lifetime. Compare escaped/fallback handling
   and reuse after failure. Establish the embedding's panic boundary separately
   from a memory invariant violation.
   Bind slice length, capacity and backing-array ownership separately. Follow
   bytes.Buffer views, reslicing and pool return into any later observer; a
   reused allocation is not current input merely because its bytes are accessible.

Source navigation: [JSON implementation](https://github.com/golang/go/tree/edcdd30e39ef493fa031cd582a5705500b09a762/src/encoding/json),
[v1 compatibility options](https://github.com/golang/go/blob/edcdd30e39ef493fa031cd582a5705500b09a762/src/encoding/json/v2_options.go),
[v2 API contracts](https://pkg.go.dev/encoding/json/v2).
Re-establish the selected build path and defaults on the assessed version.
