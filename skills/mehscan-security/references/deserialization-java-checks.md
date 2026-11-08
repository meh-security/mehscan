# Java deserialization source-review checks

Use with the [shared checks](deserialization-checks.md). Record the selected
factory/mapper, JavaType, modules, constraints and effective options. Distinguish
Jackson 2 `com.fasterxml.jackson`, Jackson 3 `tools.jackson` and JDK object
streams. Transfer checks to Gson, Moshi, XML or YAML through their actual adapters.
Reason through the comparison cases using the implementation and its callers;
these checks require no target execution or test harness.

1. **Check constraint coverage by frontend.** Follow byte arrays, Readers,
   InputStreams, DataInput or async feeders into the checks on nesting,
   number/name/string length, document length and token count. Compare a complete
   single buffer, a final buffer and fragmented input. Bind each limit's units
   and check position to allocation/work; inspect the selected factory's actual
   `StreamReadConstraints`. Character and byte limits cover different quantities.
   When a wrapper exposes a ByteBuffer or pooled backing array, follow position,
   limit and actual read length rather than crediting the array's full capacity.

2. **Check duplicate and framing scope.** Trace `STRICT_DUPLICATE_DETECTION`
   separately from tree-only `FAIL_ON_READING_DUP_TREE_KEY`. Compare tree, bean
   and map targets, decoded duplicate names, custom keys and case matching.
   Follow `FAIL_ON_TRAILING_TOKENS` at the selected reader call; sequence readers
   have a different contract. Verify defaults on the assessed major version.

3. **Check type validation before activation.** Follow class-name, minimal-class,
   named or custom IDs into the resolver and `PolymorphicTypeValidator`.
   Include generic arguments and array components. Inspect class loading,
   initialization and construction separately, including custom class loaders.
   Compare rejected IDs, allowed subtypes and nested selections. A class lookup
   performed without initialization cannot alone establish an initializer effect.

4. **Check deferred binding and partial updates.** Trace creators, external
   type IDs, `TokenBuffer`, unknown-property handlers and setters. Compare
   early/late discriminators and fresh/`readerForUpdating` or merge targets.
   Inspect retained tokens, absent/null values and aliases observing mutations
   before failure. A thrown exception does not establish rollback.

5. **Check canonicalization, caches and recyclers.** Follow name-table collision
   handling, cardinality limits and child-to-root merging. Distinguish symbol
   caches from type/deserializer caches. Check buffer ownership and initialized
   character ranges after rejection or reentry. Compare warm reuse and bounded
   collision handling; disclosure needs returned stale data and an observer.

6. **Check JDK object-stream filters and hooks.** Inspect the effective filter
   factory and stream filter, absent/undecided decisions, depth, references,
   array length and bytes. Follow actual invocation coverage for strings and
   primitives before crediting byte limits. Trace `readObject`, `readExternal`
   and `readResolve` and which constructors execute. Compare early filter
   rejection with an allowed class whose callback/invariants are also inspected.
   Class approval alone does not establish graph or callback safety.

For each selected frontend, compare wrapper overloads and derived mapper/readers
to verify that restrictions actually propagate. A configured factory or filter
not used by the reached operation cannot close that operation's question.

Source navigation: [Jackson streaming](https://github.com/FasterXML/jackson-core/tree/9b1561f7d1eae3c85cce0f39d1b2903e0d510323/src/main/java/tools/jackson/core),
[Jackson binding](https://github.com/FasterXML/jackson-databind/tree/b02acce88765473e3d883c877f1e64e1c1d8910d/src/main/java/tools/jackson/databind),
[JDK object input](https://github.com/openjdk/jdk/blob/c73d7d13aeea1caec275d9df6e429fc979339318/src/java.base/share/classes/java/io/ObjectInputStream.java),
[filter contract](https://docs.oracle.com/en/java/javase/25/core/serialization-filtering1.html).
Use the assessed revision's deciding implementation, not a transferred default.
