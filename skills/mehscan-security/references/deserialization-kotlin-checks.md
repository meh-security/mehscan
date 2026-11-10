# Kotlin deserialization source-review checks

Use with the [shared checks](deserialization-checks.md). Bind Kotlin target
(JVM, JS or Native), serialization plugin/runtime versions, selected serializer,
format instance, SerializersModule and framework wiring. For Jackson, Gson or
JDK object streams also use the [Java companion](deserialization-java-checks.md)
for the actual JVM path. Reason through cases from source; no target execution
or test harness is required. Partial native Kotlin analysis is not a safe verdict.

1. **Check the actual polymorphic dispatch.** Follow sealed/generated
   serializers, contextual/polymorphic module registrations, discriminator names,
   default providers and custom content-based serializers into the selected
   subtype and construction hook. Compare an unregistered tag with allowed
   subtypes on this format instance. A class-discriminator setting alone does
   not establish arbitrary class loading or cover an alternate JVM decoder.

2. **Check defaults, coercion and validator agreement.** Trace explicitNulls,
   coerceInputValues, ignoreUnknownKeys, alternative names, naming strategies and
   leniency only where configured and supported. Compare absent/null/invalid
   values, duplicate/escaped fields and case variants into the object actually
   used. Generated property types do not replace a business constraint. A bypass
   needs the validator and consumer to make different security decisions on the
   same input, not merely a configuration difference.

3. **Check boundaries and input progress.** Follow decodeFromString, stream or
   sequence APIs and framework body converters to full-input, terminal or
   multi-value framing behavior. Compare one value with a tail and whole versus
   split tokens through the supported implementation. For lazy sequences,
   inspect iteration, stream ownership, cancellation and early failure. Returning
   a sequence or suspending a call does not prove bounded buffering or cleanup.

4. **Check recursive and collection work.** Follow deserialize calls through
   generated descriptors, custom KSerializer implementations, nested format
   instances, ignored values and format-specific reference/alias handling.
   Compare deep versus wide values, repeated updates and independently decoded
   dimensions before allocation. Verify which logical budget is shared across
   nested calls; do not assume the compiler plugin supplies a universal limit.

5. **Check construction and failure effects.** Trace constructors, init blocks,
   property/custom setters, default factories and user serializers to observable
   effects or aliases. Compare fresh objects with custom updates of shared state
   and rejection before versus after a hook. A thrown SerializationException
   does not establish rollback. Inspect whether a wrapper forwards the intended
   serializer/module/options rather than creating a differently configured Json.

6. **Check platform ownership, caches and output.** On JVM follow array slices,
   ByteBuffer position/limit and reused buffers; on Native follow interop owners,
   pins and copied versus borrowed pointers. Use the
   [JavaScript companion](deserialization-javascript-checks.md) for
   a JS decoder or backing view that actually crosses that boundary. Bind cache
   entries to real serializer/type keys, and decoded fields to output or persistent
   effects. Do not infer native memory corruption from a managed exception.

Source navigation: [JSON configuration](https://kotlinlang.org/docs/serialization-json-configuration.html),
[polymorphic serialization](https://kotlinlang.org/docs/serialization-polymorphism.html),
[sequence decoding](https://kotlinlang.org/api/kotlinx.serialization/kotlinx-serialization-json/kotlinx.serialization.json/decode-to-sequence.html).
Inspect the selected platform's source and actual configuration; API availability
and behavior from another target or version are not binding evidence.
