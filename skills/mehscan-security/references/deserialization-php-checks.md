# PHP deserialization source-review checks

Use with the [shared checks](deserialization-checks.md). Bind PHP version,
platform integer width, serializer/session handler, decoder flags, class loader
and application wrappers. The native scanner's PHP coverage is partial; source
review still follows the actual implementation. Reason through comparison cases
from source; these checks require no target execution or harness.

1. **Check object restoration and magic-method effects.** Follow unserialize,
   session decoding and serialization extensions to accepted class names,
   autoloading, __unserialize, __wakeup, Serializable::unserialize and later
   __destruct behavior where applicable. Native unserialize is unsuitable for
   untrusted input; allowed_classes is not a general safety certificate. Bind a
   claimed gadget effect to available classes, arguments and reachable hooks.
   Compare data-only JSON decoding with object restoration; neither a method
   name nor a class-name string establishes the whole execution chain.

2. **Check options and authentication at the boundary.** Trace allowed_classes,
   max_depth and extension-specific restrictions through every wrapper/overload.
   If signed data is treated as trusted, establish the authenticated exact bytes,
   verification before restoration, key authority and replay/purpose conditions.
   Encoding, a plain digest or a later failure is not that proof. Compare rejected
   input with the actual allowed path; retain its deployment assumptions.

3. **Check JSON type, error and numeric interpretation.** Follow associative
   decoding, object/array selection, JSON_BIGINT_AS_STRING, invalid-UTF-8 flags and
   JSON_THROW_ON_ERROR into return values and error handling. Compare valid null
   with a decode failure and inspect the caller's actual error test. Trace
   duplicate/escaped keys, numeric-key conversion and loose versus strict
   comparison into the protected decision; permissive conversion alone is not
   an authorization bypass. Runtime width and configured casts matter.

4. **Check depth, expansion and materialization.** Bind the depth option to the
   chosen decoder and follow later recursive traversal, reference graphs,
   hydration and extension allocations separately. Compare deep/wide data,
   repeated references and distinct values. Inspect actual length/count checks
   before allocation or copying; a depth cap alone does not bound string size,
   graph traversal or total retained input. Resource claims need their effect.

5. **Check publication on failure and reuse.** Follow mutation of existing
   objects, session/global state, reference aliases and magic-method effects
   through exceptions and error returns. Inspect whether cleanup/destructors
   expose additional effects after rejection. Compare fresh data targets with
   shared/prepopulated state. Copy-on-write terminology does not establish
   isolation from explicit references or application hooks.

6. **Check extensions, caches and output.** For native decoders trace PHP string
   length, embedded NUL, integer narrowing, allocation ownership and error cleanup
   into the extension's actual C access. Separate managed warnings/errors from
   native corruption. Bind persistent keys to actual insertion and eviction, then
   decoded values to templates, includes, filesystem operations or other consumers;
   a dangerous sink requires its own input/control/effect chain.

Source navigation: [unserialize restrictions and trust contract](https://www.php.net/manual/en/function.unserialize.php),
[JSON flags and error behavior](https://www.php.net/manual/en/function.json-decode.php),
[object restoration hooks](https://www.php.net/manual/en/language.oop5.magic.php).
Check version-specific dispatch and extension implementation before transferring
defaults or assuming a class restriction closes other resource or state effects.
