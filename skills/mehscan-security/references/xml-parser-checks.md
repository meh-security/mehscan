# XML parser source-review checks

Use for XML library implementation, custom readers/binders/resolvers and custom
schema, XInclude or XSLT processing, including source assignments with zero
candidates. Ordinary library usage starts with native questions and the basic
[parser/resource checks](categories/parser-resource.md); use this deeper guide
when implementation code or a concrete unresolved internal relationship needs it.
Apply the [shared decoder checks](deserialization-checks.md) to the relevant
bounds, ownership and work relationships. Reason through comparison cases from
source; do not execute the reviewed parser, payloads, tests or benchmarks.

## Select the actual processor

Bind the imported implementation, dependency/runtime version, build features,
entry overload, effective options and custom hooks. A filename or caller language
does not identify the XML engine. Distinguish a supplied URI from supplied bytes:
opening the primary document can perform I/O before entity policy applies.
Record who controls document bytes, base URI, schemas, stylesheets, catalogs and
resolver registration. A namespace URI is a name, not evidence of retrieval.

Load only the relevant section of [XML platform checks](xml-platform-checks.md):

| Implementation reached | Section / worker guidance name |
| --- | --- |
| C/C++, libxml2 or Expat bindings | Native / `xml-native` |
| C# / .NET System.Xml | .NET / `xml-dotnet` |
| Java or Kotlin on JVM using JAXP/StAX | JVM / `xml-jvm` |
| Python stdlib or lxml | Python / `xml-python` |
| JavaScript, TypeScript, TSX, browser or Node | JavaScript / `xml-javascript` |
| Go encoding/xml or another Go XML library | Go / `xml-go` |
| Rust XML crates | Rust / `xml-rust` |
| PHP XML extensions | PHP / `xml-php` |

For Kotlin/JS or Kotlin/Native select the implementation it actually calls.
A wrapper may need its own section and one native section for a deciding edge.
These checks guide source review; they do not add native detector coverage.

## Checks and deciding controls

1. **Separate each resource-loading stage.** Trace the primary input open,
   external DTD subset, parameter entities and general entities independently.
   Continue through explicit XInclude, schema include/import/redefine and
   stylesheet include/import, transformation-time `document()` and extensions
   when present. A reader's DTD rejection closes that parse path; carry that
   result only to processors that actually use it. A safe initial parse does
   not determine the policy of a later validator or transformer.
   For a decorated reader, put inner parsing and outer event filtering on that
   timeline; rejecting a returned event does not prevent inner work already done.

2. **Follow resolution to the operation that opens or supplies content.** Inspect
   base-URI resolution, catalogs, callback return values and fallback behavior.
   Distinguish returning trusted bytes, returning a new URI, returning an empty
   resource, returning null and raising an error using that API's contract.
   A network restriction need not deny local files or custom loaders. For an
   allowlist, check the resource eventually opened, redirects and any nested
   loads. Compare an allowed fixed resource with an attacker-selected resource
   and rejection before opening. SSRF needs a reachable request; disclosure also
   needs sensitive content reaching an observer. A loader flag alone proves
   neither. Load file/network guidance for the consequential operation.

3. **Charge expansion across one logical operation.** Follow internal entities,
   external replacements, character references, attributes/defaults and repeated
   declarations through the actual expansion and materialization paths. Identify
   what each counter measures, its units, threshold, disabled value and overflow
   behavior. Check child parsers, new DTDs, recursive resolver calls and retries
   for resets or uncharged work. Compare nested entities, repeated wide references
   and a rejected reference. Derive the recurrence or violated budget: ordinary
   linear character decoding is not automatically disproportionate expansion.
   Follow loaders that fetch or buffer content before returning a reader/stream;
   a parser quota may not constrain those earlier effects. Compressed input and
   later serialization have separate budgets.

4. **Inspect work before event delivery.** Trace accumulation of a single long
   token, attributes, namespace declarations, interned names and open-element
   stacks before the caller can inspect an event. Check split-token reparsing,
   retained prefixes and callback-driven flushes. Compare one chunk with many
   chunks, wide start tags with deep trees, and namespace-aware with plain readers.
   Locate a bound before growth or repeated scanning. Streaming, an iterative
   reader and a post-event application check do not by themselves bound this
   internal work. Separate memory proportional to input from amplification or a
   concrete enforced-budget failure.
   Where active, inspect validation and XSLT/XPath evaluation work independently;
   an entity-expansion limit does not bound arbitrary schema/transform computation.

5. **Bind validation to the consumed node and representation.** Compare expanded
   names `(namespace URI, local name)`, prefix rebinding, default namespaces on
   elements versus unprefixed attributes, duplicate attributes and sibling order.
   Follow whitespace, CDATA, comments, character/entity decoding, schema defaults,
   numeric coercion and XML-to-object key conversion where consequential. Compare
   the validator's selection with the actual consumer. For a signature claim,
   identify the verified reference, ID uniqueness/registration, transforms and
   exact node later used. A local-name match, permissive syntax or accepted
   duplicate alone does not prove an authorization/signature bypass. A validator
   that verifies the exact consumed node can close the selected substitution.

6. **Follow finalization, failure and reuse.** Check document versus fragment
   mode, full input consumption, trailing roots and suppressed/recoverable errors.
   Events can trigger writes before a later parse error or validation failure.
   Trace partial publication, borrowed token lifetime, cancellation, callback
   reentry, parser pooling and restoration of resolver/error-handler state.
   Compare fresh use, failure then reuse, and an early rejecting path. Confirm
   which options and handlers survive reset or are copied to child processors;
   a secure factory unused by the actual overload is not a deciding control.

## Record the bounded result

For each applicable relationship record the input or caller sequence, exact
processor/stage, earliest effective guard, source evidence and narrow effect.
Keep refutations and named missing helpers/configuration with the coverage record.
Distinguish library invariants from application exposure. No candidate, loaded
guide or closed XXE path certifies the other XML stages or the entire library.
Use ordinary source proposals and finalization when a new supported mechanism
warrants a finding; guidance is not application evidence.

Contract references: [XML namespaces](https://www.w3.org/TR/xml-names/),
[JAXP resource stages and security properties](https://docs.oracle.com/en/java/javase/25/security/java-api-xml-processing-jaxp-security-guide.html),
[XML Signature best practices](https://www.w3.org/TR/xmldsig-bestpractices/).
Use the assessed implementation's version for deciding semantics.
