# XML platform checks

Apply the [XML parser checks](xml-parser-checks.md), then read the implementation
section below. Workers request only the named section through its catalog entry.
The API names are navigation hints; establish the assessed version and call path.

## Native: libxml2 and Expat

<!-- runtime:native -->
For libxml2, reconstruct the effective option mask and resource loader on the
actual context. `XML_PARSE_NOENT` enables substitution; it does not prohibit
entities. `DTDLOAD`, `DTDATTR` and `DTDVALID` can activate additional loading.
`XML_PARSE_NO_XXE`, available since 2.13.0, denies external DTD/entity loading;
do not extend that guarantee to primary input opening or every later processor.
`XML_PARSE_NONET` is narrower: built-in network support changed across versions,
and custom loaders must enforce their own policy. Check catalogs and local paths.

Inspect `XML_PARSE_HUGE` and caller-adjusted amplification/resource limits before
crediting defaults. Follow explicit XInclude, schema and libxslt operations under
their own contexts and permissions. A SAX interface can still allocate state
before callbacks. Inspect context reuse, error returns and changed global loaders.

For Expat, an external entity is handled through the registered application
callback; do not invent automatic network/file access when no loader is installed.
Follow child parser creation and inherited handlers to its I/O. Reparse deferral
in supported versions avoids retrying large incomplete tokens on every chunk;
inspect disabling calls and buffer-pressure/final-input paths before deriving a
work bound. Reset changes handlers; verify reinstallation and shared charging.
For callback slices, parent/child lifetimes and native/FFI buffers, load native
memory guidance and prove the particular invalid extent or lifetime.

Sources: [libxml2 options](https://gnome.pages.gitlab.gnome.org/libxml2/html/parser_8h.html),
[Expat API](https://libexpat.github.io/doc/api/latest/).
<!-- /runtime:native -->

## .NET: System.Xml

<!-- runtime:dotnet -->
Distinguish `XmlReader.Create`, legacy readers, `XmlDocument.Load`, `XDocument`,
`XPathDocument` and `XmlSerializer` overloads. Record framework/runtime version,
the exact reader supplied and whether the overload instead opens input itself.
Inspect effective `DtdProcessing` and `XmlResolver` together; a null resolver can
close external resolution while internal entity processing remains a separate
work question. Preserve `MaxCharactersFromEntities` and `MaxCharactersInDocument`
units and zero semantics. A recursive object binder has its own depth budget.
Keep the entity resolver separate from the resolver opening a primary input URI;
explicitly null entity resolution does not prohibit opening that primary input.

For `XmlReader.Create(existingReader, settings)`, distinguish event filtering from
reconfiguring the inner parser. Trace `inner.Read`/`ReadAsync` before the outer
DTD/error check; a rejected `DocumentType` event can follow inner DTD parsing and
resolver I/O. Verify which resolver and quotas remain owned by the inner reader.
Compare constructing directly over bytes/stream with decorating an existing reader.

Trace resolver acquisition through response buffering as well as URI opening.
`XmlUrlResolver` can reach a downloader that copies the response into a
`MemoryStream` before the XML character quota is charged. A decoded-character
limit is not a bound on earlier response bytes, memory, requests or elapsed time.
Inspect the assessed implementation and any bounded loader; do not infer that an
async signature makes copying cancellable or bounded. A resource finding still
needs the enabled resolver, controlled response and applicable caller contract.
For HTTP acquisition, trace timeout/cancellation through response-body consumption:
returning a stream after headers can end the request timer before a later copy.
Check redirect handling at the actual HTTP transport, beyond initial URI checks.

Establish default limits in the assessed constructor/initializer and inspect all
counter writes. Separate a new-document reset from encoding re-decode adjustments
and nested entity state. Current API prose or an option name can disagree with
the pinned implementation; retain that distinction instead of choosing a default
by recollection.
Follow default-resolver switches to their consumers and fallback-value helper;
explicit resolver instances can take a different path from default selection.
On Windows, follow file URIs through `Uri.LocalPath` to distinguish local and UNC
resources. A file-scheme restriction can still permit network-share access;
bind any further authentication or disclosure claim to the actual OS policy.

For validation, trace `ValidationType`, `ValidationFlags` (including inline/schema
locations), `Schemas` and the `XmlSchemaSet.XmlResolver` used for imports/includes.
Settings on an unrelated reader do not constrain schema compilation. Identify
which event handler suppresses an error and whether a failed validation result is
still consumed.

For `XslCompiledTransform`, separate the resolver used by `Load` for include/import
from the resolver used during `Transform` for `document()`. Inspect
`XsltSettings.EnableDocumentFunction`, extension objects and stylesheet control.
Do not infer script execution from `EnableScript` on runtimes that do not support
it: stylesheet scripts are a .NET Framework capability, not .NET Core/5+ support.
Compare a fixed stylesheet/denying resolver with the actual enabled path. Carry
reader settings through wrappers, async siblings and reused instances.

Sources: [reader settings](https://learn.microsoft.com/en-us/dotnet/api/system.xml.xmlreadersettings),
[settings implementation](https://github.com/dotnet/runtime/blob/60629d14374c56f1cb51819049ad1fa529307f8d/src/libraries/System.Private.Xml/src/System/Xml/Core/XmlReaderSettings.cs),
[resource buffering implementation](https://github.com/dotnet/runtime/blob/60629d14374c56f1cb51819049ad1fa529307f8d/src/libraries/System.Private.Xml/src/System/Xml/XmlDownloadManager.cs),
[file URI conversion](https://learn.microsoft.com/en-us/dotnet/api/system.uri.localpath),
[schema set](https://learn.microsoft.com/en-us/dotnet/api/system.xml.schema.xmlschemaset),
[XSLT security](https://learn.microsoft.com/en-us/dotnet/standard/data/xml/xslt-security-considerations).
<!-- /runtime:dotnet -->

## JVM: Java and Kotlin

<!-- runtime:jvm -->
Resolve the actual JAXP provider and JDK version, including service-provider
selection. Distinguish DOM/SAX factories, StAX `XMLInputFactory`, `SchemaFactory`,
validators, `TransformerFactory`, JAXB and framework wrappers. Kotlin callers on
JVM inherit the reached Java processor's contract; multiplatform callers need
their actual implementation instead.

Check DTD/general/parameter-entity features and `ACCESS_EXTERNAL_DTD`,
`ACCESS_EXTERNAL_SCHEMA`, `ACCESS_EXTERNAL_STYLESHEET` at the relevant stage.
Default secure processing and explicitly setting `FEATURE_SECURE_PROCESSING`
can differ; do not treat a flag name as proof of the complete policy. StAX has
its own properties. Inspect rejected/unsupported property setters, catch blocks,
property precedence and whether the configured factory actually creates the
reader in use.

Follow `EntityResolver`, StAX `XMLResolver`, `LSResourceResolver`, `URIResolver`
and catalogs into returned streams/sources. JDK external-access properties do not
govern a non-null source supplied by the resolver; inspect that callback's own
I/O. Null can mean fallback in these APIs, not universal denial. Separate explicit
schema construction, XInclude configuration, transformation and extension calls.
Check effective `jdk.xml.*` limits and their disabled values on the active
processor. A documented JDK property does not automatically bind another provider.

Sources: [JAXP security and precedence](https://docs.oracle.com/en/java/javase/25/security/java-api-xml-processing-jaxp-security-guide.html),
[StAX factory properties](https://docs.oracle.com/en/java/javase/25/docs/api/java.xml/javax/xml/stream/XMLInputFactory.html).
<!-- /runtime:jvm -->

## Python

<!-- runtime:python -->
Identify `ElementTree`, SAX/pulldom/minidom, direct `pyexpat`, `defusedxml` or lxml;
they do not share one security contract. Bind the loaded Expat/libxml2 version,
including system-library builds. Expat itself does not fetch resources; inspect
SAX entity features, `EntityResolver` and direct external-entity handlers in the
wrapper. Built-in character references do not establish executable object loading.

For Expat-backed feeds inspect reparse deferral, `flush()` or explicit deferral
changes and the actual child-parser budget. Distinguish compressed transport from
XML entity expansion. For ElementTree XInclude, follow `ElementInclude.include`,
its loader, base URL and depth independently of the original parse.

For lxml, bind the passed parser and effective `resolve_entities`, `load_dtd`,
`attribute_defaults`, `dtd_validation`, `no_network`, `huge_tree` and recovery
settings. Defaults changed between releases. `no_network` does not establish a
local-file ban; inspect registered resolvers/catalogs and fallback. Documents
retain parser context for later resolution. Follow `xinclude()`, validation and
stylesheet compilation/application as separate operations. `XSLTAccessControl`
restricts selected transformation I/O; it does not bound CPU or automatically
settle stylesheet parsing/imports. Inspect Python extension functions themselves.
For `iterparse`, check retained nodes/ancestors and callback work before claiming
that consuming events bounds memory.

Sources: [stdlib XML security](https://docs.python.org/3/library/xml.html#xml-security),
[Expat controls](https://docs.python.org/3/library/pyexpat.html),
[ElementTree inclusion](https://docs.python.org/3/library/xml.etree.elementtree.html#xinclude-support),
[lxml resolvers](https://lxml.de/resolvers.html), [lxml parsing](https://lxml.de/parsing.html).
<!-- /runtime:python -->

## JavaScript, TypeScript and TSX

<!-- runtime:javascript -->
Resolve browser `DOMParser`, a JS package or a native libxml2 binding; names and
TypeScript declarations do not establish runtime behavior. For browser parsing
bind the MIME type, XML error-document handling and later node adoption/output.
Disabled scripting while parsing does not establish safety of a later interpreting
sink. Do not transfer browser behavior to a Node implementation or vice versa.

For packages such as fast-xml-parser, xml2js, sax/saxes or libxmljs, follow the
actual version's DTD/entity implementation and configured callbacks. Entity
replacement support alone does not prove filesystem/network fetching. If a native
binding is reached, load `xml-native` for the decisive options/loader edge.

Inspect entity limits in the code that performs replacement, including alternative
numeric/built-in paths and per-document reset. Compare a second DTD in the same
document with reset for a genuinely new document; a callback that re-registers
entities can reset another library's counters. Read that dependency when its
behavior decides the claim. Bound event-loop work from loops/recurrences rather
than assuming `async` parsing provides preemption.

Follow XML-to-object name processing, prefix removal, attributes merged into
properties, repeated siblings and value processors into validation and consumers.
For prototype pollution, establish the actual dangerous property write and
consequential use; an element named `__proto__` alone is insufficient. For coercion
or namespace bypasses bind both interpretations and the affected decision.

Sources: [DOMParser algorithm](https://html.spec.whatwg.org/multipage/dynamic-markup-insertion.html#dom-domparser-parsefromstring),
[fast-xml-parser source](https://github.com/NaturalIntelligence/fast-xml-parser),
[saxes contracts](https://github.com/lddubeau/saxes).
<!-- /runtime:javascript -->

## Go

<!-- runtime:go -->
Distinguish `encoding/xml` from third-party packages and native wrappers. In the
standard decoder, inspect `Directive` token handling, predefined/configured
`Entity` replacements and `CharsetReader`; a DOCTYPE token does not itself prove
external DTD fetching. A replacement map is not automatically a recursive DTD
resolver. Find the application loader or different implementation before alleging
external access. A namespace URI alone is also not an I/O operation.

`Decoder.Strict` does not enforce all namespace requirements. Compare `Token`
with `RawToken`, unknown-prefix handling, `DefaultSpace`, expanded `Name.Space`
and local-name-only struct tags/selectors. A bypass requires a real security
consumer using a different interpretation. Check document/fragment expectations,
what `Decode` consumes and whether the caller checks remaining input.

Follow `UnmarshalXML`, `UnmarshalXMLAttr`, `encoding.TextUnmarshaler` and raw
`,innerxml` fields through custom side effects and output. Token byte slices may
alias the decoder's buffer until the next call; inspect `CopyToken`/copies before
retaining them or passing them asynchronously. A byte-limited reader can bound
input but does not by itself bound retained nodes, transformed output or custom
callback work. Inspect actual depth/work guards in the assessed Go version and
each custom recursive hook; do not assume a generic `MaxDepth` option exists.

Source: [encoding/xml API and linked implementation](https://pkg.go.dev/encoding/xml).
<!-- /runtime:go -->

## Rust

<!-- runtime:rust -->
Bind the crate/version/features and distinguish quick-xml `Reader`, `NsReader`,
Serde binding, roxmltree, xml-rs and libxml2 wrappers. Do not transfer a DTD or
resource contract between crates. Follow `DocType`/`GeneralRef` events and actual
unescaping/resolver code to determine whether declarations are interpreted or
resources opened. A name or event alone does not establish external loading.

For namespace-aware readers inspect declaration storage before event return,
per-element declaration limits, active-scope bytes and caller overrides. A plain
reader can refute the namespace-storage mechanism while leaving token buffering
unexamined. A declaration-count cap does not bound long URIs, total depth or all
later binding. Compare namespace checks with local-name matching in the actual
consumer. Preserve `NsReader` versus plain-reader and sync/async distinctions.

Inspect reusable buffers, borrowed event/attribute slices, conversions to owned
values and references retained across reads. Borrow checking does not bound
allocation/work; an alleged memory-safety defect needs an actual unsafe/FFI edge.
Trace feature-dependent encoding and matching-end/error checks through skipped
and consumed events. Serde replay, graph materialization and destruction have
separate budgets from the token reader. For roxmltree, inspect the assessed
`ParsingOptions` including DTD and node limits rather than assuming another
crate's defaults or an application check after constructing the tree.

Sources: [quick-xml configuration](https://docs.rs/quick-xml/latest/quick_xml/reader/struct.Config.html),
[namespace reader](https://docs.rs/quick-xml/latest/quick_xml/reader/struct.NsReader.html),
[roxmltree options](https://docs.rs/roxmltree/latest/roxmltree/struct.ParsingOptions.html).
<!-- /runtime:rust -->

## PHP

<!-- runtime:php -->
Bind the PHP version, loaded libxml version and exact extension: DOM, SimpleXML,
XMLReader, Expat-backed XML parser or another package. Distinguish passing XML
bytes from a filename/URI. Reconstruct flags and instance properties such as DTD
loading, entity substitution and validation; default assumptions from another
extension or release do not decide this call.

`LIBXML_NOENT` substitutes entities; `DTDLOAD`, `DTDATTR` and `DTDVALID` can enable
additional external access. `LIBXML_NO_XXE` requires PHP 8.4+ with libxml 2.13+;
check availability and use on the actual parse path. `LIBXML_NONET` is not a
universal local-file/custom-stream ban. Follow `libxml_set_external_entity_loader`
and registered stream wrappers: a returned stream supplies content, a returned
string can name a resource to open, and callback null means resolution failure.
Do not transfer a Java resolver's null-fallback behavior to this API. Inspect
restoration of global loader/error state in long-lived workers.

Review `xinclude()`, `schemaValidate`/schema compilation and XSLT separately.
For `XSLTProcessor`, inspect security preferences and PHP-function registration
before alleging file writes or execution. `LIBXML_PARSEHUGE` relaxes internal
limits; relate it to the actual work and exposure. Streaming XMLReader can retain
or expand subtrees through `expand()`/`readOuterXml()`; trace the resulting tree
and output. Suppressing libxml errors does not prove parsing or validation passed.

Sources: [libxml constants](https://www.php.net/manual/en/libxml.constants.php),
[external loader](https://www.php.net/manual/en/function.libxml-set-external-entity-loader.php),
[XSLTProcessor](https://www.php.net/manual/en/class.xsltprocessor.php).
<!-- /runtime:php -->
