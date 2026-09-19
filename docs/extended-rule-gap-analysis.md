# Extended rule gap analysis

This analysis compares Mehscan's 415-rule embedded catalog and procedural
analyzers with a pinned extended reference corpus containing 870 rules for
Mehscan's supported languages. The reference corpus spans 106 CWE labels. The
comparison is by security boundary and effective argument role, rather than by
rule name or raw catalog count.

The separate [unknown-origin review policy](unknown-origin-review-analysis.md)
defines which strong sink shapes must retain a decision-critical provenance
question during AI triage instead of allowing missing provenance to support
dismissal.

| Reference language | Rules assessed | Mehscan mapping note |
| --- | ---: | --- |
| C | 16 | C mechanics were also checked for applicable C++ boundaries. |
| C# | 33 | Compared with declarative rules and typed .NET summaries. |
| Go | 80 | Compared with catalog rules plus HTTP, filesystem, database and policy analyzers. |
| Java | 110 | Compared with catalog rules plus typed JVM ownership/configuration analyzers. |
| JavaScript | 189 | Compared with Node/browser catalogs and project summaries. |
| Kotlin | 1 | The sparse reference set was supplemented by applicable JVM APIs. |
| PHP | 60 | Compared with PHP native and bounded project-context rules. |
| Python | 366 | Compared with catalogs plus framework and project summaries. |
| Rust | 10 | The sparse reference set was supplemented by standard-library and crate APIs. |
| TypeScript | 190 | Applicable mechanics were also checked against TSX. |

The reference set contains no independent C++ or TSX directories. That absence
is not treated as evidence that those Mehscan languages have complete coverage.

The result is deliberately selective. Mehscan records sources, sinks,
sanitizers, policy evidence and bounded relationships for later review. A rule
is a useful candidate only when it adds a missing boundary with a stable API
identity and a security-sensitive operand. Framework-specific verdicts,
arbitrary same-name calls and syntax with no connection to an existing
capability are not imported merely to increase catalog parity.

## Added candidates

| Boundary | Languages | Added mechanics | Why it fits |
| --- | --- | --- | --- |
| Filesystem writes and mutations (CWE-22) | All 12 supported languages | Native and .NET moves; PHP copy, rename, delete and directory mutations; JVM NIO copy, move, delete and directory creation; Node rename, copy, remove, unlink and mkdir; Python `shutil` destinations and explicit `pathlib.Path` reads/writes; Go rename/remove-tree/mkdir; Rust copy, rename and directory mutations | These are concrete path-taking sinks. Copy and move preserve the source separately while `path` identifies the destination or mutation target. |
| Dynamic code (CWE-94) | C#, Java, Kotlin, Go, Rust, JavaScript, TypeScript, TSX | Razor parsing; typed Java script engines; typed Groovy, SpEL and EL expressions; typed Otto and Rhai engines; Node VM `compileFunction`, `Script` and `SourceTextModule` code operands | These APIs compile or evaluate code/expression syntax and have a distinct code operand. |
| Executable deserialization (CWE-502) | Python | `marshal`, `dill` and `jsonpickle` load/decode payloads | These extend the existing pickle/YAML payload boundary and preserve the serialized operand. |
| LDAP queries (CWE-90) | C, C++, Java, Kotlin, PHP, Rust | Native/PHP LDAP filters, typed JNDI directory-context filters and typed ldap3 filters | Filter syntax is captured separately from base DN, scope, controls, returned attributes and placeholder values. Existing C# and Go analyzers already cover their typed LDAP clients. |

The additions use established namespace or type names and retain explicit
argument roles. Focused tests cover positive operands and unrelated receiver
lookalikes. Lexically shadowed standard module names remain a general limitation
of declarative rules unless a language-specific resolver proves ownership.

## Complete family disposition

Every one of the 870 assessed rules is included in the disposition below. Rule
variants and framework-specific duplicates are collapsed into their 106 CWE
families; the API-level decisions for the current Mehscan surfaces are expanded
in the next table.

| Disposition | CWE families |
| --- | --- |
| Existing or extended Mehscan evidence surface | CWE-20, CWE-22, CWE-23, CWE-73, CWE-74, CWE-78, CWE-79, CWE-80, CWE-89, CWE-90, CWE-91, CWE-93, CWE-94, CWE-95, CWE-96, CWE-98, CWE-113, CWE-115, CWE-116, CWE-117, CWE-134, CWE-250, CWE-284, CWE-285, CWE-287, CWE-289, CWE-295, CWE-297, CWE-300, CWE-345, CWE-346, CWE-470, CWE-502, CWE-601, CWE-611, CWE-614, CWE-643, CWE-776, CWE-798, CWE-807, CWE-862, CWE-918, CWE-942, CWE-943, CWE-1004, CWE-1275 |
| Future capability or semantic-model work | CWE-119, CWE-190, CWE-200, CWE-209, CWE-269, CWE-276, CWE-307, CWE-310, CWE-311, CWE-319, CWE-322, CWE-323, CWE-326, CWE-327, CWE-328, CWE-329, CWE-330, CWE-338, CWE-347, CWE-352, CWE-377, CWE-400, CWE-415, CWE-416, CWE-436, CWE-501, CWE-521, CWE-522, CWE-523, CWE-532, CWE-548, CWE-613, CWE-668, CWE-704, CWE-774, CWE-780, CWE-913, CWE-915, CWE-916, CWE-921, CWE-922, CWE-939, CWE-1236, CWE-1333, CWE-1336 |
| Contextual, correctness, advisory, or syntax-only findings rejected as sink parity | CWE-14, CWE-155, CWE-183, CWE-242, CWE-252, CWE-451, CWE-454, CWE-477, CWE-489, CWE-553, CWE-676, CWE-697, CWE-706, CWE-1104, CWE-1204 |

## Existing areas compared

| Existing surface | Comparison result | Remaining useful gaps |
| --- | --- | --- |
| SQL and NoSQL injection (CWE-89, CWE-943) | The extended database pass covers the strong driver and document-query candidates for all 12 languages. C# also carries exact controller parameters through one service and one repository call when every target is unique. | Wrapper factories, compiler-resolved overloads, inferred SDK fields and deeper or transformed cross-file flows remain bounded gaps. See [extended database coverage](extended-database-coverage.md). |
| Process execution (CWE-78) | Standard process and shell launch APIs already cover the reference mechanics, with command/argument separation represented independently. | Framework wrappers require proof that they reach a process boundary. Generic callback or method invocation is not a process sink. |
| Outbound requests (CWE-918) | Declarative rules plus typed Java, Kotlin, C# and Python summaries already cover the principal HTTP clients and URL operands. Browser automation navigation largely overlaps dynamic browser-control semantics. | Add Playwright/Puppeteer navigation only after receiver construction and lazy-versus-dispatched request identity can be preserved. |
| Filesystem access (CWE-22) | The comparison found the standard mutation gaps added above. Archive-entry paths and containment controls already use separate evidence. | ODBC-style virtual filesystems, framework storage adapters and aliases need backend identity; a generic `open`, `copy` or `move` method is insufficient. |
| Dynamic code (CWE-94) | Built-in evaluators, Node VM constructors, Razor parsing and typed Groovy/SpEL/EL/Otto/Rhai engines are represented. | OGNL and additional template engines remain candidates only with imported/typed receiver ownership and a distinct expression/template role. |
| Deserialization (CWE-502) | Native .NET/Java object graphs, SnakeYAML/Jackson context, Node executable serialization, Python pickle/YAML, Go gob and Rust structured decoders are represented. The Python executable formats above were missing. | JMS/RMI/framework entrypoints need transport and declared-type ownership. Ordinary JSON decoding remains contextual data parsing rather than an unsafe-object verdict. |
| XML parsing (CWE-611) | Procedural Java and C# configuration analysis already covers factory features, resolver policy and parser use; Node native XML and Python parser boundaries are represented. | Additional third-party XML libraries need option semantics and entity-resolution proof, not parser-name matching alone. |
| TLS and certificates (CWE-295) | Request options, .NET callback policy, JVM trust/hostname policy and Rust invalid-certificate builders are already handled with literal/configuration semantics. | Custom trust implementations and cross-file builder state need project-level analysis. |
| HTML output (CWE-79) | Response writers, trusted-markup bypasses and framework-specific output contexts cover the strong sink candidates. | DOM assignment and UI-framework sinks need exact property/context modeling; broad `render`, `write` and `html` names are too ambiguous. |
| Redirects (CWE-601) | Major server framework redirect destinations and validation evidence are covered. | Browser navigation assignments and less common framework helpers need response or DOM ownership. |
| Uploads, authentication and authorization (CWE-306, CWE-434, CWE-639, CWE-862) | Mehscan models these as route, resource, file-content and guard relationships rather than standalone suspicious calls. | Reference rules that issue a verdict from a missing annotation or one API call do not preserve route inheritance, middleware order or resource identity. |
| Logging, LDAP, CORS and native memory (CWE-117, CWE-90, CWE-942, CWE-119/120/134) | Existing analyzers use log/value roles, LDAP context-specific encoding, response policy and native region/format operands. | Generic logging calls, string replacement and memory-function names do not establish injection, correct encoding or an invalid region by themselves. |

## Candidates requiring new capability work

The remaining reference rules are not sink gaps in an existing Mehscan
surface. They cluster into capability families that need their own contracts:

- CSRF and request-integrity policy (CWE-352), mass assignment (CWE-915), rate
  limiting (CWE-307) and password policy (CWE-521/916).
- Cleartext transport and storage (CWE-319/922), sensitive error/log exposure
  (CWE-200/209/532) and unsafe temporary files or permissions (CWE-276/377).
- Header, SMTP and expression injection (CWE-93/113/643), template injection
  (CWE-1336), regular-expression denial of service (CWE-1333), and CSV formula
  injection (CWE-1236).
- Cryptographic cipher/mode/key-lifecycle findings beyond the current hash,
  TLS and secret surfaces (CWE-321/323/326/328/329/330/338/347).
- Language/runtime-specific memory, ownership and unsafe-API findings that do
  not map to Mehscan's current native region evidence.

Each family needs a capability, semantic roles, safe controls, relationship
rules and positive/lookalike fixtures before individual API patterns are useful.

## Rejected parity candidates

The following shapes are intentionally excluded:

- a vulnerability verdict based only on a non-literal argument;
- broad method names such as `run`, `load`, `parse`, `render`, `write`, `open`,
  `copy`, `search` or `redirect` without receiver ownership;
- ordinary JSON/data decoding labeled as executable object deserialization;
- string replacement or generic escaping treated as a proven sanitizer;
- missing annotations treated as missing authorization without route and
  inherited policy context;
- dependency/version advisories, debug settings and configuration checks that
  do not add a source, sink, sanitizer or relationship to the current model.

These exclusions preserve Mehscan's partial-coverage contract: an unimplemented
mechanic is documented as a gap instead of being replaced by a noisy syntactic
approximation.
