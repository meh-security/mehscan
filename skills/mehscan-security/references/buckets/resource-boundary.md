# Resource boundary

Keep the verdict on its selected operation. An unsafe archive extraction does
not turn temporary-file cleanup into an unsafe deletion. Use the engine's
extraction sink and destination for ZIP traversal; retain an uncovered adjacent
effect as a separate lead. Containment computed only for reporting after the
write does not prevent extraction.

Trace **selector origin → resolved resource or destination → applicable
constraint → read, write or request**. Compare the final target, not just a
raw path or URL string.
Check the complete expression: quoted fragments do not make an operand fixed.
Concatenation and conditional/logical operators can select a different path or
destination even when a literal prefix is visible.

Establish where the request executes before calling an outbound request
SSRF. A browser or desktop client fetch is not a server-side request merely
because it uses an HTTP client; identify any separate privileged network
boundary before applying CWE-918.
For native browser requests, inspect `endpoint` producer facts and request options.
`browser_request_context` supports conditional Value selection of ordinary GET/HEAD,
not a safe destination verdict. Headers, bearer tokens, cookies/credentials,
mutations and unknown options retain their own relationship. Follow the URL/config
producer when those effects make the destination consequential; do not investigate
every browser GET as though the server executed it.
For DOM configuration, follow the name conversion into its markup producer:
`dataset.apiUrl` corresponds to `data-api-url`. Use `references --symbol data-api-url
--path-prefix COMPONENT` to locate its views/templates, then read the returned
source. These are textual leads, not proof of destination ownership.
When wider references include generated copies, follow the authored source rather
than rereading equivalent distributions.

- For files, inspect path joining, normalization, containment, symlinks and
  the exact storage or read root relevant to this question. A framework render
  option may select another file even when the explicit template name is fixed;
  read the registered view engine and a local behavior test before naming the
  engine or closing that path. A writer
  elsewhere in the repository is a lead until its destination can reach the
  read target.
  Read the actual open flags/mode before calling it a read or write. An
  `filesystem-mode:unresolved` tag asks for the effective mode, not an invented
  effect. Normalization alone is not root containment. For moves/renames, inspect
  both `path` and `filesystem_source`; a fixed destination or its guard does not
  close an independently selected source. For a Comprehensive recursive-root
  question, follow the content/export/disclosure consumer instead of researching
  every listed filename. Ordinary setup/listing sinks are omitted at extraction.
  Check a filename guard against the actual path library and supported platforms.
  Rejecting separators and `..` alone leaves Windows drive-relative names such
  as `C:name`; .NET `Path.Combine` can discard the intended root. Rooted-path
  rejection, basename extraction or complete proven selectors can settle that
  property. Unknown platform semantics require a targeted check, not a safe verdict.
- C# native `fixed_filesystem_path` establishes fixed selection for that exact
  operand, not authorization or safe contents/effects. Complete
  `temporary_filesystem_path` closes routine generated-path traversal selection.
  A compiler-bound Guid.ToString segment cannot introduce traversal, even if the
  GUID came from a request. Do not research its caller to establish that property.
  Supported scalar formatting, known runtime roots and closed-root enumeration
  can also settle traversal syntax; they do not settle object ownership. Do not
  reopen these proven selectors merely because a variable reaches a file API.
  Check any unknown root or additional filename separately.
  A record ID constrains selection, not the stored path text in the selected
  row. For a remaining string component, inspect its writers across relevant
  authored components, including import paths; a GUID-only upload path alone
  does not establish all stored values. Keep proven GUID components closed.
  Native `property_writer` facts locate assignments to the exact source property,
  not necessarily the selected resource instance. Follow a consequential writer
  through persistence and caller authority; an empty or bounded candidate list
  does not establish all writers. Reuse verified generated-key construction
  while checking alternate assignments independently.
  Archive contents, unauthorized object selection and executable writes are distinct relationships;
  retain them when supported by source, rather than reopening mundane setup.
  Use `local_operand_origin` for exact producers and `operand_boundary` to locate
  the missing edge. Path.Combine and arbitrary ToString calls alone do not prove
  safe selection. A fact carrying `partial_semantic_context` remains navigation
  evidence; a locally complete path fact can survive unrelated compiler errors.
  `immutable_filesystem_operand` only identifies an unchanged string slot. For
  `shared_csharp_filesystem_selection`, inspect shared root authority once and
  check the selected operation's guards/effect; do not transfer a safe verdict.
- For outbound requests and redirects, identify the final scheme, authority
  and destination after any parsing or rewrite. Fixed release URLs selected
  by OS or architecture do not become attacker-selected merely because a
  variable holds them.
  Establish the intended network authority first. Fetching user-selected public
  URLs for images, previews or imports is not by itself SSRF, and need not use
  a fixed host allowlist. Show unintended protected-resource access or credential/
  data disclosure; inspect actual scheme/address filtering, redirects and proxy
  behavior. A named filtering wrapper is not proof: read its rejection behavior,
  defaults and the selected call's overrides. Report a shown conditional bypass
  with its activation conditions; do not replace that analysis with either an
  automatic safe verdict or an issue based only on arbitrary public destinations.
  URL parsing alone is not destination approval. Review the dispatch, using
  `endpoint` and its related construction facts. When
  `outbound-request:unresolved-producer` is present, inspect the supplied
  `request` origin and helper/mutation before choosing a verdict. A fixed URL
  in supporting constructor evidence does not close an unresolved final request.
  Request builders are context without an extra verdict. Establish the
  server/privileged actor and consequence independently of dispatch accounting.
  For Kotlin OkHttp, `initial_endpoint` with
  `outbound-request:unresolved-client-policy` locates the initial request URL,
  not the final destination. Follow the captured `client` and its configured
  interceptors/rewrites before closing the request. A shown input relationship
  into that initial URL remains a lead, with final-destination uncertainty;
  unknown client policy does not erase the supplied input flow.
  Kotlin connection properties
  such as `inputStream` and `responseCode` can perform I/O; their read sites are
  real consumers, while `openConnection` alone remains construction context.
  Java uses the same separation at connect/content/header/response consumers.
  With `outbound-request:unresolved-proxy-policy`, inspect the captured `proxy`
  separately from the request URL. A fixed URL does not close proxy selection.
  A typed unknown connection retains its origin question; metadata/setup reads
  such as getURL and getRequestProperty are omitted from network reviews.
  The endpoint capture and `outbound_operation` locate the destination expression
  and exact lexical callable. Compact callable source can expose shared URL
  construction and transport options. Check whether execution is in a browser
  or server and whether dynamic data can change the destination authority,
  rather than only a path/query. Configuration and SDK callbacks require their
  actual producers checked. A nearby configuration assignment does not prove
  the reaching URL: inspect fallbacks, interpolation and later writes before
  dismissing caller influence. Shared client context does not prove identical
  redirect, proxy, credential or branch policy across sites.
- For resource access, identify whether the selected object belongs to the
  intended public surface or requires authority the caller lacks. Establish the
  consequential read/disclosure/action before treating missing guards as a gap.
  A response difference can be an existence oracle, but explain which protected
  information it discloses and why that exceeds intended access. Expected
  discovery behavior alone does not establish that consequence. Then compare the
  selected object with the
  verified subject or another tenant. A sensitive read or existence oracle
  can matter without a mutation. Inspect earlier middleware on every matching
  route prefix to see whether it replaces request identity fields before the
  selected handler; compare the final field value used in the query.
  Before closing on delegated protection, inspect the applicable policy and its
  rejection behavior for the selected actor, resource and action. A call named
  `authorize` or `can`, or an actor ID passed to a finder, does not establish that
  protection. Finder options, association loading and policy context can preload
  data without restricting which row is selected. Read the effective filter or
  the invoked guard's implementation; cite that behavior, not only its call site.
  If this decisive code remains unread or unresolved within the budget, retain
  the specific gap rather than returning a safe verdict from the names/arguments.
  `result_use:boolean_or_null_test_only` describes complete bounded local uses
  of a lookup result, not an ownership control or proof the query was awaited.
  Review the observable error/status difference and any credential or mutation
  enabled by that test. Do not infer safety from validation-shaped consumption.
  `resource_selector.*` facts locate selector-value producers, including bounded
  local constants. A member read such as `req.user.id` is not a verified subject
  or proof that the selected model is that subject's account. Follow the identity
  producer and match the resource/key. `resource_selector:fixed_equality` closes
  caller-selected key substitution only; operation authorization and disclosure
  remain separate questions.
  `resource_operation` locates the exact lexical callable, not a proven route or
  policy scope. Compact callables can be supplied as one reusable source artifact
  so later checks remain visible. Reuse that context across questions, but verify
  each selector, branch and effect independently. Larger callables remain lookup
  targets; a bounded excerpt cannot establish that a later control is absent.
  Resource helper context can identify a direct call to a unique stable local
  function. This establishes a lexical target, not that the helper ran, succeeded,
  or protected this operation. Member calls, imported helpers, shadowed names and
  mutable bindings may have no resolved helper excerpt. Use the operation and
  import/receiver locations to inspect the actual implementation when its behavior
  changes the verdict; missing helper context is not evidence of missing controls.
  Python filter captures identify the selector expression without tracing aliases
  or proving object identity.
  `resource_execution_context` points to enclosing class bases: resolve their
  imports and actual registration before treating a method as CLI, HTTP or an
  authentication callback. A CLI-looking class may have other callers. A read
  using a passed object's key is not automatically an authorized reload.
  A thin repository getter still needs its caller checked. Imports, service
  registries and callbacks can expose it even when no request-to-getter flow is
  supplied. Use references or structural lookup to locate method calls and
  service registrations, then check the actual caller's selector and authority.
  An authorized caller does not close other callers; no local guard in a getter
  does not establish a bypass. A nearby `create()` call does not establish that a
  later selector retains the created record's ID: inspect intervening writes, model/context
  identity and ordering. Keep distinct reads, disclosures and writes separate.

Stop when the exact target is fixed or constrained for the same operation, or
when a lower-trust selector can reach the protected target. If resolution or
the relevant producer is missing, request that specific location.
