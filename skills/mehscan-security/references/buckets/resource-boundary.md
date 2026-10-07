# Resource boundary

Trace **selector origin → resolved resource or destination → applicable
constraint → read, write or request**. Compare the final target, not just a
raw path or URL string.

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
- For resource access, identify whether the selected object belongs to the
  verified subject or another tenant. A sensitive read or existence oracle
  can matter without a mutation. Inspect earlier middleware on every matching
  route prefix to see whether it replaces request identity fields before the
  selected handler; compare the final field value used in the query.

Stop when the exact target is fixed or constrained for the same operation, or
when a lower-trust selector can reach the protected target. If resolution or
the relevant producer is missing, request that specific location.
