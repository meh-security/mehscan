# Resource boundary

Trace **selector origin → resolved resource or destination → applicable
constraint → read, write or request**. Compare the final target, not just a
raw path or URL string.

Establish where the request executes before calling an outbound request
SSRF. A browser or desktop client fetch is not a server-side request merely
because it uses an HTTP client; identify any separate privileged network
boundary before applying CWE-918.

- For files, inspect path joining, normalization, containment, symlinks and
  the exact storage or read root relevant to this question. A framework render
  option may select another file even when the explicit template name is fixed;
  read the registered view engine and a local behavior test before naming the
  engine or closing that path. A writer
  elsewhere in the repository is a lead until its destination can reach the
  read target.
- C# native `fixed_filesystem_path` establishes fixed selection for that exact
  operand, not authorization or safe contents/effects. `temporary_filesystem_path`
  is conditional on temporary-root authority and symlinks; reopen deferred Value
  IDs when those assumptions fail or the operation participates in a sensitive
  effect. Use `local_operand_origin` for exact producers and `operand_boundary`
  to locate the missing edge. Path.Combine and a primitive ToString call alone
  establish neither containment nor trusted input. Partial compiler facts remain
  research evidence and do not justify closing the question.
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
