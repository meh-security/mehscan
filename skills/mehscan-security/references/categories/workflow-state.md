# Workflow, ordering and shared state

Review a bounded operation, not a speculative state machine for the application.
Name its protected effect and source-supported prerequisite, then compare the
same actor/object/value at the check and the effect.

- Rejection: return, throw, transaction abort or effective middleware can stop an
  effect. Logging, recording a challenge, sending an error then continuing, or
  calling a validator whose result is ignored may not.
- Alternate branches: identify whether an unrecognized mode, omitted field,
  fallback or secondary entrypoint bypasses the prerequisite. An absent intended
  path is not proof of a bypass; show a path reaching the actual effect.
- Authoritative values: compare server price/permission/owner/state with the value
  used in mutation. Check transformations, duplicate representations and merge
  order when the validated value can differ from the consumed value.
- Repetition: for allowances, one-time actions or quotas, inspect both the limit
  predicate and the state update. Equality boundaries and retries may matter.
- Concurrency: do not infer race safety from a transaction name or race exploit
  from two source statements alone. Establish relevant conditional update,
  uniqueness, locking or isolation semantics; preserve unknown semantics when
  decisive rather than inventing a runtime interleaving.

An intended workflow requirement must come from source policy, tests,
documentation or an explicit requirement. A product preference is not a security
finding. Separate code-supported bypass, unproved deployment condition and
unavailable business policy. Do not turn every missing SQL LIMIT into a resource
finding or every self-service change into an authorization violation.
