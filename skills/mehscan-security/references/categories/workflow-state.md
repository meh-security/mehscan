# Workflow, ordering and shared state

Review a bounded operation, not a speculative state machine for the application.
Name its protected effect and source-supported prerequisite, then compare the
same actor/object/value at the check and the effect.

Describe the allowed transition using authoritative starting state, actor,
target, amount/allowance, prerequisite and committed benefit. Choose a material
misuse case from that relationship and show a path reaching the effect; do not
enumerate speculative workflows.

| Bypass family | Deciding source relationship |
| --- | --- |
| Skip/reorder/direct call | A later entrypoint reaches the benefit without rechecking the required earlier state; the UI's normal sequence is not enforcement. |
| Alternate representation | Unknown/omitted modes, duplicate parameters or different checked/consumed IDs select a path to the effect. Trace parsing and defaults rather than assuming which representation wins. |
| Replay/parallel/batch use | The same grant, balance or allowance can fund multiple effects. Bind consumption to the transaction and accepted batch; check idempotency and failure/rollback semantics. |
| Value substitution | Type-correct amounts, quantities, role or status fields violate a server-owned restriction. Follow recomputation and persistence before claiming a bypass. |

Inspect denial before the first consequential effect, including queued work and
earlier committed writes. A later error or a failed secondary step does not
establish rollback. Conversely, a source-proven abort or authoritative overwrite
can close that path. A valid ownership check does not prove payment or approval;
a missing payment check does not make the selected object someone else's.

Return, throw, transaction abort or effective middleware can stop an effect;
logging, recording a challenge, sending an error then continuing, or ignoring a
validator's result may not. Check transformations and merge order between the
validated and consumed value. For quotas and one-time actions, inspect both the
predicate and consumption, including equality boundaries and retries.
Do not infer race safety from a transaction name or a race exploit from two
statements. Establish conditional update, uniqueness, locking or isolation
semantics; preserve a decisive unknown rather than inventing an interleaving.

An intended workflow requirement must come from source policy, tests,
documentation or an explicit requirement. A product preference is not a security
finding. Separate code-supported bypass, unproved deployment condition and
unavailable business policy. Do not turn every missing SQL LIMIT into a resource
finding or every self-service change into an authorization violation.

For automated abuse of a public flow, establish the business restriction and
concrete harm. Missing rate limiting alone does not establish abuse, and a per-
request limit may not enforce a per-account or per-operation allowance. Preserve
unavailable business policy rather than inventing a prohibition on normal use.

Sources: [OWASP WSTG workflow circumvention](https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/10-Business_Logic_Testing/06-Testing_for_the_Circumvention_of_Work_Flows/),
[Transaction Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Transaction_Authorization_Cheat_Sheet.html)
and [API6:2023 sensitive business flows](https://api-security.owasp.org/editions/2023/en/0xa6-unrestricted-access-to-sensitive-business-flows/).
