# Authorization

First establish an action that needs a protected subject or resource. Public
sign-in and registration, and sign-out of only the current session, can be
intentional without an authorization guard. A missing `RequireAuthorization`
alone is not CWE-862. If a logout request can be forced cross-site, assess
that as a separate CSRF question. Seek gateway or deployment policy only when
it could change the verdict for the exact sensitive effect.
An object ID in a public CRUD route does not itself establish an owner policy.
Use the application's accounts, documented access model, and actual resource
effect to establish one; if the app intentionally exposes that operation to
everyone, close the ownership claim rather than inventing an owner subject.
First verify that the action actually changes or discloses a resource. A log
and a success-shaped response can simulate deletion or transfer without doing
either. Read prepared same-project startup and inherited policy source before
spending per-endpoint queries; those files are navigation, not proof that a
policy applies. A clipped startup window cannot prove absence of a fallback.
Locate the actual handler or resolver body. Documentation objects, decorator
arguments and client mutation-success callbacks do not themselves establish a
server authorization boundary. For GraphQL, check that the candidate is the
resolver member, rather than a callback merely near mutation-related text.

Trace **route/action → accepted credential branch → verified subject →
selected object → applicable guard and rejection → sensitive effect**.
Authentication alone does not authorize the action on that object.

Choose the relationship being challenged before widening the review:

| Boundary | Concrete misuse case to check in source |
| --- | --- |
| Object access (BOLA/IDOR) | An allowed actor substitutes another object's ID, parent/child relationship or batch member. Bind the effective selected records to that actor's permitted scope. |
| Function access (BFLA) | A lower-privileged actor reaches a restricted action through a method, route, resolver or alternate entrypoint. Derive the restriction from actual policy, not an admin-looking URL. |
| Property access | An otherwise allowed operation accepts a protected owner/author/tenant/role field or returns a sensitive property. Inspect effective input mapping, server overrides, persistence and response projection. |
| Workflow authority | The actor owns the object but skips a required payment, approval, verification or state prerequisite. Use `workflow-state` for the transition, not another ownership check. |

For the material boundary, contrast an allowed case with a minimally changed
request or sequence that should be rejected. Name the feasible actor, changed
value, expected restriction and actual disclosure/write. Follow server-side
normalization and merge order: the checked URL/body/cache value may differ from
the one consumed. Check every affected record in a batch. Parameter binding,
opaque identifiers and a valid token do not establish object or field permission.
A comparison that records a mismatch after a write cannot authorize that write.
Keep a distinct issuer compromise or workflow defect separate from an otherwise
effective local owner predicate; record the producer flaw and affected conditions
without multiplying it into independent local bypasses.

Prioritize the producer of a relied-on subject or storage key before sibling
endpoints. For a session/cache-derived subject, use
[token review](../token-review.md) to inspect acceptance and relevant state writers;
a cache read or equality with another field from that cache is not independent
identity proof. Reuse that inspected acceptance chain for compatible consumers.

For an authenticated connection or pooled client, trace the requested identity
and the identity bound to the reusable object into the match and attach paths.
Check whether the active authentication mode binds state to a request or to the
connection. Follow its already-authenticated branch to see whether it sends new
credentials. A destination match or an update to stored credential fields can
leave the old authenticated context active. Check method-specific rejection and
any early accept or fallback that can still attach the object. Use matching
credentials or a verified fresh connection as a control, and keep origin and
proxy authentication separate when both are present.

For a supposedly owner-scoped compound key, check the actual encoding. Validating
each component's characters does not prove that different owner/object pairs
cannot map to the same stored key. Preserve applicable grants and require a
feasible collision under the accepted component constraints.
Rust `rust_context_*` captures can supply the actor type, extractor/guard helpers,
imports and policy definitions. These are bounded source dependencies, not proof
that a particular trait implementation or macro enforces this action. Bind the
accepted identity and the effective rejection to the selected object and effect;
keep ambiguous dispatch or conditional configuration explicit.
For self-service actions, also inspect privilege, enrollment, billing or ownership
side effects. A session-bound user does not alone authorize a state transition;
check supplied resource IDs against the policy and membership actually affected.
An owner check can settle object ownership while leaving action permissions,
delegated-client scopes or tenant policy unresolved. Match the full selected
question before closing it. When permission metadata is present, locate the
code that consumes it and establish that enforcement applies to this route;
neither the annotation nor its apparent missing local guard proves the verdict.

A missing more granular check is not itself a bypass. Establish which principal
can reach which prohibited effect under the effective permission composition.
A global grant may cover the selected objects; trace how applicable own-resource,
type and explicit-denial handlers combine with it. Do not assume a null-resource
check grants less authority or that a later handler revokes an earlier grant.
Comments about optional custom policy are leads, not evidence of an active denial.
A shown check-to-effect identity mismatch can support a conditional finding
under source-supported permission conditions without a deployed account. If the
effective policy is still unknown, preserve that question rather than promoting
a bypass or declaring the whole endpoint safe.

1. Resolve the exact method/path, action or resolver. For generated CRUD,
   separate the supported collection and item operations; do not transfer a
   guard from a sibling route.
2. If the subject comes from a token, session or API key, inspect the accepted
   branch that supplies it. Check verification before trusting an owner lookup.
3. Follow delegation to the service that selects or mutates the object.
   For a receiver method, locate its construction/type and import, then check
   applicable implementations or overrides. A same-named method elsewhere is
   a search result, not the invoked contract. If ownership stays unresolved,
   name that missing edge rather than borrowing a nearby rejection.
   Compare the verified subject with that same resource.
4. Check policy attachment, matching scope, ordering and whether rejection
   actually stops this operation. A policy name, annotation or framework
   import alone is insufficient.

For Spring, combine class/method mappings and ordered filter-chain matchers.
For ASP.NET, combine class/action attributes and relevant fallback policy;
`AllowAnonymous` can override inherited requirements. For Express, preceding
middleware and mount scope matter. For DRF, use the effective global, class
or action permission and object check. For GraphQL or generated routes,
establish the registered operation before applying its guard.

A `review-admission-marker` records a candidate server boundary and mutation-
shaped effect, not a missing guard. Verify actual server registration and
invocation: a similarly named client, CLI or database call is not boundary
proof. If its service, credential branch or effective
policy is absent and the bundle offers no lookup, identify that exact
packaging gap rather than closing the review safe.
Marker admission is bounded. When assessing authorization coverage, compare
the selected questions with real entrypoints and effects; the marker list is
not an exhaustive authorization audit. A boundary omitted by the admission
budget has not been reviewed or found safe. Read `marker_admission` in the
inventory overview; use bounded marker continuation from review planning when
the remaining questions warrant review.

Sources: [OWASP API1:2023 object authorization](https://api-security.owasp.org/editions/2023/en/0xa1-broken-object-level-authorization/),
[API3:2023 property authorization](https://api-security.owasp.org/editions/2023/en/0xa3-broken-object-property-level-authorization/),
[API5:2023 function authorization](https://api-security.owasp.org/editions/2023/en/0xa5-broken-function-level-authorization/)
and the [Authorization Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html).
