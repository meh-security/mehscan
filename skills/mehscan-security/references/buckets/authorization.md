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

Trace **route/action → accepted credential branch → verified subject →
selected object → applicable guard and rejection → sensitive effect**.
Authentication alone does not authorize the action on that object.

1. Resolve the exact method/path, action or resolver. For generated CRUD,
   separate the supported collection and item operations; do not transfer a
   guard from a sibling route.
2. If the subject comes from a token, session or API key, inspect the accepted
   branch that supplies it. Check verification before trusting an owner lookup.
3. Follow delegation to the service that selects or mutates the object.
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

A `review-admission-marker` proves a server boundary and mutation-shaped
effect, not a missing guard. If its service, credential branch or effective
policy is absent and the bundle offers no lookup, identify that exact
packaging gap rather than closing the review safe.
