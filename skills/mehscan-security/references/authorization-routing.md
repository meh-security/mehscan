# Authorization routing review

Read this reference for authorization and resource-access reviews involving an
HTTP route, generated CRUD surface, controller/action, endpoint group, resolver,
router mount, framework policy, or object-permission check.

## Framework-neutral baseline

Build a small operation matrix before deciding:

| Field | Required question |
| --- | --- |
| Boundary | What exact server handler, action, resolver, or generated operation is reachable? |
| Operation | What HTTP method and normalized path, RPC action, or resolver field invokes it? |
| Effect | Does it read sensitive data, mutate state, assign privilege, access another subject's object, or perform an intentionally public function? |
| Attachment | Which middleware, annotation, decorator, group, filter, policy, or default applies to this exact boundary? |
| Scope | Does the control cover this method, path, item/collection form, class/action, group, mount, or resolver? |
| Order | When order matters, does the control run before the handler or generated registration? |
| Strength | Does it establish identity, a coarse role/permission, or authorization of the same action and resource? |
| Enforcement | Does rejection stop execution? Is a boolean authorization result actually checked? |
| Override | Does an explicit public/anonymous exception replace an inherited or global requirement? |

Expand generated or conventional resource routing into separate operations only
when the framework/package behavior is supplied or canonical for the detected
framework. Do not invent a generator's supported methods. Once established,
judge collection and item operations separately. Coverage for one verb or path
does not transfer to a sibling operation unless an applicable mount, group, or
default explicitly supplies it.

Classify controls conservatively:

- `explicitly_public` and `denied` require canonical framework syntax or an
  exact local definition.
- `authenticated` proves identity only.
- roles, permissions, scopes, and coarse policies do not prove owner or tenant
  authorization for a caller-selected resource.
- custom security-sounding names are attachments until the exact definition
  and rejection behavior are shown.
- client UI checks, commented code, challenge telemetry, logging, and rejection
  followed by continuation are not server authorization.

Use `issue` when the supplied or boundedly retrieved code establishes a
sensitive application operation with a concrete public, uncovered, mismatched,
ignored, or fail-open authorization policy. Use `not_issue` for an intentionally
public safe operation or an exact effective control for the same operation and
resource. Use `needs_review` only for a decision-critical artifact named in the
response contract, such as a dynamic mount, unknown global default, or unresolved
custom guard.

An issue summary names the exact method/path or resolver/action, the sensitive
effect, and the missing or ineffective control. Do not broadly claim that every
route, model, or generated operation is exposed.

### Review-only mutation markers

An `authorization-review-marker` is the authorization family of the shared
`review-admission-marker` contract. It is emitted only when bounded syntax
establishes both a server mutation boundary and a mutation-shaped operation or
named helper, and carries
`review-invariant:action-resource-authorization`. It exists because a sensitive
action can deserve authorization review without calling a conventional security
sink. The marker is review admission, not proof that authorization is absent.

Do not ignore a marked operation because no ordinary sink, source-to-sink path,
or deterministic vulnerability candidate fired. Build the operation matrix from
the supplied boundary, handler, and framework facts. Use a supplied exact helper
definition when the marker names one; if it is absent and decisive, retrieve at
most one bounded exact definition. Use `issue` only for a concrete uncovered,
mismatched, ignored, or fail-open action/resource policy. Use `not_issue` only
when the supplied code establishes an intentionally safe or public effect, or an
effective control for the same subject, action, and resource. Authentication or
an unknown global policy does not by itself justify either conclusion.

## Bundle fact baseline

Prefer these facts for the reviewed operation, in this order:

1. `authorization_boundary_context` for the exact route, action, handler, or
   resolver.
2. `authorization_exception_context` or `authorization_default_context` when it
   changes the local requirement.
3. The closest `authorization_attachment_context` and
   `authorization_requirement_context`.
4. `authorization_order_context` for order-sensitive routers.
5. `resource_authorization_context` for owner, tenant, possession, action, or
   policy checks tied to the selected object.
6. One `authorization_guard_definition_context` for a decisive custom control.
7. The endpoint body and at most one exact helper implementing its sensitive
   effect when that context is already named by the review.

For a generated CRUD observation, prefer
`generated_route_registration_context`. It contains the bounded generator and
preceding registration scope needed to compare generated methods with local
controls. Use a supplemental source lookup only when this fact is absent,
truncated before the controlling scope, or names a dynamic mount that remains
decision-critical.

Do not let generic framework inventory displace the boundary or resource facts.
If method-level context is missing, retrieve one bounded source region covering
the named registration and its controlling scope. Include the complete preceding
registration section in an order-sensitive setup function; a fixed short window
that starts after relevant middleware is insufficient. Prefer `mehscan
investigate source`. Use `structural` only for an exact syntax question, and do
not treat an empty, truncated, or parse-failed search as proof of absence.

## Express and compatible ordered routers

- `app.METHOD` or `router.METHOD` controls one verb unless a surrounding mount
  also applies. `app.use`/`router.use` may cover multiple verbs and descendant
  paths according to its literal prefix.
- A route-chain control applies only to the methods carrying that middleware.
- Resolve a literal router mount prefix when supplied; keep dynamic mounts
  unresolved.
- Only middleware registered before the handler or generator can protect it.
- For generated resources such as REST model registration, compare every
  established generated verb and collection/item path with earlier mounts and
  method-specific controls.
- A Mehscan `generated-crud` rule establishes that the matched registration
  creates CRUD operations even when the local excerpt contains only endpoint
  templates. For `finale.resource`/`sequelize-restful`, review at least GET on
  collection/item, POST on the collection, and PUT/DELETE on the item path.
  Retrieve the preceding registrations before deciding; do not dismiss the
  observation merely because those verbs are implicit in the generator call.
- Include one exact custom middleware body when its rejection and `next()`
  behavior decides the result.

## ASP.NET Core

- Combine controller/class and action attributes. `[AllowAnonymous]` overrides
  inherited `[Authorize]` for that endpoint.
- Preserve literal `Roles`, `Policy`, and `AuthenticationSchemes`; these remain
  coarse unless the reviewed operation needs only that boundary permission.
- For minimal APIs, carry `MapGroup` prefixes and `RequireAuthorization` or
  `AllowAnonymous` inheritance to the exact mapped verb. Include authorization
  attributes on endpoint delegate parameters when present.
- Apply fallback/default policies only in their configured scope and include
  `UseAuthentication`/`UseAuthorization` ordering when activation is decisive.
- `AuthorizeAsync` protects an operation only when its result or failure gates
  execution and its resource/action matches the sensitive operation.

## Spring MVC, WebFlux, and Ktor

- Combine class and method mappings to form the endpoint path.
- Apply Spring Security matcher rules in declared order and only within the
  matching filter chain. Keep multiple-chain selection unresolved when the
  supplied matchers cannot decide it.
- Distinguish `permitAll`, `denyAll`, authenticated, roles/authorities, and
  literal access expressions. An authenticated route still needs resource
  authorization for caller-selected objects.
- Method annotations require their corresponding activation. Preserve the exact
  `@PreAuthorize`, `@PostAuthorize`, `@Secured`, `@RolesAllowed`, `@PermitAll`,
  or `@DenyAll` expression for AI review.
- Ktor `authenticate` blocks and route nesting inherit structurally; custom
  authorization inside handlers remains a bounded definition.

## Django and Django REST Framework

- Apply Django decorators and mixins to the exact view, including method/action
  overrides.
- Resolve DRF global, class, and action-level `permission_classes`; the closest
  explicit override wins. `AllowAny` is public, `IsAuthenticated` proves only
  identity, and object access may require object permissions or an owner-scoped
  queryset.
- Treat router-generated ViewSet actions separately: list, retrieve, create,
  update/partial-update, delete, and custom actions can have different policy.
- An exact `check_object_permissions(request, obj)` or owner-scoped queryset can
  protect the selected object. Merely defining a permission class does not prove
  that the reviewed action invokes it.

## Laravel and Symfony

- Carry Laravel route-group prefixes and middleware to literal routes and
  `Route::resource`/`apiResource` actions. Respect `only` and `except` on routes
  and controller middleware.
- `auth` establishes identity. `can:ability,model`, throwing controller
  `authorize`, and a checked Gate decision can establish action/resource policy
  when their subject matches the operation.
- A FormRequest `authorize(): true` allows that request class; it does not prove
  resource authorization. A controller policy check may still provide it.
- For Symfony, apply ordered `access_control`, firewall scope, `PUBLIC_ACCESS`,
  roles, `#[IsGranted]`, and `denyAccessUnlessGranted` to the exact route. A
  boolean `isGranted` result must gate execution.

## NestJS, Fastify, Next.js, and GraphQL

- In NestJS, combine controller, method, and global guards. `@UseGuards(Foo)` is
  an attachment; inspect `Foo.canActivate` and matching metadata before treating
  it as authorization. Public metadata may override a global guard.
- In Fastify, respect plugin encapsulation, prefixes, and ordered `onRequest`,
  `preValidation`, and `preHandler` hooks.
- In Next.js, middleware matcher coverage is a boundary fact. Route Handlers,
  Server Actions, and data-access mutations still need an applicable server-side
  session and resource check.
- For GraphQL, use the resolver field as the boundary. HTTP endpoint protection
  does not automatically establish field/action/resource authorization.

## Go, Rust, and native web frameworks

- Carry literal router groups, mounts, middleware chains, filters, guards, and
  fairings/layers only to routes they structurally wrap.
- Respect framework ordering and exact rejection behavior. A parsed token or
  populated principal establishes identity, not authorization of a selected
  object.
- Keep macros, generated configuration routes, dynamic filter lists, and custom
  policy engines as bounded context unless the supplied expansion or definition
  establishes exact coverage.
