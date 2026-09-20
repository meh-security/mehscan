# Authorization framework analysis

## Goal

Authorization coverage should preserve three separate questions:

1. What route, handler, resolver, or operation is exposed?
2. What authentication or authorization requirement is attached to that exact
   boundary?
3. Does the requirement authorize the same subject, action, and resource used
   by the sensitive operation?

The engine can answer the first two when the framework syntax is exact. It can
also prove a few local resource relationships. The AI reviewer should answer
the third from bounded facts and exact custom-guard definitions. A middleware
name containing `auth`, `role`, or `admin` is not proof of enforcement.

## Shared fact model

The current `HttpRouteAccess` values conflate an unclassified route with an
explicitly public route. Extend the route model with `explicitly_public` and
`denied`. Keep `role_restricted` for compatibility and attach the specific
requirement as facts instead of adding an enum variant for every policy style.

| Fact role | Locally provable content |
| --- | --- |
| `authorization_boundary_context` | Exact framework route, handler, method, resolver, or server action and its HTTP method/path when available. |
| `authorization_requirement_context` | Canonical authenticated-user, role, authority, permission, scope, policy, gate, voter, or request-guard requirement with literal arguments. |
| `authorization_attachment_context` | Exact decorator, annotation, middleware argument, route group, builder chain, or configuration entry that attaches a requirement to the boundary. |
| `authorization_default_context` | Exact fallback, global guard, default permission class, filter chain, or access-control rule and its application scope. |
| `authorization_exception_context` | Exact anonymous/public/permit-all override, including the affected route or method. |
| `authorization_activation_context` | Exact activation needed for the policy, such as Spring method-security enablement, Nest `APP_GUARD`, or ASP.NET authorization middleware. |
| `authorization_guard_definition_context` | One exact custom guard, middleware, dependency, policy, or voter definition. This is control inventory unless a supported local enforcement shape is proved. |
| `resource_authorization_context` | Exact subject/resource/action arguments, owner or tenant predicate, or framework object-permission call associated with the sensitive operation. |
| `authorization_order_context` | Exact source order when the framework defines order semantically, such as Express/Go middleware registered before a route or ordered Spring request matchers. |

Bound each review to one effective default, two direct requirements, two
attachment facts, and one custom definition. Reuse the framework index and
existing exact-name context index. This remains one source pass plus bounded
name lookups: no general call graph, DI resolution, CFG, or taint propagation.

## What should become findings

The engine should create a security-configuration finding only for an explicit
local policy failure:

- a canonical public override on a known sensitive or state-changing boundary;
- a broad framework rule such as catch-all `permitAll` or `PUBLIC_ACCESS`;
- a fail-open setting or an authorization decision whose result is visibly
  ignored before the sensitive operation;
- a locally proved rejection branch that still invokes the next handler; or
- request-selected resource access where the same local query or lookup is
  proved to omit an available authenticated owner or tenant constraint.

The absence of an annotation, middleware, policy call, or local configuration
remains an unresolved fact. It is not a finding because inherited, global, or
deployment policy may own the control.

## Framework analysis

### C# — ASP.NET Core MVC, Razor Pages, and minimal APIs

Current coverage observes fallback/default policies, `[Authorize]`,
`[AllowAnonymous]`, minimal API `RequireAuthorization`, anonymous state changes,
middleware order, role assignment, and some owner-scoped Entity Framework
queries.

Add exact framework identity and structured facts for:

- controller and action inheritance for `[Authorize]`, `[AllowAnonymous]`,
  `Roles`, `Policy`, and `AuthenticationSchemes`;
- Razor Page conventions such as `AuthorizeFolder`, `AuthorizePage`, and
  `AllowAnonymousToPage`;
- minimal API groups and endpoints: `MapGroup`, `RequireAuthorization`,
  `AllowAnonymous`, and group inheritance;
- `AddPolicy` requirements including `RequireRole`, `RequireClaim`,
  `RequireAssertion`, and `RequireAuthenticatedUser`;
- `IAuthorizationService.AuthorizeAsync`, `User.IsInRole`, and `User.HasClaim`
  as subject/action/resource facts near a sensitive operation; and
- `UseAuthentication`/`UseAuthorization` activation and ordering as project
  facts.

The engine can classify canonical attributes and literal policy builders.
Policy handlers, `RequireAssertion` lambdas, custom
`IAuthorizationRequirementHandler` implementations, and whether an
`AuthorizeAsync` result protects the operation belong to AI review.

### Java — Spring MVC and Spring Security

Current coverage observes a narrow `HttpSecurity` route policy and
`@PreAuthorize`/`@Secured` inventory. It misses important sibling forms and
some rules do not yet require exact annotation identity.

Add:

- `requestMatchers` with multiple paths, HTTP-method overloads, `anyRequest`,
  `securityMatcher`, and ordered rule facts;
- `denyAll`, `hasAnyRole`, `hasAnyAuthority`, and literal `access` expressions;
- legacy `authorizeRequests`/`antMatchers` as compatibility facts;
- exact `@PreAuthorize`, `@PostAuthorize`, `@Secured`, `@RolesAllowed`,
  `@PermitAll`, and `@DenyAll` imports at class and method scope;
- `@EnableMethodSecurity` flags for pre/post, secured, and JSR-250 activation;
- `AuthorizationManager.check/authorize` and owner/tenant expressions involving
  the exact method parameter or return object; and
- WebFlux `SecurityWebFilterChain` equivalents.

The engine can resolve literal matcher order and class/method inheritance.
SpEL meaning beyond small canonical calls, meta-annotations, proxy bypass,
multiple filter-chain selection, custom `AuthorizationManager`, and role
hierarchy effects should be supplied to AI as bounded definitions.

### Kotlin — Spring and Ktor

Kotlin Spring should share the Java policy vocabulary while retaining its exact
import/alias handling. Add the full annotation and request DSL forms listed
above, including class-level inheritance and activation facts.

For Ktor, add exact facts for:

- `install(Authentication)` and named provider declarations;
- `authenticate(...)` route ancestry and `AuthenticationStrategy`;
- typed authentication and `withRoles`/role-aware route requirements; and
- `call.principal<T>()` plus local role/permission rejection near an operation.

Named providers and required route blocks are deterministic. Provider
callbacks, optional authentication, custom principal semantics, and business
resource authorization belong to AI review.

### JavaScript/TypeScript/TSX — Express

Current coverage reconstructs direct routes, prior mounted middleware, and one
exact handler hop, but it classifies some guards from names.

Keep deterministic route/group/order reconstruction and emit middleware names
as attachment facts. Classify authentication or authorization only for exact
owned implementations or canonical packages. Include one exact middleware
definition showing its rejection response, `return`, `next`, or `next('route')`
behavior. A local deny branch followed unconditionally by `next()` is a useful
explicit fail-open finding.

AI should decide whether a custom middleware verifies identity, checks a role
or resource, terminates on failure, and covers the reviewed route. Dynamic
router composition and application/gateway policy remain unresolved.

### JavaScript/TypeScript — NestJS

Current coverage understands controllers, routes, and `@UseGuards`, but guard
names are used to infer authentication or role restriction.

Add exact facts for:

- method and controller `@UseGuards` inheritance;
- global guards registered with `APP_GUARD` or `useGlobalGuards`;
- canonical Passport `AuthGuard(...)` attachment;
- metadata created through `SetMetadata` and used by exact route decorators;
- `@Roles`, permission/policy metadata values, and explicit public metadata;
  and
- the matching `CanActivate` definition and `Reflector` key.

`UseGuards(Foo)` proves attachment only. AI should interpret custom
`canActivate`, metadata composition, CASL/ability checks, and whether a global
guard honors a public override.

### JavaScript/TypeScript — Fastify

Current coverage extracts route-level `onRequest`, `preValidation`, and
`preHandler` hooks and plugin registrations.

Add inheritance facts for encapsulated plugins and prefixes, arrays of hooks,
canonical `@fastify/auth` composition and relation, and exact hook definitions.
Keep arbitrary hook semantics with AI. The engine can report a local hook that
sends a denial and then visibly continues to the handler.

### TypeScript/TSX — Next.js

Current coverage models middleware matcher coverage and some NextAuth token
guards. Add separate facts for Proxy/middleware, Route Handlers, Server
Actions, and data-access functions. A Proxy session check is an optimistic
boundary fact; it should not prove authorization at a data mutation or query.

Exact calls to a locally resolved `verifySession`/`auth` helper, literal role
rejection in a Route Handler or Server Action, and owner-scoped data predicates
are useful facts. AI should assess custom auth libraries, DAL helper bodies,
cache/session validity, and whether the resource query uses the authenticated
subject.

### JavaScript/TypeScript — Apollo Server and GraphQL resolvers

Apollo has no universal authorization annotation. Capture resolver identity,
context user/principal reads, directive names, plugin hooks, and local
`UNAUTHENTICATED`/`FORBIDDEN` rejection as facts. Custom directives, schema
transformers, context construction, field-level policy, and resolver-to-data
authorization remain AI work. Do not infer semantics from a directive named
`auth`.

### Python — Django and Django REST Framework

Current coverage understands `permission_classes`, several decorators, global
DRF defaults, and some owner-scoped resource access.

Add exact framework identity and facts for:

- Django `login_required`, `permission_required`, `user_passes_test`,
  `LoginRequiredMixin`, `PermissionRequiredMixin`, and literal permission names;
- DRF function, class, and action-level `permission_classes`;
- canonical `AllowAny`, `IsAuthenticated`, `IsAdminUser`,
  `DjangoModelPermissions`, and `DjangoObjectPermissions` semantics;
- overridden `get_permissions`, `get_queryset`, and `get_object` as bounded
  custom definitions;
- exact `check_object_permissions(request, obj)` calls after local object
  retrieval; and
- global `DEFAULT_PERMISSION_CLASSES`, including explicit `AllowAny`.

The engine can classify canonical permission classes and direct object checks.
AI should interpret custom `BasePermission`, action-dependent permissions,
queryset ownership, list/create limitations, and third-party object-permission
backends.

### Python — Flask

Current coverage recognizes route decorators and name-based login guards.
Require exact Flask-Login import ownership for `login_required` and
`fresh_login_required`. Record custom decorators as attachments and include one
exact definition. Add local facts for `current_user.is_authenticated`, literal
role/permission rejection, and Flask-Security decorators when their imports are
canonical.

AI should determine custom decorator behavior and resource ownership. A
template-only `current_user` check is presentation context, not server-side
authorization.

### Python — FastAPI

Add exact dependency facts for route, router, and application dependencies:

- `Depends` for authentication-shaped dependencies;
- `Security(dependency, scopes=[...])` with literal scope requirements;
- `APIRouter(..., dependencies=[...])` and `include_router` prefixes;
- exact `SecurityScopes` use and denial in the dependency definition; and
- authenticated subject fields used in owner/tenant query predicates.

Literal `Security(..., scopes=...)` proves a declared requirement. A generic
`Depends(foo)` proves only attachment. AI should inspect the dependency body,
sub-dependency chain, token validation, and resource policy.

### Go — net/http, Gin, Echo, Fiber, Chi, and Gorilla Mux

Current coverage reconstructs several routes and wrappers but relies on names
such as `RequireAuth` and `JWTMiddleware` for access classification.

Add exact route trees for global, group, and per-route middleware, including
registration order. Preserve custom middleware as attachment facts. Canonical
controls such as Gin `BasicAuth`, Echo JWT authentication, and exact Casbin
`Enforce` calls can receive stronger semantics. Include one exact middleware
definition showing reject/abort/return versus `Next`/`ServeHTTP` continuation.

AI should interpret custom middleware, context principal values, role checks,
and owner/tenant predicates. The engine can flag a locally obvious Gin denial
that calls `Next` without `Abort`/return, or an ignored Casbin result before an
operation.

### Rust — Axum, Actix Web, Warp, and Rocket

Current Actix route facts are always `unknown`; other identified Rust web
frameworks have little authorization context.

Add:

- Axum `.layer`/`.route_layer`, `from_fn`, and `from_extractor` attachment;
- Actix `App`/`scope`/`resource` `.wrap` inheritance and handler extractors;
- Warp filter composition facts around `and`, `or`, and rejection handlers;
- Rocket handler request-guard types and their exact `FromRequest`
  implementation; and
- one exact custom middleware/extractor/guard definition per review.

Framework attachment and handler type identity are deterministic. Custom Tower
layers, extractor rejection behavior, Warp combinator semantics beyond a
bounded chain, and resource authorization should remain AI work.

### PHP — Laravel

PHP currently lacks framework authorization context, making this one of the
largest gaps.

Add exact canonical facts for:

- route/controller `auth`, `auth:sanctum`, `can:ability,model`, and policy
  middleware;
- route groups and middleware inheritance;
- `Gate::authorize/allows/denies/check`, `$user->can/cannot`, controller
  `authorize`, and `authorizeResource`;
- policy registration/discovery context and exact policy method definitions;
  and
- subject/resource/action arguments near Eloquent reads or mutations.

Throwing `authorize` calls and canonical `can` middleware are strong controls.
Boolean gate calls are controls only when their result gates the operation. AI
should interpret policy methods, `Gate::before/after`, custom guards, implicit
model binding, and owner/tenant logic.

### PHP — Symfony

Add exact facts for controller `#[IsGranted]`, `denyAccessUnlessGranted`,
`Security::isGranted`, voters, and ordered `security.yaml` `access_control`
entries. `PUBLIC_ACCESS`, literal roles, route/path patterns, and first-match
order are deterministic configuration facts. Include the matching voter
definition for AI when a subject is supplied.

AI should interpret custom voters, expressions, firewall selection, role
hierarchies, and whether an `isGranted` boolean actually controls the operation.
An explicit catch-all `PUBLIC_ACCESS` is a strong configuration candidate when
the scope contains sensitive routes.

### C++ — Drogon and Crow

Drogon already has the strongest native authorization model: it links route
filters to locally verified credential decoders and keeps authentication
separate from resource authorization. Extend it to configuration-file routes
and middleware registrations while retaining the same proof standard.

For Crow, add exact route and blueprint middleware attachment plus global
middleware inventory. Include the relevant `before_handle` definition and
whether a denial ends the response before handler execution. AI should
interpret custom middleware and resource ownership. Never classify a C++
middleware by its type name alone.

### C

C has no dominant framework contract in the current framework index. Keep
authorization support library-specific: exact policy-engine calls, locally
proved owner/tenant predicates, or explicit route tables from a separately
supported framework. Generic comparisons, callbacks, and handler names should
remain AI context rather than authorization controls.

## AI skill contract

The security skill should use authorization facts to answer these questions in
order:

1. Is the reviewed operation attached to the supplied route or invocation
   boundary?
2. Is the attached fact authentication, coarse role/permission authorization,
   or resource-specific authorization?
3. Does a custom guard reject before the operation and stop execution?
4. Is the subject derived from verified server-side identity rather than a
   request field?
5. Does the checked resource/action match the object and operation under
   review?
6. Does an explicit public exception override an inherited or global rule?
7. Is activation or deployment ownership the only remaining decisive fact?

The skill may inspect one exact named guard, policy, dependency, voter, or
middleware definition when the bundle names it as unresolved. It should not
search for arbitrary nearby checks, infer behavior from names, treat client UI
conditions as server authorization, or turn missing local syntax into a
confirmed issue.

## Recommended implementation order

1. **Correct the shared semantics.** Add explicit-public/denied states and
   downgrade name-based custom guards to attachment facts.
2. **Complete canonical managed-framework facts.** ASP.NET Core, Spring
   Java/Kotlin, Django/DRF, NestJS, Express, and Fastify.
3. **Close the PHP gap.** Laravel and Symfony have common, highly structured
   authorization APIs and configuration with strong production value.
4. **Add dependency and middleware inheritance.** FastAPI, Flask, Go routers,
   Next.js DAL/route handlers, and Ktor.
5. **Add Rust route protection.** Axum, Actix, Rocket, and bounded Warp chains.
6. **Extend native framework facts.** Drogon configuration routes and Crow
   middleware.
7. **Leave custom policy meaning to AI.** Apollo directives, arbitrary DI,
   custom voters/guards/layers, dynamic route assembly, role hierarchies, and
   cross-service or gateway authorization should remain bounded review work.

This order first removes overclaimed controls, then covers the frameworks with
the strongest and most common declarative authorization shapes.

## Primary framework references

- [ASP.NET Core policy-based authorization](https://learn.microsoft.com/en-us/aspnet/core/security/authorization/policies)
- [Spring request authorization](https://docs.spring.io/spring-security/reference/servlet/authorization/authorize-http-requests.html)
- [Spring method security](https://docs.spring.io/spring-security/reference/servlet/authorization/method-security.html)
- [Ktor authentication and authorization](https://ktor.io/docs/server-auth.html)
- [NestJS authorization](https://docs.nestjs.com/security/authorization)
- [Express middleware](https://expressjs.com/en/guide/using-middleware.html)
- [Fastify hooks](https://fastify.dev/docs/latest/Reference/Hooks/)
- [Next.js authentication and authorization](https://nextjs.org/docs/app/guides/authentication)
- [Django authorization](https://docs.djangoproject.com/en/5.2/topics/auth/default/)
- [Django REST Framework permissions](https://www.django-rest-framework.org/api-guide/permissions/)
- [FastAPI OAuth2 scopes](https://fastapi.tiangolo.com/advanced/security/oauth2-scopes/)
- [Flask-Login view protection](https://flask-login.readthedocs.io/en/latest/)
- [Gin middleware](https://gin-gonic.com/en/docs/middleware/using-middleware/)
- [Axum middleware](https://docs.rs/axum/latest/axum/middleware/)
- [Actix Web middleware](https://actix.rs/docs/middleware/)
- [Rocket request guards](https://docs.rs/rocket/latest/rocket/request/trait.FromRequest.html)
- [Laravel authorization](https://laravel.com/docs/authorization)
- [Symfony security](https://symfony.com/doc/current/security.html)
- [Drogon middleware and filters](https://github.com/drogonframework/drogon/wiki/ENG-05-Middleware-and-Filter)
- [Crow middleware](https://crowcpp.org/master/guides/middleware/)
