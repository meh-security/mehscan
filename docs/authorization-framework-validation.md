# Authorization framework validation

This validation uses pinned public application repositories to test whether
authorization review receives the facts needed to decide real operations. The
repositories are manual evaluation inputs rather than network-dependent test
fixtures.

## Corpus

| Framework | Repository | Revision | Reviewed operation |
| --- | --- | --- | --- |
| Ktor | [nomisRev/ktor-full-stack-real-world](https://github.com/nomisRev/ktor-full-stack-real-world) | `af76ae678a02adc0710a8043e682569647e683ee` | Update and delete an article by slug |
| NestJS | [lujakob/nestjs-realworld-example-app](https://github.com/lujakob/nestjs-realworld-example-app) | `c1c2cc4e448b279ff083272df1ac50d20c3304fa` | Update and delete an article by slug |
| Fastify | [fastify/demo](https://github.com/fastify/demo) | `5cd560125b3c2f0d42192bc7f493e8e3b9e75e52` | Update a task by ID |
| Next.js | [nextjs/saas-starter](https://github.com/nextjs/saas-starter) | `6e33e58b1e553a41fe22e6b941a7229a002de361` | Remove a team member and issue team invitations |
| Apollo GraphQL | [apollographql/fullstack-tutorial](https://github.com/apollographql/fullstack-tutorial) | `fca98dec747244a6cd08e3611f826db01617e208` | Cancel a trip |
| Gin | [gothinkster/golang-gin-realworld-example-app](https://github.com/gothinkster/golang-gin-realworld-example-app) | `626c372d259472148d93303f74aa9b9a1cdcef24` | Update and delete an article by slug |
| Axum | [launchbadge/realworld-axum-sqlx](https://github.com/launchbadge/realworld-axum-sqlx) | `f1b25654773228297e35c292f357d33b7121a101` | Update and delete an article by slug |
| Symfony | [symfony/demo](https://github.com/symfony/demo) | `8d2e2ef75c3e18df173d8bf2379a14abb58c4c31` | Show, edit, and delete an admin post |

Each case has an exact server boundary, a sensitive read or mutation, and local
authentication or resource-policy code. This makes the corpus suitable for
testing the operation matrix rather than only framework identification.

## Bundle results

The current release build scanned production source with the default review
material policy.

| Framework | Authorization/resource evidence | Generated authorization-relevant review | Result |
| --- | --- | --- | --- |
| Ktor | None | None | Missed authenticated route nesting and owner-scoped repository mutations. |
| NestJS | One Sequelize resource observation; no authorization evidence | One resource review for article creation | The review was correctly dismissed, but update/delete were missed. |
| Fastify | Two route `preHandler` observations; no resource evidence | None | Attachments were detected but not joined to task mutations. |
| Next.js | None | None | Server Actions, their authentication wrapper, team scope, and role-sensitive mutations were missed. |
| Apollo GraphQL | One Sequelize resource observation; no authorization evidence | One owner-scoped cancellation review | Both models correctly dismissed the supplied owner-scoped filter, but the forgeable context identity was absent. |
| Gin | Four resource summaries; no authorization evidence | Four listing/serialization reviews | Both models correctly dismissed the supplied cases, but protected update/delete operations were missed. |
| Axum | None | None | Auth extractors and owner-scoped SQL mutations were missed. |
| Symfony | None | None | Controller attributes, voter checks, and Doctrine mutations were missed. |

All six Luna and Terra responses for the three generated resource bundles passed
`review-bundle-triage` validation. They agreed on every supplied review. The
reviews themselves did not represent the important authorization operations in
the applications.

## Bounded source results

To separate skill quality from bundle coverage, Luna and Terra reviewed the same
eight operations with the named route, policy, and mutation files available.

| Framework | Luna | Terra | Source assessment |
| --- | --- | --- | --- |
| Ktor | `not_issue` | `not_issue` | Authentication and author ID are applied before update/delete. |
| NestJS | `issue` | `issue` | Authentication is present, but update/delete select only by caller-controlled slug. |
| Fastify | `issue` | `issue` | Any authenticated user can patch a task selected only by ID. |
| Next.js | `issue` | `issue` | The wrapper proves identity, but ordinary members can remove members or invite an owner. |
| Apollo GraphQL | `issue` | `issue` | The owner filter uses `context.user`, but that identity is derived from an unsigned base64 email header. |
| Gin | `issue` | `not_issue` | Luna treated deletion after a failed preliminary lookup as fail-open; Terra treated the not-found case as an idempotent no-op. The branch needs error-classification evidence before a security verdict. |
| Axum | `not_issue` | `not_issue` | The authenticated subject is checked in the update and delete predicates. |
| Symfony | `not_issue` | `not_issue` | Class role policy and the post voter protect the same selected post. |

The framework-neutral operation matrix and framework sections produce useful,
specific decisions when controlling code is present. Seven of eight cases had
stable model agreement. The Gin disagreement is appropriately narrow and shows
that a bundle should preserve whether a lookup error means absence, a database
failure, or another condition before asking AI to judge a subsequent mutation.

## Coverage priorities

1. Admit exact server mutations as authorization reviews when the handler has a
   caller-selected resource key and a database update/delete or privilege
   assignment. This is the common cross-framework baseline.
2. Attach already-detected route policy, authenticated subject, selected
   resource, and local mutation predicate to the same operation. Fastify shows
   that attachment evidence without a sensitive operation is not useful.
3. Add small framework extractors for boundaries the common baseline cannot
   identify reliably: Next.js Server Actions, GraphQL resolver fields, Ktor
   typed resources, Axum handler extractors, and Symfony controller attributes.
4. Preserve exact authentication producer details when resource authorization
   relies on its subject. Apollo demonstrates that an owner predicate does not
   compensate for a forgeable identity.
5. Preserve error branches around lookup-then-mutate sequences without deciding
   their meaning. AI can then distinguish not-found behavior from a possible
   fail-open mutation using the supplied API contract or local error match.

These additions remain bounded syntax and local context. They do not require a
CFG, call graph, dependency-injection resolution, or general interprocedural
data flow.

## Review-admission follow-up

The bounded review-admission implementation was run against the same pinned
corpus. It now admits the previously invisible server mutations without
requiring a database sink or resolved repository call.

| Framework | Authorization markers | Other marker families |
| --- | ---: | ---: |
| Ktor | 8 | 0 |
| NestJS | 10 | 0 |
| Fastify | 6 | 1 credential-lifecycle |
| Next.js | 6 | 1 credential-lifecycle |
| Apollo GraphQL | 1 | 0 |
| Gin | 11 | 0 |
| Axum | 2 | 0 |
| Symfony | 4 | 1 credential-lifecycle |

The marker supplies the exact route or resolver operation and bounded named
helper definitions; it does not claim a missing control. On the Fastify
password-change review, both Luna and Terra used the supplied route, request
schema, and exact repository helper to identify the enforced current-password
check and returned `not_issue`. Both responses passed
`review-bundle-triage`. Generic helper words such as `update` are excluded from
cross-file lookup, so this bundle has no unrelated helper facts or truncation.
