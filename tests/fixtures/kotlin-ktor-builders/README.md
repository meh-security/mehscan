# Kotlin Ktor client-builder controls

Original Ktor 3.6.0 teaching source. Canonical `HttpClient(CIO)` factories and
request-builder calls must remain owned request leads. `rawFactory` and
`rawBuilder` send the request-selected destination without approval.
`replacedBuilder` replaces the initial query value with a separate supplied
parameter: the initial request value does not establish the final destination,
and the parameter name does not certify its safety. `fixedBuilder` uses a fixed
destination and ignores the query value.

Compile with Kotlin 2.4.10, JDK 17, Ktor client/server core 3.6.0 and CIO plus
their dependencies. These helpers do not establish deployed route registration.
The fixed port is not contacted by the runtime harness. Request-builder effects
are supplied source-review context; no native final-URL propagation is claimed.
