# Prepared receiver ownership controls

Original source controls for exact immutable-local statement ownership.
The raw routes execute request-interpolated SQL. Binding a different object does
not protect the raw query. The bound route resets and then binds its own values.
The preparation-only route closes fixed SQL without executing it. Conditional
execution remains conditional source context, not guaranteed runtime behavior.

These are test handlers, not a deployed application.

The source compiles with Kotlin 2.4.10/JDK 17. Eight direct H2 checks cover benign
predicate injection, bound values after reset, valid selection, quote handling,
both conditional branches and successful preparation-only closure. No HTTP
server was deployed.
