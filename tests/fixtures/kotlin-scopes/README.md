# Kotlin standard scope context

Original Ktor/JVM teaching controls. Standard `let`, `also` and an imported
`let` alias bind request-selected scalar text to the lambda's process call.
The fixed-result chain discards the request value. A same-named member on
`Other` does not acquire standard-library semantics.

Compile with Kotlin 2.4.10, JDK 17 and Ktor server core 3.6.0. Evidence provides
the exact standard scope call and its containing function for source review.
It does not assert native lambda/caller propagation or unknown helper effects;
the lookalike's supplied implementation is separately ordinary source context.
