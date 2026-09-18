# JDBC factory controls

Original Spring source controls for immutable local JDBC receiver inference.
The raw Statement and raw prepared-SQL routes interpolate request text; the
fixed Statement and separately bound prepared route keep query syntax fixed.
A lookalike connection/statement returns a constant and performs no JDBC call.

These are deliberately vulnerable test handlers, not a deployed application.

The files compile with Kotlin 2.4.10/JDK 17. Nine direct H2 checks exercise benign
predicate injection, fixed-query behavior, bound-value behavior, normal selection,
quote handling and the constant lookalike. No HTTP server was deployed.
