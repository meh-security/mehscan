# Kotlin Exposed JDBC SQL controls

Original Exposed v1 JDBC fixture for implicit transaction SQL, imported
transaction aliases, immutable current-transaction aliases and declared
JdbcTransaction receivers. Fixed SQL and typed bound arguments are negative
SQL-injection controls. Exposed transaction entry does not sanitize raw SQL.
The private harness compiles against Exposed 1.5.0 and uses its own in-memory
H2 database and dummy records. No deployed route or production-data claim is made.
Legacy Exposed packages and R2DBC APIs require separate ownership coverage.
