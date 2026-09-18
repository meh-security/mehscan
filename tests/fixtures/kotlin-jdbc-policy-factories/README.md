# Kotlin JDBC factory controls

Original scalar-input Spring fixture for JdbcTemplate construction, pooled/XA
connection ownership and three/four-argument preparation. Dynamic SQL must be
executed to establish query impact; bound values do not change the fixed query
syntax. The unexecuted preparation is an inapplicability control for runtime
query-impact claims, not a general recommendation to construct dynamic SQL.
Private direct-call controls use an owned in-memory H2 database and two dummy
records. No deployed endpoint or production-data claim is made.
