# Kotlin named-parameter JDBC controls

Original Spring named-parameter fixture with DataSource/JdbcOperations
construction, a declared NamedParameterJdbcOperations receiver and an executed
prepared-statement callback. Named-parameter support does not repair text already
interpolated into SQL. Fixed SQL with map or SqlParameterSource binding keeps
request input as data. Private controls use only owned H2 dummy records; no
deployed Spring dispatch or production-data access is claimed.
