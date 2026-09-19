# Extended database rules: SQL and NoSQL coverage

This gap analysis covers all 12 supported language profiles. It compares query
mechanics with the embedded rule catalog **and** procedural analyzers; a method
missing from YAML is not necessarily missing from a scan. All coverage remains
partial. An observed boundary is a review lead, not a confirmed injection.

SQL text and raw clauses use CWE-89. Operator-capable NoSQL filters, pipelines,
raw document queries and executable predicates use CWE-943. Query preparation
does not sanitize interpolated query text. Separately bound values, typed scalar
equality selectors and fixed documents are not injection proof.

## Language gap matrix

| Language | Existing SQL / NoSQL mechanics | Gaps addressed by extended rules | Remaining identity / mechanic limits |
| --- | --- | --- | --- |
| C | SQLite execution and preparation; no embedded MongoDB client filter rule | PostgreSQL libpq, MySQL and ODBC query-text positions; MongoDB C client read, delete, update and aggregate filter positions | Client wrappers, function pointers and no compiler/linker identity resolution |
| C++ | SQLite; no typed MongoDB collection filter rule | PostgreSQL/MySQL/ODBC native APIs, MongoDB C APIs and declared `mongocxx::collection` filters | Qt database adapters, inferred collection factories and cross-file aliases |
| C# | SqlCommand, typed CommandText assignments, EF/EF Core raw SQL and typed Dapper calls | Typed object-initializer CommandText, data-adapter and batch-command query text, broader Dapper terminal APIs, dynamic SQL composition facts, additional provider commands and declared MongoDB collection filters | Composition follows direct expressions and bounded same-callable aliases; indirect command factories, arbitrary builders, inferred MongoDB factories and generic type aliases are not universal |
| Java | JDBC query/preparation, typed Spring JDBC and JPA queries/binding | JDBC execute overloads, large updates, batch text and callable preparation; declared Hibernate/JDO/Vert.x query receivers; MongoDB collection filters and raw document/query construction | Turbine/Torque peers, arbitrary JDO overload dispatch, Hibernate sqlRestriction, mutable BSON put/append assembly, inferred asynchronous factories, cross-file receiver factories |
| Kotlin | Typed JDBC, Spring JDBC, JPA and canonical Exposed SQL strings | JDBC large updates, declared Hibernate/JDO/Vert.x query receivers, typed MongoDB filters and raw document/query construction | Callback/overload dispatch, extension functions, inferred SDK factories and compiler effects across lambdas |
| JavaScript | Conventional SQL receivers, driver-specific MySQL/PostgreSQL handling, MongoDB predicates/operator selectors and project summaries | Imported Knex raw clauses, SQLite methods, mssql requests, broader SQL execute/unsafe entrypoints; proven MongoDB filters/pipelines; DynamoDB v2 query requests and v3 query-command construction | Sequelize literal expression construction, arbitrary dependency injection, wrapper modules, unresolved collection aliases, computed methods and dynamic SDK dispatch |
| TypeScript | Node SQL/NoSQL analyzers and conventional SQL receivers | Same extended Node mechanics, including imported constructors, aliases and namespace imports | Type-only imported interfaces and injected/inferred fields are not general receiver proof |
| TSX | Node SQL/NoSQL analyzers in parsed TSX | Same extended Node mechanics | Same bounded Node receiver inference; JSX/framework dispatch does not establish a database identity |
| Python | DB-API execute methods, framework-specific SQLAlchemy observations; no general imported MongoDB filter rule | Renamed DB-API producers and class connection properties; DB-API stored-procedure selection; asyncpg fetch/prepare, additional native/async driver imports, SQLAlchemy Session/text/driver SQL; Django RawSQL and locally declared model-manager raw queries; PyMongo/Motor filters and DynamoDB expressions | Imported application model definitions, Django extra/custom expressions, arbitrary async context managers, injected connection types and wrapper factories |
| PHP | Native mysqli/PDO calls, typed native parameters and bounded include-based connections | Unique same-class constructor connection properties; native PostgreSQL functions; Laravel SQL facade and raw builder clauses, declared Doctrine query/builder receivers; MongoDB Driver Query construction | Dynamic/untyped properties, connection promotion and arbitrary includes; untyped WordPress bootstrap globals, generic Laravel validators, dynamic builder identifiers and joins, injected SDK properties and wrapper factories |
| Go | database/sql query methods, dynamic preparation, GORM v1, MongoDB filters/writes and project summaries | QueryRow and preparation siblings; typed pgx context/name/query positions and sqlx destination/query positions; GORM v2 imports and additional raw clauses; MongoDB v2 imports, delete/aggregate and mutation filters | Inferred pgx/sqlx factories, legacy pg/pgx Ex overloads and go-pg ORM builders; GORM/MongoDB analyzers retain existing file-import gates rather than compiler dispatch |
| Rust | Canonical SQLx/Diesel functions and locally constructed postgres clients | PostgreSQL simple/batch text, SQLx query-with-bindings functions, declared rusqlite/tokio-postgres/MySQL client text APIs, declared MongoDB collection filters | Destructured async client factories, inferred MongoDB collections, macros and compiler-resolved trait dispatch |

## Mechanics assessed

The SQL inventory includes ADO.NET/EF, JDBC, JPA, Spring JDBC, Hibernate, JDO,
Vert.x, legacy peer APIs, Node MySQL/PostgreSQL/mssql/Knex/Sequelize/Prisma/SQLite,
Python DB-API and asynchronous drivers, Django and SQLAlchemy, PHP native
drivers/Doctrine/Laravel/WordPress, Go database/sql/pgx/sqlx/GORM/go-pg,
Rust SQLx/Diesel/PostgreSQL/rusqlite/MySQL and native C client APIs.

The NoSQL inventory includes MongoDB executable `$where` values, whole filters,
mutation selectors and aggregation pipelines; raw BSON/JSON query construction;
and DynamoDB legacy filter maps, condition/filter expressions, whole requests
and query-command construction. A scalar value used in a typed equality
selector differs from an attacker-selected operator/document. DynamoDB
`ExpressionAttributeValues` differs from its expression text.

The matrix records unimplemented boundaries explicitly. Redis keys, generic
JSON decoding, arbitrary SQL-looking strings, and arbitrary same-name methods
are not added as injection sinks without an applicable query-language role.
This is not a claim of exhaustive database-driver or backend coverage.

## Identity and argument checks

- New broad Node/Python method names require a recognized imported producer,
  bounded aliases and visible construction. Reassignment, local shadows and
  unrelated receivers are excluded. Existing conventional SQL receivers remain
  compatible with earlier scans.
- New Java `execute`, `addBatch` and large-update matches require a JDBC Statement
  type or a proven Connection statement factory. New JVM ORM and MongoDB matches
  use declared SDK receiver ownership.
- PHP constructor connection fields require one unconditional assignment in the
  constructor of the same lexical class. Native typed parameters and typed SDK
  parameters exclude receiver replacement and unknown prior helper mutation.
- C# project summaries may add caller context when exact syntactic targets are
  already cheap and unambiguous. Sink admission and AI review do not depend on
  these summaries or on a fixed number of caller hops.
- SQL sinks in every supported language classify direct interpolation,
  concatenation, formatting, and bounded same-callable aliases independently
  of repository handoff recognition. Nonliteral operands at recognized raw
  query boundaries remain decision-critical even when local composition or
  origin cannot be resolved. C# additionally identifies integral,
  Boolean and `Guid` parameters as constrained representations. Separately
  bound query values are not labeled as dynamic SQL composition.
- Review context may include a small exact-caller excerpt as optional
  enrichment. Missing caller context never suppresses a strong typed sink, and
  the scanner does not claim a CFG or whole-program source-to-sink flow.
- pgx SQL follows its context argument; pgx Prepare SQL follows context and
  statement name. sqlx Get/Select SQL follows the destination. These operands
  are not interchangeable with database/sql argument positions.
- Inline DynamoDB requests capture expression text rather than bound attribute
  values. Variable requests and spreads remain whole-request review leads.
- Proven Node NoSQL query boundaries can attach whole `req.body`/`req.query`
  reads from the same conventional request-parameter scope. Bounded local
  value relationships must still connect those reads to the captured filter.
- Existing specialized NoSQL predicate/operator evidence takes precedence over
  overlapping whole-filter extensions. Exact SDK matches replace overlapping
  generic query captures.

Raw document construction needs verification of a downstream query consumer.
Typed collection filters need verification of operator-capable request data.
Neither BSON parsing nor a collection call alone establishes an issue.

## Validation and API references

`database_query_mechanics.rs` covers the originally reported JDBC/PHP misses,
SQL argument roles across every language, property identity and lookalikes.
`extended_database.rs` covers NoSQL operands across every language, additional
SQL drivers, DynamoDB binding roles, imported-name shadows and PHP builders.
Catalog checks require provenance and retain partial coverage declarations.

Implementations and guidance are independently authored. Each embedded extended
rule links to driver documentation and its applicable CWE. Examples:
[JDBC Statement](https://docs.oracle.com/en/java/javase/25/docs/api/java.sql/java/sql/Statement.html),
[Knex raw bindings](https://knexjs.org/guide/raw),
[MongoDB query safety](https://www.mongodb.com/docs/drivers/client-libraries-best-practices/),
[DynamoDB expressions](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/Expressions.html),
[pgx](https://pkg.go.dev/github.com/jackc/pgx/v5),
and [PHP MongoDB query filters](https://www.php.net/manual/en/mongodb-driver-query.construct.php).
