# Kotlin JDBC static controls

Original source controls for exact JDBC ownership and SQL/value separation.
They are parsed by Mehscan and are not a runnable server or a deployed-app
assessment. Import aliases resolve to canonical Statement and Connection types.

Independent source labels:

| Method | Label | Reason |
| --- | --- | --- |
| rawStatement | issue | Request String changes SQL passed to executeQuery. |
| fixedStatement | not_issue | Query resolves to the class's fixed companion const, not the request value. |
| rawPrepared | issue | Request String changes SQL before preparation and the statement is then executed. |
| boundPrepared | not_issue | Fixed SQL contains a placeholder; setString supplies data separately. |

The prepared query boundary captures SQL text, not the bound value. Preparation
alone does not prove subsequent execution or runtime data access. The fixed
constant's definition must be supplied from this class, never borrowed from an
unrelated class or from a shadowed declaration.
