# SQL query review

Review the selected query and its effect, not every database call in the file.
Bind the actual database API/import, complete query construction and executed
statement. A prepared statement created elsewhere does not protect this query.

1. Separate fixed grammar, bound values and dynamic identifiers/fragments.
   Parameter binding protects the bound value positions; it does not bind a
   table name or raw expression assembled before preparation.
2. Inspect the exact producer or complete control. A closed enum mapped to fixed
   SQL identifiers can settle that selection. An arbitrary string, quoting helper
   name or unrelated validator does not. Numeric typing must hold at runtime or
   through an inspected conversion, not just a request-interface declaration.
3. For wrappers, follow the actual import/receiver and consequential caller.
   Fixed calls do not prove all callers safe. Do not enumerate the whole program
   once the selected argument/control relationship is settled.
4. Distinguish unsafe construction from established attacker reachability and
   effect. Use the interpreted-input policy for source-established unsafe SQL
   construction with unresolved exposure; never inflate it into demonstrated
   remote database compromise.

Bound-value examples are clean for SQL grammar, while ownership or mass assignment
may remain separate questions. A safely parameterized update that changes another
tenant's record is an authorization concern, not SQL injection. Preserve that
distinct lead under its own ID or source-lead channel.

Finish with the query-building expression, decisive binding/control, exposure
conditions and actual selected effect. If the only missing fact is a local helper
body, request it rather than calling the database contract unknown.
