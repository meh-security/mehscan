# PHP native coverage

This development profile is not included in published 0.2.0 binaries.

PHP support is partial. The scanner parses PHP and mixed HTML/PHP in `.php`,
`.phtml`, `.php5`, `.php7`, and `.php8` files without running PHP or Composer.
The ordinary test, generated-file, and vendor exclusion policy applies.

The initial profile recognizes reads from `$_GET`, `$_POST`, `$_REQUEST`,
`$_COOKIE`, and `$_FILES`, and exact native command, mysqli query, HTML output,
filesystem, deserialization, and dynamic-code APIs. PDO methods require a
visible local construction or an exact parameter type. Explicit global names
and supported imports preserve API identity; local lookalikes, unknown
namespaced fallbacks, and unknown receivers are excluded.

Relationships are bounded to direct inputs and same-function local aliases,
concatenation, and interpolation. Reassignment, arbitrary helper calls,
cross-file includes, fields, dynamic call targets, and uncertain branch flow
stop deterministic propagation. An unlinked sink is a review lead, not proof
of a vulnerability.

Controls remain facts for review. `prepare` does not protect interpolated SQL;
HTML encoding needs the correct output context; `realpath` does not establish
containment; shell argument quoting does not authorize a command. The engine
does not automatically mark PHP HTML encoding or path normalization as
protection. Literal placeholder queries are distinguished from dynamic SQL.

Named or unpacked call arguments, group imports, framework APIs,
cross-file receiver provenance, stored HTML accumulation, JWT libraries,
heredoc flow, `.inc` files, and deployment controls are outside this initial
profile. Native evidence does not establish Laravel, Symfony, or WordPress
coverage. Secret detection remains a separate opt-in stream.

Original regression fixtures cover positive and safe calls, API identity,
imports, receiver ownership, reassignment, branch controls, mixed capabilities,
inert comments/strings, templates, repeated IDs, and repository policy.
