# PHP native coverage

This profile is included starting with 0.3.0; it is absent from 0.2.1 binaries.

PHP support is partial. The scanner parses PHP and mixed HTML/PHP in `.php`,
`.phtml`, `.php5`, `.php7`, and `.php8` files without running PHP or Composer.
The ordinary test, generated-file, and vendor exclusion policy applies.

The profile recognizes reads from `$_GET`, `$_POST`, `$_REQUEST`,
`$_COOKIE`, and `$_FILES`, and exact native command, mysqli query, HTML output,
filesystem, deserialization, and dynamic-code APIs. PDO methods require a
visible local construction, an exact parameter type, or one mandatory
`__DIR__`-anchored include of a conservative native connection config.
The include target must be discovered within the scan root; arbitrary helpers,
additional includes, receiver replacement and uncertain config execution are
excluded. Bare relative includes still have unresolved cwd/include-path semantics.
Explicit global names
and supported imports preserve API identity; local lookalikes, unknown
namespaced fallbacks, and unknown receivers are excluded.

Native `json_decode` fields from `php://input` are request sources with either
a direct native read or one preceding raw-body binding. Associative array
fields and static object properties require the matching decoder mode and one
unconditional same-owner binding
and no intervening replacement, field writes, references or helper mutation.
Local JSON files, dynamic properties, aliases and framework body readers are
outside this summary. Each field retains its exact decoder and, for split
reads, its raw-body producer in evidence. Unknown helper mutation stops provenance.

Relationships are bounded to direct inputs and same-function local aliases,
concatenation, interpolation, raw conditional value arms and `.=` accumulation.
`echo` and `print` are output boundaries. Numeric augmented assignments do not
preserve attacker-selected text. Same-arm `if`/`try` handoffs remain uncertain
review candidates; loops and unresolved branch joins are excluded. Reassignment,
arbitrary helper transformations, dynamic call targets and unknown includes
stop propagation. An unlinked sink is a review lead, not proof
of a vulnerability.

Controls remain facts for review. `prepare` does not protect interpolated SQL;
HTML encoding needs the correct output context; `realpath` does not establish
containment; shell argument quoting does not authorize a command. The engine
does not automatically mark PHP HTML encoding or path normalization as
protection. Literal placeholder queries are distinguished from dynamic SQL.
One same-owner native PDO `prepare` with literal SQL can establish statement
ownership for separately supplied `execute` values. Interpolated preparation,
unknown receivers, statement replacement and helper mutation never establish
parameter protection. Separate `bindParam`/`bindValue` state is not summarized.

Native cURL requests retain the URL from one local `curl_init`, including
unconditional same-handle `CURLOPT_URL` replacement and a small explicit option
allowlist. Unknown option arrays, dynamic option names, helpers, references,
namespaced option identities and branch-dependent configuration are excluded.
Peer/hostname verification options are TLS configuration inventory, including
enabled and disabled siblings. Their presence alone does not prove an HTTPS
request executes or that a later option change leaves verification disabled.

Named or unpacked call arguments, group imports, framework APIs,
general cross-file receiver provenance, persistence/stored-output summaries, JWT libraries,
heredoc flow, `.inc` files, and deployment controls are outside this initial
profile. Native evidence does not establish Laravel, Symfony, or WordPress
coverage. Secret detection remains a separate opt-in stream.

Original regression fixtures cover positive and safe calls, API identity,
imports, receiver ownership, reassignment, branch controls, mixed capabilities,
inert comments/strings, templates, repeated IDs, and repository policy.
