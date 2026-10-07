# PHP native coverage

This profile is included starting with 0.3.0; it is absent from 0.2.1 binaries.

PHP support is partial. The scanner parses PHP and mixed HTML/PHP in `.php`,
`.phtml`, `.php5`, `.php7`, and `.php8` files without running PHP or Composer.
The ordinary test, generated-file, and vendor exclusion policy applies.

The [extended database rules](extended-database-coverage.md) also cover bounded
constructor connection properties, PostgreSQL query text, Laravel/Doctrine raw
query entrypoints and MongoDB Driver query construction. Unknown property and
wrapper identities remain gaps.

Review inventories also expose bounded operand facts for compound includes
and whole-operand output encoding calls. `__DIR__` and exact native
`dirname(__FILE__)` plus literal string suffixes produce a lexically normalized
repository-relative target. Configured constants retain an unresolved root.
Dynamic suffixes, interpolation, stream syntax, and paths escaping the source
root do not receive a fixed-path fact. Target existence, filesystem aliases,
and content trust remain separate checks.
Scalar coercion, escaped strings, and opaque suffix bindings remain unresolved
rather than inheriting another language's literal semantics.

An `encoding_call` fact identifies an exact outer output call, including
observed WordPress helpers. It does not establish callable behavior, filter
semantics, encoding options, or output context. Concatenation and conditional
output do not inherit this fact from a nested call. These facts are currently
shadow evidence: they change queue navigation and cards, not review admission
or protected-path decisions. Other languages retain their existing analysis;
the fact contract is language-independent.

Value inventory selection can defer a sink-only fixed code-relative include
of an existing repository PHP file under a trusted-source assumption.
Runtime/generated directories and observed writes naming the target veto this
hint. Unknown writers and deployment changes remain possible: this is a
`value_hint`, not a safety proof. `review-inventory-list --selection value`
omits these IDs with visible counts; `--selection deferred` shows their reasons
and `--selection all` retains them for Comprehensive review. The target file's
own findings remain eligible, and encoding-call names alone never qualify.

Structural follow-ups accept a single PHP code construct, with or without a
PHP opening tag; the query adapter supplies the mixed-grammar parse context.
Multiple statements are rejected rather than silently narrowed. C/C++, PHP
and Rust language selectors are available alongside the other scanner languages.

Complete native integer/boolean casts and exact native `intval`, `strlen`,
`count`, or `sizeof` output produce a `numeric_output` proof. Only the exact
CWE-79 output review is closed; raw evidence, candidates, nested command/file
operations, and other independent reviews remain available. Concatenation,
multiple echo operands, conditional raw branches, string casts, unknown
namespaces, overrides, named arguments and unpacking do not inherit this proof.
The inventory's admission audit records every closed anchor and operand location.
This relies on PHP's [integer conversion](https://www.php.net/manual/en/language.types.integer.php)
and [string conversion](https://www.php.net/manual/en/language.types.string.php)
contracts, not absence of a request source.

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

## Value review scope

Value keeps every admitted ID in the inventory. Existing repository-code
includes can be deferred under an explicit trusted-source assumption. Bounded
source constants, concatenation and native `dirname` can supply a default
target; conflicting or dynamic definitions, missing targets, observed writers
and runtime/upload/generated paths prevent this deferral. Runtime overrides
remain a review assumption.

Static context facts also cover plain raw output, so observed script/event
positions remain active even when no encoder is called.
Repeated whole encoding calls in matching ordinary static template contexts
can share an active implementation question. Their dependent IDs remain
conditional, with no safety verdict. Reviewing the shared callable as unsafe
or unresolved reopens its dependents through the review ledger. Unknown
bindings, URL/script/style/event/srcdoc and unquoted contexts, raw/mixed/stored
outputs with connected input, explicit markup construction and source-bearing
groups remain active. Unconnected ordinary output/constant-shaped loading
occurrences become conditional surface inventory. Inspect actual producers,
including stored data, before selecting distinct consequential relationships;
missing source provenance is not proof of trusted input. Unsafe or unresolved
same-file/rule verdicts reopen these ordinary occurrences through the ledger.
Every shared encoding site's options
and runtime context still need an applicability check. Comprehensive selects
all admitted IDs; Value can expand to it when evidence warrants that scope.

These are generic PHP source/template facts. A helper spelling never proves
its implementation safe. They do not add framework SQL coverage or close
fixed-path file-disclosure questions.
