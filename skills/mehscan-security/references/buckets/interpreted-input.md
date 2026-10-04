# Interpreted input

Trace the exact value consumed by the interpreter: **sink operand → how it
was built → who can supply it → same-path constraint**. Decide whether a
lower-trust actor can change grammar or a dangerous target, not merely a
scalar value.

Check a plausible complete control before tracing every producer or caller.
When its verified contract keeps the exact interpreter grammar safe for any
input in this context, that settles this property. Do not keep researching
input origins just to establish that the control is needed. For escaped HTML,
check the entire operand, callable behavior/options/hooks, actual text or
attribute context and any transformation after escaping. Trace producers when
the control is absent, partial, incompatible or uncertain, or when intentional
raw/rich content needs a trust policy. Independent disclosure or access checks
retain their own questions.
Follow a local control wrapper to the transformation that establishes its
behavior once per shared contract. Flags passed to another unchecked helper
do not establish what that helper returns.
Quoted attributes can still interpret URLs, JavaScript events or CSS; verify
that interpretation before treating HTML escaping as a complete control.
For URL controls, check the consumer's effective scheme after whitespace,
control-character and entity handling. A server-side parser's scheme result
alone does not establish what a browser will execute.

- **SQL:** A raw-query API or nonliteral `sql` parameter is an inventory
  point. If it is a wrapper, find the wrapper's callers and inspect every
  relevant argument. Fixed query text with bound values differs from text
  concatenation. Search the actual identifier used at call sites and treat
  text references as leads; check whether aliases, dynamic dispatch, or an
  exposed wrapper leave a caller outside that inventory. When an application
  operation that should treat input as a value shows a variable inserted into
  executable SQL grammar without binding, report the
  unsafe construction as `issue` even if runtime or attacker reachability
  remains unproved after targeted checks. Use `low` confidence for that
  uncertainty and say explicitly that exploitation is unproved; recommend
  parameterization. Do not claim an exploitable SQL injection path without
  evidence of the caller and input. A raw-query API alone, a fixed SQL template
  with bound values, or a branch proved non-executable does not meet this rule.
  Missing HTTP route registration lowers exposure confidence; it does not make
  variable-built SQL safe if the method itself can execute when called.
  JVM `prepared_statement_use` facts locate uses of that exact local
  preparation. Check query construction separately from its bindings; another
  statement's bindings do not apply. Read source for conditions, resets and
  execution order. Missing use facts do not prove the statement is unused.
- **Command or executable:** Separate a fixed executable from its arguments.
  A command-line option proves the program accepts a value; inspect who
  controls the invocation before calling it attacker-controlled. In-repository
  callers that pass a fixed value do not cover direct or external invocations
  of a CLI entrypoint. If the executable still comes from an option and the
  invocation authority is unknown, name that missing fact in `needs_review`;
  do not close it as safe from the observed callers alone. Check shell
  interpretation separately from direct process launch. If an application
  operation that should treat input as data assembles an unconstrained variable
  into shell command text, report that construction as `issue` with `low`
  confidence when runtime activation remains unknown. State that attacker
  control and exploitation are unproved. If the variable is solely an option
  for an intentional CLI command runner and invocation authority is unknown,
  use `needs_review` instead. Fixed executable plus separate arguments does
  not meet this shell-construction rule.
  Python shell-option facts describe a keyword or bounded local dictionary;
  inspect an `operand_boundary` when reuse stops. `shell=False` does not rule
  out an explicit interpreter such as `sh -c`. With `shell=True`, argument
  sequences differ by platform: on POSIX, the first item is script text and
  later items are shell positional arguments. Use `posix_shell_command` only
  after verifying that runtime; check quoting inside the script and any
  replacement executable. [Python subprocess contract](https://docs.python.org/3/library/subprocess.html#subprocess.Popen).
- **Code evaluation:** If an unconstrained variable becomes code passed to
  `eval`, script compilation, or an equivalent evaluator in an application
  operation that should treat input as data, report the unsafe construction as
  `issue` with `low` confidence when its caller or activation is unknown. If
  the code operand is solely an intentional CLI evaluator option and invocation
  authority is unknown, use `needs_review` instead. Identify the exact code
  operand and evaluator; do not infer attacker control or claim remote code
  execution without its input path.
  Fixed approved scripts and an effective same-path allowlist do not meet this
  rule.
- **BSON or structured query:** Determine whether request input controls
  keys/operators or only a value under a fixed key. Follow the exact decoded
  type, any preparation method, and filter passed to the database. If a
  reference identifies their common model file, read the declaration and
  helper together within one bounded source window. When a lower-trust object
  reaches an unconstrained selector position but the dependency's operator
  behavior is unavailable, keep the unsafe construction as a lower-confidence
  `issue` and name the unproved interpretation. Use high confidence for an
  operator-injection claim only when a dependency contract, implementation, or
  behavior test establishes how that object is interpreted.
- **Template, HTML, deserialization, loader:** Identify the consuming parser
  and the representation supplied to it. Check whether the value is template
  source, escaped data, or an engine option such as a layout path; a fixed
  view name alone does not settle what the engine reads. Use the template,
  framework contract, or repository tests when its interpretation is decisive.
  For unconstrained HTML output, identify who can write the exact rendered field. An
  admin-only publisher of intentionally rich content does not establish XSS
  merely because the renderer uses raw HTML. If the writer's trust or content
  policy is unknown, name that missing boundary instead of treating a
  privileged writer as a lower-trust attacker.
  If a behavior test can be explained by an earlier transformation (for
  example, a route's explicit `eval` before template compilation), isolate
  which operation caused the observed output before attributing it to the
  anchored sink. When the first test is ambiguous, use `references` on the
  route, feature, or challenge identifier to locate integration or browser
  tests for the exact output effect. For a browser-output claim, inspect a
  returned browser test before stopping at an API assertion about text.
  Once the producer, anchored sink, and exact behavior test settle the same
  path, stop querying. Keep a distinct interpreter
  weakness as a separate lead.
  For a file-backed template or script value, trace writers of the selected
  file, including uploads and archive extraction, before treating the file as
  repository-owned. Search a feature or challenge identifier for a behavior
  test when the write path is not obvious.
  A sanitizer or validator matters only when it constrains that same value
  before that parse.

Stop when the relevant grammar/target is fixed or safely constrained, when a
concrete lower-trust path reaches the dangerous interpretation, or when one of
the SQL, shell, or code-evaluation rules above establishes an unsafe
construction despite unresolved exposure.
For other unresolved wrapper callers or producers, name the exact missing edge.
