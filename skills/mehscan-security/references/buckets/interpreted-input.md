# Interpreted input

Trace the exact value consumed by the interpreter: **sink operand → how it
was built → who can supply it → same-path constraint**. Decide whether a
lower-trust actor can change grammar or a dangerous target, not merely a
scalar value.

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
  helper together within one bounded source window.
- **Template, HTML, deserialization, loader:** Identify the consuming parser
  and the representation supplied to it. Check whether the value is template
  source, escaped data, or an engine option such as a layout path; a fixed
  view name alone does not settle what the engine reads. Use the template,
  framework contract, or repository tests when its interpretation is decisive.
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
