# Unknown-origin review policy

An unknown input origin must not become evidence of safety when the local code
already proves that a runtime value is interpreted as SQL, code, a shell
program, a native format string, or another executable grammar. Those
observations should remain `needs_review` until supplied evidence establishes
attacker influence or an affirmative constraint. An ordinary API boundary does
not get the same treatment merely because its argument is nonliteral.

This distinction preserves useful sinks without making every configurable URL,
path, redirect, query, or process argument decision-critical.

## Current failure mode

Observation review currently asks one of two generic provenance questions when
it has a sink without a deterministic path:

- `What is the exact origin of the security-sensitive sink input?`
- `Does the supplied source influence the security-sensitive sink input? The deterministic engine did not admit a path.`

Both questions are intentionally advisory and are removed from
`decision_facts.unresolved`. The resulting review is decision-ready, so AI
triage can use `not_issue` when it sees a strong sink but no proved source.
That is reasonable for ordinary boundaries. It is lossy when the observation
already establishes dangerous construction or interpretation.

C# dynamic SQL composition now demonstrates the intended middle ground:

1. The sink alone remains an ordinary observation.
2. Concatenation, interpolation, formatting, or bounded aliases into executable
   SQL establish a stronger local fact.
3. The exact dynamic operand receives a decision-critical origin-or-constraint
   question.
4. A fixed, numeric, enum, GUID, or exact allowlisted operand can affirmatively
   close that question. Parameter binding does not repair text already composed
   into SQL syntax.

The same policy should be reusable across capabilities, but only for shapes
that prove an interpreter boundary or a similarly strong unsafe primitive.

## Decision rule

Retain an origin question in `decision_facts.unresolved` when all of these are
true:

- the receiver or function is identified as the intended security-sensitive
  API rather than a same-name lookalike;
- the captured operand occupies an executable, structural, or trust-bypass
  role;
- the operand is dynamic or partially dynamic at the operation;
- no supplied fact affirmatively restricts the exact operand to a safe domain
  or shows an applicable safe construction;
- deciding `issue` versus `not_issue` depends on the missing production origin
  or constraint.

Use `issue` when the same review establishes attacker influence and no effective
applicable control. Use `not_issue` only when it establishes a safe value
domain, trusted immutable producer, non-executable use, or applicable safe
construction. Keep the origin question advisory for ordinary boundaries whose
local syntax does not itself establish a dangerous interpretation.

## Ranked implementation scope

The counts below cover 202 declarative sink and sensitive-operation rules.
Procedural analyzers add evidence beyond these counts, so the counts measure
review surface size rather than complete scanner coverage.

| Order | Family | Declarative rules | Production likelihood | Decision-critical local shape | Exclusions and affirmative safety |
| --- | --- | ---: | --- | --- | --- |
| 1 | SQL query text | 59 database rules include SQL and NoSQL | Very high | Concatenation, interpolation, formatting, builders, or bounded aliases incorporated into executable SQL across every supported language | Fixed SQL, parameter placeholders with separately bound values, and typed scalar operands with a non-SQL-token representation. A raw-query API alone remains ordinary. |
| 2 | Explicit HTML trust bypass | 17 HTML-output rules | High | Runtime content passed to `Html.Raw`, trusted-markup constructors, Angular trust bypasses, or equivalent APIs that explicitly disable escaping | Normal framework rendering and response writing remain ordinary unless a source relationship or stored-XSS relationship is established. Fixed trusted markup is suppressed. |
| 3 | Shell command text and native format strings | 13 process rules; 2 format-string rules | High | A dynamic string interpreted by `system`, `popen`, shell helpers, Node `exec`, PHP shell functions, or as the format operand of a native printf-family call | Structured argv execution, a fixed executable with separate arguments, and fixed format strings remain ordinary. Shell mode must be established for APIs whose behavior depends on options. |
| 4 | Dynamic code, expression, and template program text | 14 dynamic-code rules | Medium to high | A dynamic operand evaluated by `eval`, `Function`, script engines, Roslyn/Razor parsing, Groovy, SpEL, EL, Otto, Rhai, or equivalent expression evaluators | Fixed program text is suppressed. Plugin or assembly paths are not code-text injection and need path/load-policy analysis instead. Template data passed to a fixed template is excluded. |
| 5 | Executable object deserialization | 14 deserialization rules | Medium to high | Dynamic bytes/text consumed by native object graphs, pickle/dill/jsonpickle, PHP unserialize, node-serialize, unsafe typed YAML, or comparable type-instantiating formats | Ordinary JSON and Rust structured-data decoding stay advisory. Go gob and general YAML require format/options/type context before receiving this policy. A trusted immutable file or payload is affirmative safety. |
| 6 | Raw or executable NoSQL construction | Included in the 59 database rules | Medium | Dynamic `$where` program text, raw JSON/BSON documents, operator-capable filters, pipelines, or expression syntax | Typed scalar equality filters and separately bound DynamoDB expression values remain ordinary. A collection call or parsed document alone is not enough. |
| 7 | LDAP filter construction | 6 rules | Medium | A dynamic value composed into a raw LDAP filter or distinguished-name grammar without context-specific encoding | Fixed filters, placeholder APIs with separately bound values, and exact context-appropriate LDAP encoding close the question. |
| 8 | Context-qualified outbound requests and redirects | 19 outbound-request rules; 12 redirect rules | High boundary frequency, lower standalone signal | A request-selected scheme, authority, or external-capable redirect destination shown at the boundary | Operator configuration, fixed authority plus dynamic path/query, and internal route/action redirects remain advisory. Do not escalate every service-to-service URL or browser fetch. |
| 9 | Context-qualified filesystem access and upload destinations | 29 read/write rules; 2 upload rules | Very high boundary frequency, lower standalone signal | A request-selected path segment, archive entry, include target, or upload destination crossing an intended root | General dynamic application paths remain advisory. Server-generated names, canonical containment, immutable configuration paths, and repository-owned assets can close the question. |

Orders 1 through 7 are suitable for a shared local classification mechanism.
Orders 8 and 9 should wait for source-role or boundary-specific evidence; a
nonliteral URL or path is too common to retain on its own.

## Families that should remain advisory by default

- generic logging calls without a proved request, control-character, or secret
  relationship;
- ordinary safe-format serialization and deserialization;
- raw database APIs whose query text is not locally shown to be composed;
- structured process execution where the executable and argument boundaries
  remain separate;
- ordinary HTML responses and escaped template rendering;
- XML parsing without an unsafe external-entity or resolver policy;
- configurable endpoints, redirects, and filesystem paths without a
  request-selected authority, destination, or path relationship;
- resource access without a request-selected object or a violated ownership
  policy;
- broad unsafe, memory, hashing, encryption, and resource boundaries unless a
  violated invariant is locally established.

## Implementation design

Add one shared observation classifier rather than another capability-wide
exception or a separate triage instruction for every family. Its output should
describe:

- the interpreter or structural grammar, such as SQL, shell, native format,
  script, trusted HTML, serialized object graph, NoSQL filter, or LDAP filter;
- the exact capture role and captured dynamic operand;
- the local construction style;
- any affirmative constraint found for that same operand;
- a capability-specific unresolved question when the constraint is absent.

Rules and procedural analyzers should mark only proven strong shapes with a
semantic tag such as `review-origin:decision-critical`. The classifier should
also require the expected capture role and capability, so a tag cannot turn an
unrelated operand into a blocker. Existing literal evaluation should suppress
fixed operands before review construction. Specialized analyzers may add a
safe-domain fact, as C# dynamic SQL already does for constrained scalar types.

The review contract can then state the behavior once for every marked
interpreter boundary. C# dynamic SQL becomes the first producer of the shared
shape instead of a permanent one-off policy. The existing advisory filter stays
in place for generic questions.

This work does not require a CFG, general taint engine, compiler-wide type
resolution, or cross-file tracing. It reads evidence tags, captures, literal
metadata, and already-supplied bounded facts. Classification is linear in the
small evidence/fact neighborhood already assembled for a review, adds no file
parsing or repository traversal, and should have negligible scan-time impact.
It may increase AI review volume because strong unknown-origin observations
will correctly remain `needs_review`; ordinary sink volume is unchanged.

## Delivery sequence

1. Introduce the shared strong-operand classifier and migrate C# dynamic SQL to
   it without changing its current verdict behavior.
2. Extend SQL composition facts to the remaining supported languages, reusing
   existing query operand captures and bounded same-callable aliases.
3. Mark explicit trusted-HTML bypasses, shell-string APIs, and native format
   operands. These are common, locally distinguishable, and high signal.
4. Mark dynamic code/expression evaluators, excluding plugin paths and fixed
   programs.
5. Split executable deserializers from safe structured-data decoders, then mark
   only the executable group.
6. Add raw NoSQL/operator and LDAP filter construction after their safe binding
   and encoding counterevidence is represented.
7. Evaluate URL, redirect, and path cases only with request-role evidence; do
   not promote their generic nonliteral sinks.

Validation at this stage should stay small: classifier unit tests plus one
synthetic positive and one safe counterexample per newly enabled semantic
class. AI comparisons should be deferred until deterministic review JSON is
stable, then run on a compact mixed sample containing issue, constrained-safe,
and unknown-origin cases.
