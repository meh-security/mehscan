# Native C and C++ review semantics

Read this reference only for C/C++ reviews or native capabilities. Mehscan's
native coverage is intentionally systems-specific. It does not mirror web
language rule counts and does not claim a compiler-grade CFG, taint analysis,
alias analysis, type solver, or interprocedural range engine.

## Interpret the candidate narrowly

- Review the exact source, sink, operands, protection evidence, and named
  invariant. A path is a high-value review signal, not proof that the whole
  function or application is vulnerable.
- `protected` means the scanner linked an exact control for this bounded path.
  When the supplied facts show that the control applies and
  `decision_facts.unresolved` is empty, use `not_issue` for this invariant. Do
  not claim that adjacent arithmetic, lifetime, parser, or authorization
  invariants are also safe.
- `unknown` means the bounded relationship lacks effective linked protection;
  it does not automatically mean `needs_review`. If
  `decision_facts.unresolved` is empty and the supplied source establishes the
  dangerous native behavior, use `issue` with the exact configured confidence.
  Use `needs_review` only for an exact supplied unresolved fact that could
  change the decision.
- CWE candidates identify plausible consequences. Confirm the named operation
  and invariant instead of treating a CWE label or dangerous API name as the
  verdict.
- Use `review-bundles` or `review-jobs` for AI adjudication instead of turning
  raw native evidence into custom review prompts. Scan/candidate output keeps
  common C/C++ memory operations and closed ownership proofs for auditability,
  but the default review funnel omits unlinked raw buffer writes and exact
  protected `free`, matching `delete`/`delete[]`, and standard RAII paths. An
  unknown leak or allocation-family mismatch, and any buffer write linked by a
  bounded source/size/capacity relationship, remains reviewable.

## Native invariants

| Family and representative capabilities | Review test | Controls that are insufficient by themselves |
| --- | --- | --- |
| Buffer capacity and termination: `buffer_write` | The exact destination capacity must cover the write, and a bounded string copy must leave an in-bounds terminator before string use. | A source bound that ignores destination capacity; `strncat(..., sizeof(destination))`; `strncpy` without proven termination. |
| Signedness, narrowing, division, and multiplication: `signed_size_memory_operation`, `arithmetic_division`, `arithmetic_multiplication`, `allocation_size_computation`, `loaded_memory_extent` | Establish effective operand widths and signedness. Overflow and zero checks must reject before the unsafe conversion or computation, for the same operands and maximum. A terminating `value < 1` or `value <= 0` branch proves the surviving value is positive. | A post-computation check; a differently typed maximum; a zero check that does not cover every required operand; assuming a typedef's width; a debug assertion that may be compiled out. |
| Count and destination regions: `count_controlled_memory_operation` | The exact count and any destination offset must fit the authoritative state-derived region before the operation. Multi-axis copies require every relevant axis. | Checking each offset alone; checking only one axis; wrapping `offset + extent` in the original width. |
| C and C++ ownership: `local_heap_deallocation`, `cpp_heap_deallocation`, `cpp_raii_owner`, `ownership_gated_release` | Follow only the exact local allocation, release family, ownership transfer, or ownership flag represented in the path. A return that is reachable only when the allocation failed is not a leak, including when a nested assignment exposes the result through an alias. | A different pointer's release; unmatched `new`/`delete[]`; arbitrary smart-pointer names; an ownership flag set after an exceptional exit can occur; treating `if (!allocated) return` as a post-allocation leak path. |
| Lifetime and required state: `post_return_dereference`, `post_invalidation_use`, `state_dependent_dereference` | Determine whether callback-local storage, a documented invalidating status, or recoverable initialization failure can reach the exact later dereference. A protecting branch must terminate before use. | Logging and continuing; checking another status or pointer; cleanup that occurs only after the shown use. |
| Serialized fixed-layout data: `serialized_blob_copy` | Compare the loader-reported source length with the exact fixed-layout copy extent before the copy. | Correct allocation size; a safe dimension product; merely obtaining a non-null blob. Blob length and arithmetic overflow are independent invariants. |
| Loaded allocation/copy extent: `loaded_memory_extent` | Determine whether a loaded scalar and the other exact operands can overflow the shown allocation-and-memory-operation extent. Protection requires pre-computation zero rejection and a matching `SIZE_MAX` division bound. | Blob-length equality; allocation success; a later overflow observation; a guard for only a different product. |
| Remaining parser input: `remaining_input_read` | The decoded extent must fit the authoritative remaining input at the exact cursor before the read. `length > total - cursor` is safe only after `cursor <= total` is established. | `cursor + length > total` in a width where addition can wrap; subtraction when the cursor bound is unknown; a guard followed by cursor/length reassignment. |
| Archive, filesystem, and XML: `archive_entry_path`, filesystem paths, `xml_parsing` | Keep traversal, absolute paths, symlink following, privilege restoration, check/use races, DTDs, entities, and external resource loading as separate invariants. | Canonicalization without containment; network-only XML restrictions as full XXE protection; one archive option treated as protection for every path or privilege invariant. |
| C++ web identity and resources: `authentication`, `resource_access` | For a supported native framework, credential verification establishes identity; separately require owner, tenant, role, or policy authorization for the selected resource. | Treating an authenticated route as proof of CWE-639 authorization. |
| Printf-family format interpretation: `format_string_output` | Decide whether the complete format is fixed at compile time. Adjacent string literals, standard `PRI*`/`SCN*` format macros, and conditional expressions whose every result branch is fixed remain compile-time formats; runtime text must be passed as a data argument or validated as a complete, constrained format language. | Treating literal-plus-`PRIu64` or an all-literal conditional as runtime-controlled; accepting runtime format text because it contains one expected directive while other directives remain active. |

`state_dependent_dereference` is intentionally a conservative same-file signal.
Its initialization source and member handoff must use the exact same owner and
member spellings before the handoff reaches the indexed parameter. It is not
cross-file alias or value-flow evidence. If an older payload joins generic
members such as `.data` across owners, files, or alternative implementation
backends, the supplied operands affirmatively disprove that named relationship;
do not treat the path label as proof and do not request call-site syntax merely
to rescue it.

## Validation discipline

For any claimed native control, verify all of these from the supplied payload:

1. It constrains the same value or unchanged local represented by the path.
2. It executes before the allocation, copy, read, release, or dereference.
3. A rejecting branch actually terminates or the clamp feeds the exact sink.
4. Its arithmetic form cannot itself overflow or underflow under the effective
   operand types.
5. It covers the entire named invariant: every product operand, destination
   axis, required length, cursor bound, ownership state, or invalid status.

Do not invent macro expansion, typedef width, implicit promotion, caller
preconditions, serializer guarantees, custom-deleter behavior, loop
invariants, or deployment configuration. Use those only when the review facts
or excerpts supply them. If the necessary fact is absent but is not listed in
`decision_facts.unresolved`, decide from the admitted bounded behavior rather
than creating a new check.

## Bounded native syntax investigation

Use the review payload first. `investigate native-call-sites ROOT --callee NAME
[--path FILE]` can collect supplemental navigation context without compiling
the target. It inventories calls whose terminal callee spelling is `NAME`,
including the call text, arguments, enclosing expression, and enclosing symbol.
Use it only when an existing C/C++ `decision_facts.unresolved` item asks whether
that exact call syntax is present, where it occurs, or which argument expression
appears. Do not run it for a decision-ready review or to create a review from a
CVE research lead that Mehscan did not admit.

This is a syntax inventory, not symbol resolution or a security path. A
`bare_identifier` call kind describes only the AST form and may still be a
function-like macro. The operation does not resolve overloads, types, aliases,
inheritance, templates, macros, function pointers, runtime dispatch, control
flow, or value flow. Its ordinary `limitations` do not prevent it from
answering a strictly syntactic question; `truncated: true` or a relevant file
under `skipped_files` does. A file under `parse_recovered_files` requires the
reviewer to treat wider file context as partial, but does not by itself erase a
locally returned syntax match. Never convert multiple matches into a flow or
reachability claim. Querying must not add scan evidence, change review
admission, or introduce checks outside the supplied unresolved set.

The generic `structural` operation is also available for bounded AST lookup in
every supported language. Use it only to answer an exact existing unresolved
syntactic question, preferably with `--path`; do not use model-invented patterns
as default verdict evidence or as a source of new findings.

## Response and reporting

Name the exact native failure in the summary, such as product overflow before
allocation, wrapping offset-plus-length validation, source-length mismatch,
use after an invalidating status, or mismatched allocation/release family. Do
not summarize every C/C++ candidate as a generic buffer overflow.

Keep capability names and state exactly as emitted. Return the normal strict
bundle response: one result per `review_id`, exact configured confidence, and a
`checks` field on every result. `issue` and `not_issue` require `checks: []`;
`needs_review` checks must be copied from `decision_facts.unresolved`.

Candidate JSON and `sarif-candidates` remain unconfirmed review leads. Only the
post-triage canonical JSON is the full-fidelity findings report; post-triage
SARIF contains confirmed issues, and Markdown is the human handoff.
