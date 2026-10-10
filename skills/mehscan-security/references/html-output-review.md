# Review HTML output

Use for a supplied chunk whose selected questions all concern HTML output.
Start with its manifest and source-bound packet, or `review-sweep --bundle REQUEST`
when no packet covers the questions, anchor IDs and source. Keep raw requests on
disk for finalization. This guide supplies the category workflow; load another
bucket only for a separate security question.

## Shared chain, individual decisions

For each exact ID identify the output context, rendered operand, producer,
transformations in order, and the writer's actor and controls. Group actual shared
renderers/writers, not just files or CWE labels. Reuse inspected source facts but
check every operation's branch and effect. Keep a short missing-edge note, not a
second report. Packet relationships and candidate-writer maps are navigation,
not proof of binding or complete coverage.

First check the output control. Verify imports/module registration and the
helper's effective behavior. Include every directly chained transformation: encoding
followed by decoding or a change of interpretation can invalidate a control.
Check text, attribute, URL, JavaScript and DOM contexts separately. Same-named
helpers can differ. If the complete verified chain is safe in this context,
close that property; input-origin research adds nothing to that conclusion.
For server responses, check the effective content type and server-side control.
One client's safe DOM insertion does not close a directly rendered HTML response.

For frontend output, use supplied initializer/helper locations to pair the sink
with its actual producer. A formatter/highlighter needs its implementation,
version and effective options; its name or return type is not an escaping proof.
When the repository names an exact external artifact, inspect that version with
available read-only tools before calling the implementation unavailable. Treat
deployment overrides as a blocker when evidence connects them to this chain;
otherwise state the normal binding assumption. For an explicit framework trust
bypass, a documented public API contract and verified import, input and consumer
can establish the source weakness under that assumption. A missing lockfile or
vendored implementation alone does not block it. Research versioned behavior
when a patch, override or uncertain API semantics would change the decision.
A complete output-control proof
can settle HTML interpretation without reconstructing every input writer.
Compact `review-card` and `review-sweep` views expose supplied frontend facts
under `frontend_context`. Start with `frontend_output_producer_context` and
helper imports. Verify the actual helper, options and complete transformation
chain. If that control settles the exact HTML property for all inputs, stop;
caller sampling gaps do not reopen it. Do not reread supplied producer windows
or investigate caller origins merely to confirm them.
If the control is absent, bypassed or unresolved, use
`frontend_component_prop_context`, `frontend_prop_caller_context` and
`frontend_prop_producer_context` to research the next missing edge. Static,
sanitized and dynamic callers can differ: reuse facts, not verdicts. The sample
is bounded; investigate spreads, omitted callers, parser gaps, reassignments
and unsupported wrappers when they affect that edge. Missing caller facts do
not mean no callers exist.
For Angular component, pipe, input or dialog facts, read
[Angular output review](angular-output-review.md). It explains the supplied
registration and handoff evidence and how to research the next missing edge.
For Vue SFC output, use supplied operands, writer snippets, native-ref bindings
and helper imports first. Writer snippets locate assignments; verify their
branches and later transformations. Retrieve missing source through
`investigate source`. Native-ref identity does not prove input trust. `v-html`
template producers, reactive assignments and child props are not linked yet.
Normal interpolation and `v-text` are escaped text. Raw output alone proves no unsafe input.
External/preprocessed blocks and dual script scopes have partial coverage;
inspect their source when relevant rather than infer absent producers or callers.
For DOM-to-DOM HTML copying, inspect the source element's markup and relevant
writers. A DOM selector/type is navigation, not trusted contents. For a shared
request helper, pair the implementation with observed callers and effective
credentials/options; keep HTML rendering as its own consumer question.

Otherwise trace who writes the exact rendered value. Inspect relevant normal
and alternate writers, their actual callers/registration, and controls on those
paths. A sanitizer setting on an editor does not protect a different direct
writer. A shared field name or receiver spelling does not prove the same object.
For API-backed values, follow the service URL into local server routes and
persistence setters/validators. A client save call does not prove the server
accepts raw content. Inspect available repository tests when they clarify a
writer or control. Do not label those local policies unavailable before checking
them; distinguish a specific remaining deployment/dependency gap.
Use source-visible tests or versioned dependency source when semantics are
decisive. Do not invent behavior from a familiar name or a failed lookup.

## Get only the next missing fact

- Known file: `mehscan investigate source ROOT --path FILE --start-line N --end-line M`.
- Definition in a known file: `mehscan investigate symbol ROOT --name NAME --path FILE`.
- Unknown writer/caller: `mehscan investigate references ROOT --symbol NAME --path-prefix COMPONENT --summary true`.

Add `--journal RUN/journals/ID.jsonl` to code-evidence queries, using the ID that
prompted the lookup. Start with small decisive windows; expand clipped methods
or missing cross-component edges. Use a supplied writer map before repeating a
writer search. Scope definitions to the known module/file instead of searching
the whole repository. Widen when needed, including truncated candidate results.
Batch independent lookups, then inspect results before choosing dependent ones.
Do not reread source to populate a journal or copy a query for each sibling ID.

## Decide and stop

- `issue`: a shown unsafe interpretation crosses a demonstrated trust boundary,
  or an explicit source-level protection is bypassed on the same relationship.
  State enablement/exposure conditions; do not claim demonstrated exploitation.
- `not_issue`: a verified control or an affirmatively inapplicable relationship
  closes this exact output property.
- `needs_review`: a specific decisive fact remains unavailable after targeted
  source research. Name the fact and how to obtain it. Query local callers,
  settings, registrations and relevant repository tests before treating them
  as missing. If deployment policy decides intentional rich-content trust,
  inspect available deployment evidence, then record that shared gap once.

Raw rich-content output alone is not XSS. Do not assume an authorized publisher
is lower trust, or call a direct writer safe because its actor policy is unknown.
An intentional setting that permits raw author content is not itself a bypass.
Without evidence of a lower-trust writer, an unknown effective setting or author
policy stays `needs_review`. Distinguish this from a writer that evades a
protection while that protection is enabled for the same content relationship.
An explicit protection bypass and unknown deployment applicability are different
questions; preserve both accurately. Do not audit hypothetical external overrides
without evidence that they affect the selected chain. Keep distinct adjacent
operations as separate leads or existing inventory IDs.

Once each selected chain is settled or precisely blocked, load
[finalize and report](finish-review.md). Write its brief draft with concise reason
and inspected source ranges, finalize against unchanged requests, and save the
report. Do not load the full response schema for a brief draft. The finalizer
binds anchors and validates responses; its validation does not judge reasoning.
