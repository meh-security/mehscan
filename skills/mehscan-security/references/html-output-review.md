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

First check the output control. Verify imports/module registration and the exact
helper implementation. Include every directly chained transformation: encoding
followed by decoding or a change of interpretation can invalidate a control.
Check text, attribute, URL, JavaScript and DOM contexts separately. Same-named
helpers can differ. If the complete verified chain is safe in this context,
close that property; input-origin research adds nothing to that conclusion.
For server responses, check the effective content type and server-side control.
One client's safe DOM insertion does not close a directly rendered HTML response.

Otherwise trace who writes the exact rendered value. Inspect relevant normal
and alternate writers, their actual callers/registration, and controls on those
paths. A sanitizer setting on an editor does not protect a different direct
writer. A shared field name or receiver spelling does not prove the same object.
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
