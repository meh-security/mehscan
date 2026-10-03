# Review related operations together

Use this when one bundle contains several IDs. The unit of reuse is a verified
implementation fact, such as a query builder, route policy, renderer, writer,
or validation path. A shared CWE label or nearby file does not establish that
the IDs use the same behavior.

1. Run `review-sweep --bundle REQUEST` to read the exact cards together. Read
   each `source_contexts` window once; rows reference it through `source_context_ids`.
   Read the row's `question_id` in `questions` for its question, category and playbook.
   The CLI merges overlapping windows and preserves clipped windows' truncation.
   For routing across many bundles, use the existing compact inventory's
   `--group-by contract` queue to find repeated operand questions. Select members
   with `--contract KEY`, existing surface filters and the ledger, then materialize
   a small exact-ID chunk. Groups are explicitly unverified: the same observed
   name/root can have overrides, contexts or targets that differ. Prefer repeated
   questions whose identity can actually be checked. Review
   the other cards when their bundles are actually triaged. For the IDs being
   reviewed, make a short table: exact operation, actor and value producer,
   interpreter options or selected files, control, effect, suspected shared
   implementation, and missing fact. Do not load the full bundle JSON into
   context.
   Do this within the existing pre-assessment or bundle review; a separate
   routing run over the same IDs is unnecessary in normal operation.
2. Group IDs by a concrete shared implementation question. An ID without that
   shared question gets its own group. Keep the grouping note small; it is a
   working map, not a second response format.
   Route the group before a long sweep: if several IDs reach one renderer,
   command builder, or interpreter through different writers, value producers,
   engine options, selected files, or sink operands, compare those IDs together
   in a small focused pass. A shared sink can hide a different boundary. For
   entry-point guard or ownership questions, check each operation in the
   normal bundle review; use a focused pass when a shared bypass or uncertain
   policy makes the operations interdependent. Other IDs can stay in the
   ordinary sweep. Record only the exact IDs and the differing edge. This
   routing depends on the relationship, not the CWE label.
3. Check shared behavior once through `mehscan investigate`, with a journal
   named for the first ID that needs the query. Record the exact source path and
   lines and which IDs the fact might affect. In this review session, reuse the
   returned text or journal for later IDs. Do not rerun a source query merely
   because another ID has a separate journal.
   For extensible APIs, inspect repository-visible overrides/registrations once
   and state the framework/extension assumptions within the requested scope.
   A hypothetical external override alone should not trigger deployment research
   for every anchor. Record an actual unavailable shared contract fact once in
   the plan, with affected IDs, while keeping their individual verdicts honest.
4. For each ID, test whether that fact applies to its own actor, producer,
   branch, operand, interpreter option, control, and effect. Query only the
   missing edge. Related sinks can differ because of a writer's trust, guard,
   parameterization, or
   output context. Before drafting, inspect those differences as possible
   exceptions: a shared renderer or query builder is not proof that every
   producer crosses the same security boundary. Where a trust or content
   policy decides the result and the available source does not establish it,
   use `needs_review` with that exact missing fact. Do not copy a neighboring
   ID's verdict or confidence.
   Cite the same inspected source range in multiple brief results when it truly
   supports each result; add the operation-specific range as needed. Empty or
   short per-ID journals are valid when earlier queries already supplied the
   evidence. The finalizer counts actual queries, not source ranges cited.
5. Stop a group when each ID has a supported verdict or a precise unavailable
   fact. Write one brief draft for the bundle and finalize it. Keep a one-line
   pattern note only if it helps a later chunk avoid rediscovering the same
   control; tie it to the current source revision and recheck after changes.

## Focused exception audit for a broad review

Before reporting a broad multi-bundle review, scan the small pattern notes and
the exact ID decisions for reused facts. Queue only groups where a shared
renderer, command builder, guard, or helper serves operations with materially
different actors, value producers, guards, interpreter options, or sink operands.
Name the differing edge and exact IDs. Do not repeat a focused group already completed on the
same source revision. This is an audit queue, not a new scanner finding.

Re-review those exact IDs in a focused pass, preferably with a fresh review
context. If the original bundle also contains other IDs, materialize an
exact-ID bundle from the same inventory before drafting; the finalizer requires
a decision for every ID in its bundle. Use the cards and targeted Mehscan source
lookups; compare each
operand's producer, actor, control, and effect. Do not give the focused reviewer
the initial verdicts as evidence. Preserve the broad responses and save the
focused validated responses separately. For a subset, replace only its ID
results in a copy of the original complete response; retain the original bundle
fingerprint and all other IDs, then run `review-bundle-triage` and the run
summary against that copy. If the focused pass cannot settle a policy or behavior
that changes the verdict, retain `needs_review` with that fact rather than
forcing agreement with the broad pass. Skip this audit when no such contrast
exists; do not re-review every ID just because it shares a CWE label.

For a large repository, build the small attack-surface map in
[review planning](review-planning.md) once per source revision. This step uses
only the relevant part of that map; it is not a new broad mapping pass.
