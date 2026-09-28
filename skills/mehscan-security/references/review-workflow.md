# Review a Mehscan bundle

Apply this to each `review_id` independently. The bundle supplies a lead and
locations, not an answer or a limit on your research.

1. **Select the exact subject.** Read `review_basis.security_question`, the
   operation and operand, and `review_playbooks[review_id]`. Resolve
   `anchor_evidence_ids` to `evidence[].id`; another evidence entry may describe
   a neighboring route. For a path review use `candidate.sink.location` and
   `candidate.primary_location`. Copy the selected ID to `selected_anchor_id`
   and cite it for a decisive verdict. Name that exact operation in the summary.
   Read the matching [bucket guide](triage-buckets.md).
2. **Separate facts from leads.** `decision_facts.established` states only its
   exact claim. `evidence` captures, nearby `facts`, and suggested lookups
   locate code; they do not establish attacker control, reachability, ownership,
   or effective protection. Clipped windows and empty unresolved lists do not
   prove safety.
3. **Test one evidence chain.** State the candidate failure and the facts that
   would prove or refute it. Follow the same value, branch, actor, resource,
   control, and effect. Ask Mehscan for the next decision-changing fact. Use
   `source` for a known path, `references` for callers or uses,
   `enclosing-at` for a known file and line, `paths` only when the path is
   unknown, and other commands when their exact question fits. Scope common
   identifiers to a known file and prefer a distinctive symbol for wider
   searches; a truncated hit list is not a complete inventory. Start source
   reads with a small window around the decisive location and expand only
   when its boundary hides a needed fact.
   Use `--journal RUN/journals/REVIEW_ID.jsonl` on every investigation query.
   The CLI records exact arguments, output, errors, and elapsed time.
4. **Challenge a claimed control.** Before `not_issue`, verify that the control
   actually constrains the selected value on the reachable branch and in the
   sink's interpretation context. Inspect its implementation, configuration,
   or a relevant behavior test when effectiveness is uncertain. A security
   function name or nearby check alone is not proof. Do not close a review
   while a concrete in-repository counterexample could change the verdict.
   For `issue`, establish the lower-trust path and missing or ineffective
   control. If a decisive edge remains unavailable after targeted queries,
   use `needs_review` and name the exact missing fact and how to get it.
5. **Stop and answer briefly.** Stop when the chain is established,
   contradicted, or blocked by a specific unavailable fact. The query journal
   is the audit trail. Put only decision-relevant, exact source excerpts in
   `decisive_artifacts`; cite those IDs and the selected anchor.
   The selected anchor is already a bundle artifact: cite its ID directly and
   do not copy it into `decisive_artifacts`. Give each newly retrieved source
   a distinct ID and copy its exact returned excerpt and location. Keep
   inference separate from scanner facts and source text. Use empty arrays for unused
   investigation fields and `journal_summary: null` in the draft. A resolved
   `issue` or `not_issue` must have `checks: []` and `blockers: []`, even when
   the bundle supplied an open question; only `needs_review` retains a
   one-line decision-changing check. Run
   `review-bundle-finalize --bundle REQUEST --draft DRAFT --journal-dir RUN/journals
   --output RESPONSE --source-root ROOT`. It attaches query counts from the
   journal and validates the final response.
   If it rejects source text, copy a smaller exact returned excerpt and keep
   the evidence chain intact; do not discard a decisive fact to pass validation.

The validator checks response shape, selected anchor, citation links, and exact
source excerpts. It cannot decide whether a control works or whether your
verdict follows from the evidence; inspect that reasoning yourself.
