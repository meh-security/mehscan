# Review a Mehscan bundle

Give each `review_id` its own verdict. The bundle supplies leads and locations,
not answers or a limit on research. For several IDs, first follow
[shared-pattern review](pattern-sweep.md); reuse source facts without copying
verdicts.

1. **Select the exact subject.** If a source-bound packet already supplies the
   exact selected question/anchor rows and source, use that initial view and
   request only missing facts. Otherwise, for several related IDs, read the exact row and
   `question_id` and referenced source windows from `review-sweep --bundle REQUEST`; reuse them
   instead of issuing another card query. Otherwise run `mehscan investigate review-card --bundle
   REQUEST --review-id ID` and read its security question, anchor operation and
   operand, decision facts, and playbook. The card shows only a small excerpt
   and locations; request further source when it can change the decision.
   The finalizer adds the selected anchor and its citation to brief drafts.
   Preserve `selected_anchor_id` and its citation when writing a full response.
   Name that exact operation in the summary. Read the matching
   [bucket guide](triage-buckets.md). Do not print the
   full request or response schema into model context; the finalizer reads the
   original request when validating the response.
2. **Separate facts from leads.** `decision_facts.established` states only its
   exact claim. `evidence` captures, nearby `facts`, and suggested lookups
   locate code; they do not establish attacker control, reachability, ownership,
   or effective protection. Clipped windows and empty unresolved lists do not
   prove safety.
   Read `operand_facts` when present. A fixed code-relative include points
   straight to its target; check that target instead of repeating input/caller
   research. An encoding call still needs the actual output context and its
   callable/options contract. Facts with remaining checks are not verdicts.
   A `local_operand_origin` locates a source producer. Inspect alternatives and
   accumulated parts without treating them as a safe value. A helper return
   still needs its call-site arguments. `local_call_argument` locates a possible
   caller argument; verify its actual value mapping. A bounded caller list does
   not establish all callers, parameter immutability or runtime dispatch.
   SQL `query_value` types locate observed construction terms; inspect formatting,
   producers and the rest of the reaching query before deciding grammar safety.
   `operand_boundary` names
   the use or shape where reuse stopped; inspect that location. Query text and
   values remain separate questions, and `process_shell_mode` settles only
   the observed option, not executable, argument, platform or caller policy.
3. **Test one evidence chain.** State the candidate failure and the facts that
   would prove or refute it. Follow the same value, branch, actor, resource,
   control, and effect. Ask Mehscan for the next decision-changing fact. Use
   a complete, context-compatible control to close this property before
   expanding caller/producer research; otherwise follow the missing input edge.
   Use `source` for a known path, `references` for callers or uses,
   `enclosing-at` for a known file and line, and `symbol --path FILE` for a
   definition in a known file. Start caller and producer searches in the authored
   component using `--path-prefix DIR`, guided by the review plan/provenance.
   Start with `references --summary true` for per-file locations and short previews;
   read selected source windows for arguments and controls. Returned occurrence
   counts cover the bounded query, not every caller. Full references remain available.
   Follow mapped originals instead of researching each generated copy. Widen when
   callers cross that boundary, the result is truncated, or a needed edge is absent;
   an empty scoped search does not establish that no callers exist.
   Use `paths` only when the path is unknown, and other commands when their
   exact question fits. Use `references --path-prefix DIR` for a known component
   or views directory; `--path` names one file. Scope common identifiers and copy
   paths from current evidence rather
   than an installed framework layout remembered from elsewhere. Prefer a
   distinctive symbol for wider searches; a truncated hit list is not a
   complete inventory. Start source
   reads with a small window around the decisive location and expand only
   when its boundary hides a needed fact.
   For a named local template or file, request that exact path with `source`
   even if it has no inventory ID. Check source-backed behavior tests when
   framework or dependency semantics decide the result.
   Use `--journal RUN/journals/REVIEW_ID.jsonl` on code-evidence lookups
   (`source`, `references`, `paths`, etc.), not on bundle listing or cards,
   naming the ID that prompted the query. The CLI records exact arguments,
   output, errors, and elapsed time. A source fact already read for another ID
   can be cited again without repeating the query; check that it applies to
   this ID's exact branch and operand.
4. **Check the exact decision chain.** Before finalizing, name the selected
   operation and operand, their producer or caller, the applicable control,
   and the effect. For renderers and parsers, check whether request-derived
   options select another template, file, layout, or interpretation context;
   a fixed view name does not prove the rendered bytes are fixed. Follow
   object spreads into render options, not just fields visibly bound by the
   template. Do not call a render safe solely because the template ignores
   ordinary request locals until any request-controlled engine options have
   been ruled out using the engine contract or a behavior test. Follow
   earlier route middleware and stored-data writers;
   nearby evidence about another operation cannot settle this ID. For a
   state-changing operation, check whether another branch reaches the effect
   without the expected payment or authorization step. Owning a record does
   not make disclosure of its sensitive fields safe.
   If another route lets a caller acquire a role or state required by this
   operation, review that bypass under its own operation; do not copy the
   bypass verdict onto every action with the role or state guard.
   If this same evidence walk exposes a distinct, consequential operation
   absent from the selected question, put one exact-source question in
   `reviewer_origin_leads`. Keep it separate from this ID's decision; do not
   count a proven adjacent weakness as proof of the selected security property.
   The distinction also applies when both weaknesses involve one operation:
   a selected file read establishes file exposure, while an HTML-output claim
   still needs evidence that lower-trust content can execute in the browser.
   Record the adjacent weakness as a lead or review its matching inventory ID.
   Do not sweep neighboring code for speculative leads. Before calling it new
   coverage, check the full same-fingerprint inventory for an ID at that
   operation. If one exists, leave it out of `reviewer_origin_leads` and
   queue that exact ID instead.
   - `issue`: show the unsafe operation and missing or ineffective control.
     Unsafe SQL, shell, or code construction can remain an issue with lower
     confidence when reachability is uncertain; state that uncertainty.
   - `not_issue`: show how a concrete control constrains this value on the
     reachable branch and in the sink's interpretation context. A function
     name or fixed view name alone is not proof.
   - `needs_review`: name the one fact that would change the verdict. If it
     names a repository caller, template, writer, configuration, or behavior
     test, query that local evidence before stopping. An unindexed file or a
     narrow search is not itself a blocker.
     For a missing runtime/configuration fact, inspect the relevant deployment
     manifest or root README before stopping. `paths` searches indexed source;
     use `source` for a known conventional filename even when scan admission
     or an empty path search omitted it.
5. **Finish once the chain is settled or precisely blocked.** Follow
   [finalize and report](finish-review.md) to save the brief draft, validate it,
   and produce the report. Load that guide at this stage.
