# Finalize and report

Stop when the chain is established,
   contradicted, or blocked by a specific unavailable fact. The query journal
   is the audit trail. Write a brief JSON draft with one result per bundle ID:
   `{ "results": [{ "review_id": "ID", "decision": "issue", "confidence":
   "high", "summary": "Exact operation and verdict", "reason": "Evidence chain",
   "evidence": [{"path": "relative/file", "start_line": 10, "end_line": 14}] }] }`.
   In this brief format, omit `schema_version`, `bundle_fingerprint` and
   `selected_anchor_id`; the finalizer supplies binding and anchor fields.
   Do not mix brief-draft fields with the full response schema.
   If the caller explicitly requests a draft-only review, save this brief draft
   and journals, then stop. The caller must finalize, validate and report it;
   a draft-only result is not a completed validated review.
   Use only decision-relevant source ranges already inspected. Keep each range
   to a few lines around the operation or control (usually at most 20; hard
   limit 40 lines and 4000 characters). Use two ranges for separated facts
   rather than one long span. Line ranges here are inclusive; a source span
   ending at column 1 of the next line does not include that next line's text.
   The CLI reads
   exact source, fills artifact locations and excerpts, cites the selected
   anchor, and attaches the query journal. Keep `summary` and `reason` concise;
   do not reproduce source in them. For `needs_review`, add `checks` with the
   one decision-changing missing fact and `blockers` if appropriate. The full
   schema 1.3 draft remains available when you need explicit artifact citations
   or reviewer-origin leads. Save drafts with shell redirection or another file
   write that prints only the path or a short success message. Do not use a
   patch tool for drafts: its diff echoes the full JSON into context. Avoid
   shell one-liners that construct large JSON objects. Run
   `review-bundle-finalize --bundle REQUEST --draft DRAFT --journal-dir RUN/journals
   --output RESPONSE --source-root ROOT`. It attaches query counts from the
   journal and validates the final response. Save RESPONSE as
   `CHUNK/responses/REQUEST_FILENAME`, beside that chunk's manifest, so reports
   and the run ledger can locate it directly.
   Finalization already validates the response. Use a separate validation check
   only for an externally supplied or edited full response:
   `review-bundle-triage --bundle REQUEST --responses RESPONSE --source-root
   ROOT --summary true`; the full response is already saved on disk.
   If it rejects a source range, select a smaller range that contains the
   decision-changing operation or control.

If a query journal is malformed, preserve it before recovery. Do not discard
invalid rows to make validation pass; recover the affected queries from the
command trace and rerun them into a clean journal, stating any unrecovered gap.

The validator checks response shape, selected anchor, citation links, and exact
source excerpts. It cannot decide whether a control works or whether your
verdict follows from the evidence; inspect that reasoning yourself.

For resolved decisions, use `checks: []` and `investigation.blockers: []`;
do not carry the resolved bundle question forward. For `needs_review`, name
the exact missing fact in one-line checks within 300 characters. Keep each
summary on one line within 500 characters. Keep the brief reason concise; the
finalizer formats up to 4000 characters into bounded inference claims without
dropping words. Full-schema inference claims still follow their own 500-character
limit.

## Report and account

Run finalization, the requested report and ledger in one shell turn, sequentially;
check each exit code before consuming its output. Inspect compact accounting once
afterward. Do not generate additional report formats or print a full
`review-bundle-summary` solely to count decisions.

Run `mehscan report --run CHUNK --responses CHUNK/responses --source-root ROOT
--format markdown --output CHUNK/report.md`; use `json` or `sarif` when requested.
State the root, selected-source limits and whether every manifest ID was reviewed.
Only confirmed issues are findings; retain unresolved reviews.

When an inventory ledger is requested, run `mehscan investigate review-ledger
--inventory RUN/inventory --history CHUNK --output RUN/review-ledger.json`.
History roots need their matching `inventory/overview.json` and input binding.
Use the actual ledger's `reviewed` map to count reviewed IDs and check `conflicts`;
do not print the whole queue or guess coverage from response filenames. For
cross-run reuse and reopened dependencies, follow [review planning](review-planning.md).
Keep separately discovered existing IDs unreviewed until their own evidence check.
