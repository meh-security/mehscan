# Review completion fixes — 2026-10-30

The two-app run exposed two controller defects: native protocol repair disclosed
only the first invalid query, and workspace offered research on the last call
without leaving an opportunity to interpret its results. Both paths are now
corrected. The original [FlaskBB/crAPI results](review-two-app-validation-results-2026-10-30.md)
remain unchanged; this is implementation and offline validation, not a new live
quality or price result.

## Native batch repair

The controller compiles the complete batch before dispatch. It collects the
existing repairable argument, range, result-limit and file/directory errors by
zero-based query index, and reports an excessive total query cost in the same
feedback. It retains the existing single correction allowance and first-error
compatibility fields. Feedback includes at most 32 entries with explicit total
and truncation indicators. An index of null denotes a batch-wide budget error.

Invalid batches execute no valid prefix, reserve no research units and create
no journals. Unknown tools, invalid attribution, escaping paths and other
unrecognized failures still fail closed; aggregation does not turn them into
repairable requests. Controller feedback is explicitly not source evidence.

Replaying the exact crAPI replies against its pinned source detects:

- Original round 0: source range at query 0 and directory-only definition
  filters at queries 7 and 8. All three are now disclosed in one correction.
- Original round 1: directory-only definition filters at queries 8 and 9.

These replies cost 12 and 13 research units respectively, within the original
24-unit ceiling. No replay query was executed and no replacement verdict was
created. This does not demonstrate how a live reviewer will use the feedback.

## Workspace final checkpoint

The current call counts toward its offered allowance. The final checkpoint is
determined by the minimum of aggregate calls remaining and any controller-bound
work or case call allowance. Its local schema and prompt disable lookups and
require a decision for every offered claim. A concrete `needs_review` decision
is an appropriate conclusion when evidence remains insufficient. Existing
question, source, proof and native-finalization guards still apply.

The controller also enforces this boundary for alternate adapters, before
applying response actions or running research. Aggregate usage is refreshed
before each dispatch, including a bounded proof correction, so a correction
cannot rely on a budget snapshot from before its rejected paid predecessor.
Corrections retain their existing restriction to auxiliary proof references;
they do not permit rewriting verdicts or purchasing another synthesis call.

The saved FlaskBB final task had five of six calls used and eight query units
remaining. Its original research reply passes the frozen old schema. The new
local schema requires 17 decisions and no lookups, and rejects that same reply.
The stable provider wire schema remains unchanged for these saved turns and is
constant across the new earlier/final checkpoints. Runtime constraints are
checked locally after receipting the paid attempt; violating responses remain
visible failures, not automatically invented conclusions.

## Validation and limits

The offline replay checks both unmodified native replies and the unmodified
workspace task/reply. All 95 checked historical inputs, receipts and completion
records retain their original hashes. It creates no judgments, dispatches no
provider calls and incurs no reviewer-provider spend.

Regression coverage exercises a complete mixed-error native batch through its
single charged correction, batch atomicity, unsafe-path rejection, bounded
feedback, query-cost accounting, aggregate/work/case final-call constraints,
stable schemas, receipted invalid replies, correction usage refresh, alternate
adapter enforcement and a six-call workspace ending in a supported issue plus
precise uncertainties through ordinary native export.

Checks completed:

- Provider adapters: 71 tests, 70 passed and one optional skip.
- Workspace actions and normal export: all 24 passed.
- Hybrid scheduling and shared allowances: all 12 passed.
- Native worker: 74 tests, 72 passed, one optional skip and one fixture-setup
  rejection during the initial run. The skill runtime was edited while that
  fixture prepared its contract, so the existing `review runtime skill changed`
  guard correctly blocked setup. The affected definition-lookup test passed on
  an unchanged isolated rerun (14.426 seconds). This was not one clean full-suite
  pass; the initial failure log is retained alongside the isolated result.
- Exact saved-reply replay and `git diff --check` passed.

Artifacts: `C:/dmitry/scan-runs/review-completion-fix-20261030-ck` contains
`replay.py`, `replay-results.json` and test logs. The replay records exact input
and changed runtime hashes. No old CJ workspace is resumed with new code, and
its expired deadlines and exhausted allowances are not reset.

Stop implementation tuning once these checks pass. The next live completion
gate, if requested, should use a fresh binding for the failed native resource
bundle and the auth-form workspace, with their original workload and bounded
allowances. Keep total price, failures, unresolved claims and flow quality in
the comparison. A successful schema gate alone does not establish live
completion or settle the separate generic HTML review-quality question.
