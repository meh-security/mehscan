# Review failure isolation — 2026-10-29

User direction: skip failed independent work and continue the rest. Quality and total package price remain primary; skipped claims are execution gaps, never inferred verdicts.

## Current experiment

Study: `C:/dmitry/scan-runs/stable-full-20261029-bk`.

The original hybrid controller stopped all dispatch after one workspace schema rejection. The rejected response cited navigation-result IDs where source handles were required. Keep that rejection; do not weaken local validation or manually admit the response. One workspace claim had already been accepted; seven remained unfinished.

A study-only recovery runner preserves original artifacts, paid usage, query/byte charges and elapsed component budgets. It treats failed units as terminal only for scheduling independent work. Product code and the frozen experiment inputs are unchanged.

The first recovery exposed a wrapper defect: `elapsed_ms` was checked inside `usage`, although provider metrics store it at the top level. The actual first recovery call has a valid receipt (37,714 input tokens, 829 output tokens, 11,776 ms). The next reservation failed the wrapper assertion before provider dispatch. No round-1 provider directory exists. The second recovery retains that reservation charge, records its proven zero provider usage, preserves the original failed artifacts, and skips this interrupted native group too. It continues the other 14 pending native units. This adds seven native execution gaps to the seven unfinished workspace claims unless separately recovered later.

Runner: `recover-independent2.py`; process logs: `hybrid-recovery2-stdout.log` and `hybrid-recovery2-stderr.log`. Its offline checks passed before launch. The original analyzer reported only the first hybrid attempt; it has now been extended and verified for combined recovery accounting.

## Intended policy

- Invalid response or exhausted local budget: preserve accepted work and receipts; isolate the affected investigation; continue independent units.
- Shared facts from rejected responses are not admitted or reused. Dependent work must retain the missing-evidence boundary.
- Unknown provider usage requires reconciliation before claiming total cost. Shared source/runtime integrity failure blocks affected dispatch.
- Report reviewed claims, complete original bundles, execution gaps, rejected calls and total paid usage separately. A partial arm cannot win a full-package price comparison.

Recovery is now complete: 102 source-validated claims, 14 explicit gaps, 23 complete original bundles, 82 actual provider calls, and $1.421542 total Standard API equivalent. All 14 independent pending groups finished. The analyzer now reconciles both recovery attempts, the proven non-dispatch reservation, raw receipts, the partial package and physical source excerpts. See the [full results](review-stable-full-native-hybrid-results-2026-10-29.md). A later bounded workspace test can constrain stable evidence strings to the source-handle syntax while retaining exact local handle validation.
