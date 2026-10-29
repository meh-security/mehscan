# Full-app BB: stopped on receipt decoding, three known calls

The first native Sol arm stops before completing its first packet. **Three actual
provider calls have known usage; no claim has a finalized verdict.** The other
three arms are not dispatched. This is a shared native-wrapper execution defect,
not evidence for or against either reviewer workflow or model.

Preserve the research/progress and spending, retire all **585 unused reachable
slots**, and do not patch or resume BB. Commit `4cee4a1` corrects the native
receipt reader to explicit UTF-8. Any continued full-app comparison needs fresh
prepared states and a separate freeze under that corrected candidate. All four
promising modes and the quality/total-price objectives remain.

## Actual spend and coverage

| Measurement | Preserved BB result |
| --- | --- |
| Actual provider calls | 3 |
| Input / cached / output tokens | 76,741 / 0 / 1,805 |
| Provider duration | 54.862 seconds |
| Native control active duration | 68.557 seconds |
| Outer wrapper duration | 69.294 seconds |
| Standard Codex credit equivalent | 4.2883 credits |
| Standard API-rate equivalent | $0.171532 |
| Finalized claim dispositions | 0 |
| Matched first packets | 1 of 25 native packets |
| Actual paid usage unknown after reconciliation | 0 |
| Paid repairs | 0 |

Prices use the [precommitted rate basis](review-full-app-execution-plan.md), not
actual invoices. All three cache-write counters are zero. The three responses
retain inspected reset-handler selection, answer verification, registered limiter
and exact remaining seed/transformation questions. They contain research/progress,
not completed claim decisions. Do not score these as two reviewed claims, a
whole-app result, a cheap completed package or a quality loss by the model.

## Failure and reconciliation

The frozen ordinary wrapper reads `research.jsonl` with `Path.read_text()` without
an encoding. Windows chooses cp1252. Earlier AX/AZ audits exposed byte-count
inflation on text that cp1252 could decode; BB contains byte `0x8f`, which cp1252
cannot decode. The UTF-8 file is valid. Reconciliation computes 71,430 canonical
received-result JSON bytes, far below the configured ceiling. This is a decoder
failure, not budget exhaustion or a missing permission/source contract.

The decode occurs before the wrapper invokes the actual provider. The core
worker has already reserved local call slots and marks the failed attempts
conservatively unknown: 28 local slots and 25 unknown-provider flags survive in
its original artifacts. Instrumented external-provider offers/observations and
three exact provider metric records reconcile to **three actual paid calls**.
Twenty-five later local attempts fail before external invocation, with no
in-flight calls remaining. Original worker counters are not rewritten, and no
reviewer is redispatched to reconcile accounting.

The earlier diagnosis treated the default-decoding problem as conservative
byte-count inflation. That diagnosis did not cover undefined cp1252 bytes and
should have been closed before paid full-app expansion. The three-call cost stays
in the record; a corrected future attempt does not erase it.

## Surgical correction and next boundary

`4cee4a1` changes only the receipt read to `encoding="utf-8"`. A regression exercises
the actual ordinary-wrapper admission path with a forced legacy default encoding,
non-ASCII text including undefined cp1252 bytes, and exact/one-byte-under received
byte limits. It verifies both admitted and stopped calls with a deterministic
provider stub. All eleven pilot checks pass, including zero-inference native
preparation; no paid model or target application test is used for the correction.

BB's source/runtime/provider bindings remain unchanged. The four BA preparations
are now consumed or retired; the historical readiness receipt stays intact and
a separate execution receipt records that lifecycle change. Reuse the pinned
application source and source-only selections in a new preparation, but import
no BB research, source answers, progress, facts, drafts or provider session into
future model contexts. This is not a paid continuation or repair of BB.

Raw artifacts:
`C:/dmitry/scan-runs/workspace-full-app-execution-20261028-bb`.
`accounting-reconciliation.json` retains the exact metrics/receipt/error boundary;
`offline-fix-verification.json` records the test and canonical receipt result.
The original 116 selected IDs, four candidate modes and finite per-packet/global
limits remain the next intended comparison. No workflow/model winner or total
production-price conclusion is possible from this stopped attempt.
