# Workspace context fix and login smoke check — 2026-10-26

**M0 passed.** One fresh replay of the saved post-lookup login task completed,
reported usage, answered the deciding question and produced actions accepted by
offline controller replay. This permits preparing the notebook experiment; it
does not establish live reuse, reduced cost or the cause of the previous stall.

## Implemented corrections

`Workspace._view` now keys lookup receipts by lookup ID and includes question ID
on each receipt. Distinct navigation answers under one open question remain
visible together. Source excerpts remain stored separately; answered questions
leave the active view. Context overflow is explicit instead of silently dropping
a result. This conservative first fix retains all receipts for open questions;
it does not yet compact redundant attempts within an unresolved question.

The pilot runner now reserves each arm's execution exclusively before dispatch.
An existing reservation or result blocks accidental reruns, including interrupted
attempts. Restart does not replenish the deadline. Ordinary incomplete summaries
report attempted/observed/unobserved calls and observed cost separately; totals
remain unknown when a reserved call has no metrics. Workspace usage already
retained that distinction. These are experimental runner changes, not new
ordinary-product scheduling or native admission behavior.

The new navigation regression and restart/unknown-accounting tests passed.
All 38 workspace/state/action/bridge/pilot cases passed across the suite and the
targeted rerun after correcting the new test's missing source proof. Seven
workspace protocol tests and 35 existing adapter tests passed; one adapter test
was skipped. The adapter's real process deadline test passed. Saved search
responses were also replayed offline: the original remained rejected for
outstanding-check field misuse; the corrected answer remained accepted.

## One-call execution result

Artifacts: `C:/dmitry/scan-runs/workspace-smoke-20261026-f`.
Private provider state is outside exports. `run-binding.json`, `run-smoke.py`,
`smoke/result.json`, `source-audit.json` and `offline-replay.json` retain the
bindings, execution outcome and audits. The old native work/source binding was
verified before preparation. The saved evidence packet is byte-identical to the
timed-out login turn's packet; task conversation/artifact paths were rebound.
The provider, model, effort, review contract and schema were retained.

The provider deadline was 170 seconds, inside a 180-second controller deadline,
to allow cleanup before the outer process limit. Historical review allowances
were retained in the replay prompt; the diagnostic runner permitted exactly one
call and executed no returned lookup. It performed no native finalization or
native state admission.

| Measurement | Actual result |
| --- | ---: |
| Attempted / observed / unobserved calls | 1 / 1 / 0 |
| Input tokens | 12,665 |
| Cached input tokens | 0 |
| Output tokens | 889 |
| Reported provider call time | 28,310 ms |
| Controller execution wall time | 28,431 ms |
| Preparation through result wall time | 186,172 ms |
| Reconstructed prompt / schema bytes | 15,918 / 13,183 |
| Executed lookups | 0 |

An initial pre-dispatch hash check rejected a duplicate Windows path key with a
stale packet hash. No execution or model call had been reserved. The original
preflight binding and zero-call rejection are preserved; the manifest was
normalized before launch. Its preparation time is included above.

## Source and action audit

The answer closes `q-login-prequery`: the preceding challenge helper does not
escape or transform email. It identifies raw email interpolation into the Users
query and retains the TOTP condition on full login/token issuance. It saves a
scoped proposition, records applicability and returns an `issue` decision with
no outstanding checks. It requests no more evidence.

Offline replay against current controller state accepted the answer update,
proposition, applicability and draft atomically. All three supplied source
windows were checked against the pinned source; decision citations stay inside
those windows. This audit adds no model calls. It validates this local mechanism,
not the wider authentication implementation or the future reuse consumers.

## Next gate

Implement the bounded notebook handoff and real caller fixture from the
[next-work plan](review-workspace-next-plan.md), then freeze the wallet producer
and the deluxe/basket consumer comparison. A SQL-specific proposition from this
smoke check is not the shared identity fact needed for that experiment.

The proposed shared allowance has consumed one call, 12,665 input and 889 output
tokens. At most 13 calls, 187,335 observed input and 13,111 output tokens remain;
the original whole-run deadline must also be retained. If preparation cannot
finish before that deadline, stop this attempt and explicitly freeze any later
experiment rather than resetting its elapsed allowance. No consumer calls have
been launched. The failed earlier pilot's unknown call remains unknown and is
not converted into a known total by this successful diagnostic.
