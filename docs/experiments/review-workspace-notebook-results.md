# Bounded notebook milestone — 2026-10-26

**The handoff is implemented and tested offline. The live trial stopped before
notebook delivery.** The wallet producer returned a source-validated
`needs_review` with an actionable route/middleware gap and saved no proposition.
Neither consumer arm ran. Live reuse and savings remain unproven.

## Implementation

`scripts/review_workspace_notebook.py` exports all available producer
interpretations, bounded to four propositions and 8 KiB with supporting source.
Import checks the snapshot/root and actual source hashes, preflights the complete
handoff, and uses existing source/proposition/focus operations with idempotent
receipts. An interrupted import can resume before the notes are focused into a
consumer context. It is not an atomic cross-workspace transaction; callers hold
the native controller lock and complete import before dispatch.

Imported notes retain conditions and exclusions. Their names are scoped to the
producer binding/selection; receipts map producer revisions to recipient
revisions and retain original evidence attribution. Recipient source preparation
does not invent another native query. No verdict, applicability, question,
conversation, credential or paid usage is copied. Explicitly importing a revised
note invalidates recorded local consumers; there is no automatic distributed
revision subscription. Replaying an old import cannot resurrect a changed or
disputed recipient note.

The native-bound experiment also supports disabling cross-work knowledge lookup.
Both trial arms disable it, so the control cannot retrieve an earlier claim's
interpretations and the treatment receives only the explicitly supplied notebook.
Ordinary source lookup and current-work notes remain available. The toggle is
experimental and defaults to the previous behavior.

Six notebook tests cover supplied-notebook visibility, owner-scoped versus
route-ID effects, unresolved caller context, separate work items, interruption,
source/binding mismatch, byte limits, revision invalidation and old-note replay.
All 44 workspace tests and seven protocol tests passed. A subsequent native
integration regression for the dispatch callback also passed, bringing current
workspace coverage to 45 cases. These deterministic assessments are controller
fixtures, not evidence of model judgment or savings.

## Binding and execution

Artifacts: `C:/dmitry/scan-runs/workspace-notebook-20261026-g`, particularly
`m1-binding.json`, `m1-correction-binding.json`, `producer/local-abort-proof.json`,
`producer_corrected/result.json`, `trial-result.json` and `closed.json`.

The preceding smoke experiment's absolute window had expired without any M1
call. It was closed as expired. This separately bound M1 phase retained the
remaining 13-call, 187,335-input and 13,111-output ceilings and declared a new
900-second preparation/execution deadline. The elapsed gap between phases is
recorded; the phases are not presented as one run inside the original window.
The three initial claim-source receipts match between consumer workspaces.
Provider/model/effort remain the smoke check's `gpt-6.1-sol`, medium, CLI
`0.164.0-alpha.11.1`.

The first producer reservation aborted locally before provider dispatch: the
trial callback called the previous-usage guard after reserving its own call.
That guard correctly rejected the pending reservation. The callback must use
the deadline already supplied by the controller. The exception location, absence
of an invoked-task artifact and absence of any private provider store confirm
that this specific reservation incurred no provider usage. It was accounted as
a proven local zero-cost abort; the reservation remained charged. This reasoning
does not apply to the older genuinely unobserved timed-out provider call.

The original runner/result and proof remain preserved. A frozen runner amendment
uses the supplied deadline, grants only the two remaining producer calls, and
extends neither the total call ceiling nor the absolute deadline. A native
integration test now exercises this callback boundary. This was a trial-runner
bug, not a failure of source review or notebook applicability.

## Measured result

| Measurement | M1 actual |
| --- | ---: |
| Charged reservations | 3 |
| Provider calls | 2 |
| Unobserved provider calls | 0 |
| Input / cached input tokens | 23,987 / 0 |
| Output tokens | 669 |
| Reported model time | 27,245 ms |
| Corrected producer execution | 32,703 ms |
| Phase preparation through corrected result | 319,784 ms |
| Lookup units / received result JSON | 3 / 7,261 bytes |
| Consumer calls | 0 |
| Native state admissions | 0 |

The producer's first paid turn asked for the wallet file, wallet references in
`server.ts` and authorization guidance. The returned references locate the route
around `server.ts:626–627`; they do not supply its source. On the final paid turn,
lookup allowance was disabled because no further producer call remained. The
model correctly retained the question of whether middleware binds `UserId` to
the verified caller. It did not assume an authorization weakness from a body
field name alone.

The result was finalized against native source, but notebook export refused an
empty proposition set. The trial is classified as `stopped_no_producer_fact`,
not a successful reuse comparison. The local abort consumed one of the original
three producer slots, so two paid turns cannot establish that the intended
three-turn producer would have failed. No consumer cost comparison is possible.

Including the earlier smoke check, actual paid work is three calls, 36,652 input
and 1,558 output tokens; charged reservations total four. These are development
costs, not savings. Neither completed coverage nor a memory benefit is implied.

## Next correction before another live attempt

1. **Supply the exact operation relationship for authorization review.** Use
   native caller/reference evidence to include the bounded route declaration,
   under the same preparation policy in both arms. Keep guard implementation
   expansion as a deciding lookup. Do not preload an audited authorization verdict
   or start exhaustive caller traversal. The current producer spent its first
   round locating source that another round would have needed to read.
2. **Derive native outstanding checks from retained questions.** The producer's
   blocker and blocked-question reason are actionable, but its `checks` array
   contains completed verification narratives. These survived native formatting.
   Avoid another repeated instruction about field vocabulary: design a compact
   model contract with an explicit unresolved relationship and have the controller
   render native `checks` from that state. Audit the mapping before changing it;
   do not alter this paid answer or clear its uncertainty.
3. **Keep the next test focused on fact production and delivery.** The notebook
   implementation is ready for a bounded fact. First prove that source preparation
   exposes the route without a discovery-only model round. Freeze any subsequent
   producer test separately with full costs and the prior failures linked.

The attempt is closed. No extra paid correction, consumer run, SQL grouping or
full-app run follows automatically. The source preparation and outstanding-check
mapping are offline implementation work for the next milestone.
