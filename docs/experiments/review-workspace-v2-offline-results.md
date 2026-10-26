# Route context and question rendering — 2026-10-26

**Both offline corrections are implemented and verified. No provider calls were
made.** Fresh packets for wallet, deluxe and basket include bounded route source;
native outstanding checks now come from saved deciding questions. Live fact
production, reuse and cost reduction still need measurement.

## Protocol version 2

The model response keeps `updates`, `lookups` and `decisions`, but decisions no
longer contain `checks` or `blockers`. A question update can create a deciding gap
without executing a lookup, including an unavailable policy/deployment fact.
Answer updates retain its status and reason. The controller derives native
checks from unresolved questions scoped to the exact claim and blockers from
blocked-question reasons, after applying same-response updates in a preview.
Updates and drafts still commit atomically.

A `needs_review` without a saved deciding question is rejected. Settled verdicts
remain blocked by unresolved deciding questions. Answered questions and other
claims' questions do not become outstanding checks. Native count/length/line
limits are enforced without truncation. The existing native finalizer is unchanged.

The protocol is `workspace-actions-v2`. The current adapter rejects version 1
and the removed fields instead of silently changing their meaning. Historical
experiments retain their frozen version-1 packages and original answers; they
have not been rebound. Ordinary worker and checkpoint decisions retain their
existing native brief shape.

An offline projection of the actual wallet producer response removed only the
two old native-format fields, replayed the original question/answer updates and
verified the supplied source. It preserves `needs_review` and renders this check:

> Does the wallet balance route bind req.body.UserId to the authenticated caller
> before the selected read, and what policy applies to that endpoint?

The complete 366-character blocked-question reason is retained as a native
blocker, within the native 700-character trace limit. The original three
completed-verification strings remain in the archived paid answer; they were
not edited. The projection is a controller replay, not a new model response.
Native integration tests separately finalize rendered questions and obstacles.

## Source preparation

`scripts/review_workspace_routes.py` materializes small source windows at
native-reported reference locations that resemble route registrations. It reads
actual pinned source, not reference preview text. Overlapping windows from that
preparation are merged. Preparation is bounded to 64 candidate sites, eight
windows and 8 KiB of delivered source. It neither follows guard bodies recursively
nor decides which callers are authorized.

Dynamic registrations, truncated locators and preparation limits remain
explicit. Controller-owned preparation-limit receipts persist in workspace state,
survive a work split, and appear in the next packet's `primary.limits`. They are
not answered questions or authorization findings. Model actions cannot change
those receipts. The prepared source is captured with source hashes and existing
preparation attribution; the separate locator queries are reserved and journaled.

This remains an opt-in controller helper. It does not automatically discover
callers for every rule or change ordinary worker preparation. A lexical route
shape is navigation evidence, not proof of Express receiver identity, complete
registration, middleware order elsewhere, guard semantics or object ownership.
The reviewer still establishes the applicable check-to-effect relationship.

## Packet validation

Final artifacts: `C:/dmitry/scan-runs/workspace-route-context-20261026-h2`,
including `offline-packet-report.json`, per-claim locator receipts, native
journals and the six prepared session packets. Both workspaces use newly bound
version-2 packages. The earlier `...-h` directory preserves a preliminary audit
and `offline-check-rendering-report.json`; the later audit also exercises the
persisted preparation-limit implementation. Neither directory launched a model.

| Selected claim | Prepared route-window bytes per arm |
| --- | ---: |
| Wallet balance | 382 |
| Deluxe customer lookup | 255 |
| Basket item lookup | 484 |

All three canonical source sets match between the two prepared workspaces.
Each packet contains its registration and `appendUserId` call. No proposition or
applicability judgment is inserted. These window byte counts describe prepared
source, not provider tokens, unique additional input or measured savings. Global
compaction against every earlier source window is not established by this helper.

The final audit reserved/executed six native locator queries, three per
workspace, and zero model calls. Preparation through final verification took
23,610 ms for that audit. The preliminary audit also made six native locator
queries; its time and development/test work are separate from the final audit
timing. Native preparation is not free model investigation: its source payload
and execution time belong in the next experiment's whole-package accounting.

## Verification and next gate

All 52 workspace tests, eight workspace protocol tests and 35 existing adapter
tests passed; one existing adapter test was skipped. Coverage includes native
packet delivery, visible partial-source limits, controller-rendered uncertainty,
atomic rejection with paid usage retained, old-protocol rejection and actual
native finalization. Static compilation and whitespace checks passed.

The next live question is narrow: with the route source already supplied and
version-2 question handling, can the wallet producer close its remaining guard
relationship and save a bounded reusable fact? Freeze that producer-only test
before dispatch, with its native preparation cost, at most three model calls
and no automatic consumer follow-up. A complete scoped fact would permit a
separately budgeted notebook comparison. Another precise unresolved result is
not a wrong dismissal, but it is not proof of cheaper review.

The earlier attempts and their unused/expired allowances are not reopened.
Known paid development cost remains the prior smoke plus notebook producer:
three actual provider calls, 36,652 input and 1,558 output tokens, with one
additional charged local-abort reservation. The older pilot's unobserved call
remains unknown. No savings percentage or full-app readiness is claimed.
