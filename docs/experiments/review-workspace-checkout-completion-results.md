# Checkout completion AC: reuse source, retain the remaining proof gap

Status: **both models finish the two workspace reviews without controller errors**.
Sol uses two calls, retrieves the remaining ownership/policy evidence and supports
both selected mechanisms. Terra uses one call and supports the wallet negative,
but assumes the basket's protected ownership policy without inspecting the required
source. Keep these three supported mechanism outcomes, the fourth finding's
specific basis gap and all previous results separately. Shorter execution alone
does not make Terra's package stronger.

All four final dispositions pass native validation and match the saved AB native
labels. That is not four complete semantic proofs. Sol also has one imprecise
wallet citation; the audited evidence map supplies the correct pointer separately
without rewriting its model answer. No incorrect safe dismissal was identified.

## What was frozen and supplied

The [plan](review-workspace-checkout-completion-plan.md) is frozen at `ef3d416`.
Source, two native IDs/properties, scopes and expectations match AB. Fresh state
contains no old verdict, answer, proposition, applicability or machine question.
Both models receive the same eight successful AB source windows, recaptured by
`prepare_evidence` against whole-file hashes. The source assistance is Sol-derived
and matched, including information Terra's failed AB run had not retrieved.

Actual initial source is **21,093 bytes in ten displayed windows**: eight carried
windows plus the two original overlapping snippets. Source is reused, not perfectly
deduplicated. The existing declared dependency metadata remains supplied. Normal
target interpretation/binding and any missing policy still require review.

Before dispatch a deterministic regression reproduces another boundary: declaring
a shared question and settling one claim on the same first turn. The controller
now derives settlement from the fully previewed question state, covering that case
as well as later continuations. **All 138 workspace tests pass in 134.117 seconds**
before inference. The model schema/guidance is unchanged. This extends `ddfd867`;
the only runtime files changed from AB are workspace state/actions.

Models are `gpt-6.1-terra` and `gpt-6.1-sol`, both medium, CLI
`0.164.0-alpha.11.1`. Execution is serial, Terra then Sol, with six calls/24 query
units/512 KiB received JSON/900 seconds per bundle and the existing dataset safety
ceilings. Three of twelve allowed calls are used. No paid repair, native model
rerun, old-workspace migration, wider dispatch or native admission follows.

## Actual cost

| Assisted completion | Calls | Input | Cached | Output | Model-call time | Active execution |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Terra medium | 1 | 19,070 | 0 | 730 | 14.191 s | 16.887 s |
| Sol medium | 2 | 41,423 | 0 | 1,800 | 53.298 s | 58.806 s |
| Total | 3 | 60,493 | 0 | 2,530 | 67.489 s | 75.693 s |

All three paid attempts have observed usage. Preparation adds 26.901 seconds,
including unused native preparations. Outside-model execution totals 8.204 seconds.
Workspace state/work checks are 10/1.784 seconds in Terra and 18/3.228 seconds in
Sol. Sol's three new lookups consume four units and 13,083 received JSON bytes;
Terra makes no lookup. Distinct captured-window bytes are 32,125/21,093 respectively,
including overlapping source windows rather than deduplicated logical lines.

AB plus AC costs **14 calls and 259.758 seconds active execution**, including the
two failed workspace attempts and saved native reference. The explicitly named
X + Z + AA + AB + AC studies total **66 observed calls, 1,267,208 input, zero cached
input, 30,566 output, 927.624 seconds model-call time and 1,100.245 seconds active
execution**. This is not total historical project spending or one paired trial.

The new initial source differs substantially from AB's original 1,054-byte packet.
Two assisted Sol calls cannot be advertised as replacing five native calls under
equal starting conditions. Retain prior retrieval costs; do not rank models by
their call counts when proof depth differs. Input/output reductions remain descriptive.
AB plus AC Sol workspace actually consumes six calls/120.275 active seconds versus
the saved native five/100.142 seconds. Completion improved; this development
sequence has not demonstrated a net primary-arm execution saving.

## Deciding work, outcomes and limits

Sol closes the wallet on turn one using the carried route/identity/handler source.
It opens a basket-only question and requests three facts that could change the
remaining verdict:

1. `models/basket.ts`: establish the user ownership field.
2. `server.ts:420–590`: inspect the intervening registration/middleware region for
   an applicable owner check between the supplied guards and checkout route.
3. `retrieveBasket` in `routes/basket.ts`: establish the adjacent source-level
   policy distinction between the authenticated user's basket and another basket.

Turn two answers that question and reports the conditional basket deletion issue.
No query rereads the carried handler or identity helper. The normal
orders-insert → `doc.end` → writer-finish → delete relationship is present in the
carried complete handler. The wallet negative does not certify basket, payment,
reward or signing-key safety. The new reads are targeted policy/check-to-effect
work, not repeated exploration of already supplied source.

Terra decides both immediately. Its wallet negative has the required overwrite,
failure-stopping and same-subject selector basis. The basket finding's control-flow
mechanism agrees with the actual snapshot, but no delivered window establishes
the required owned-resource policy; it neither retrieves the basket model nor
inspects the adjacent policy source. This is an incomplete reviewer basis, not a
demonstrated wrong finding. Its high severity versus Sol/native medium is another
reason not to infer a model ranking from its one-call result.

Neither run exercises the exact repaired narrowed/widened **shared-question**
paths or stores a derived `resolved_questions` entry. Sol's newly created question
owns only the still-open basket claim. Thus AC supports carried-source completion
and ordinary partial closure; the scope correction's direct proof remains the
deterministic tests. Both changed runtime and source assistance prevent a causal
claim that the fix alone produced recovery.

## Audited evidence map and source-profile correction

The separate
[audited evidence map](/C:/dmitry/scan-runs/workspace-checkout-completion-20261027-ac/audited-evidence-map.json)
links each selected mechanism to actual source coordinates and hashes. For wallet
ownership, the applicable prefix is `server.ts:356`, checkout registration
`server.ts:604`, overwrite/rejection `lib/insecurity.ts:175–184`, and selected
read/debit `routes/order.ts:146–153`. Sol's original wallet citation
`server.ts:352–353` misses the prefix. The correct statement was delivered in its
full source window; the coordinate issue is retained as artifact QA, with an
independently audited pointer, not a silent edit to the paid answer.

This experiment also exposes a **profile-construction gap**. The carry proposal
used only Sol workspace's successful AB captures. AB native had already inspected
the basket owner/deletion model, and AC Sol now retrieved ownership/policy source
again. Those valid source observations could have been reused across arms without
importing any conclusion. Missing context need not become another prompt warning
or an unchanged paid checkout rerun.

An unapplied `extended-carry-source-proposal.json` combines verified source already
seen by AB native and AC Sol. It removes the three metadata request entries that
the normal preparation hook already supplies, and uses those slots for the basket
owner model, adjacent basket policy and deletion-model source. The request still
fits eight windows. Raw text is checked against current whole-file hashes and
recorded lookup provenance. No old verdict/answer is carried; no new native or
model call runs on this profile. This is a source-only preparation correction,
not a second claimed live result or a new generic memory subsystem.

Closure verifies **175 frozen artifacts**, exact model descriptors, all supplied
and newly captured source hashes, observed counters and unchanged AB audit/results.
Raw study: `C:/dmitry/scan-runs/workspace-checkout-completion-20261027-ac`, including
freeze/execution/metrics/traces, `source-audit.json`, `component-outcome.json`,
`study-closed.json`, the audited map and staged extended profile. The audit is by
the implementation agent, not independent human ground truth.

## Practical next direction

Retain Sol's completed pair, Terra's supported wallet result and its explicit
policy gap. Use the audited checkout map as regression evidence. The next source
profiles should draw relevant, hash-verified observations from both native and
workspace receipts for the same claims/source binding, while keeping judgments
and caller applicability separate. Reuse the existing preparation API; avoid
preloading every file merely because it was once fetched.

Move to a new small real shared operation rather than repeat checkout to collect
one omitted fact. The prepared Directus single/batch file-delete pair is a concrete
candidate: audit actual route/accountability → service permission → delete-effect
bindings first, then freeze a bounded comparison. Its source audit may change the
selection; no expected safe verdict is accepted from a service name alone. Keep
the fourteen other R-main IDs/eight reserves and full-app scope separate until
explicitly selected. R's original main execution and the unrun AA binding copy
remain untouched.
