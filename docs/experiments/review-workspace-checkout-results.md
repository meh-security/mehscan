# Checkout contrast AB: native results retained, scope handling corrected offline

Status: **the real-application comparison exposed a controller scope mismatch**.
Native Sol completes both supported source judgments in five calls. Sol workspace
stops after four calls and Terra medium workspace after two; neither saves a final
disposition. Both fail at the same exact-scope guard for different legitimate shared
research transitions. Retain their source/response traces and all prior successful
components; this is not evidence to discard shared investigation.

The targeted correction is implemented after closure at `ddfd867`, with **137
passing workspace tests**. It separates lookup beneficiaries, immutable question
ownership and claim-specific settlement. The reviewer keeps the existing
updates/lookups/decisions schema; the controller derives the added bookkeeping.
No paid call uses this correction yet, and AB is not resumed or repaired.

## Frozen real-application setup

The [plan](review-workspace-checkout-plan.md) was committed at `2aac62b`. Select
only two actual Juice Shop observations in `placeOrder`, in one native two-claim
bundle at the unchanged maximum of 20:

- `observation-review-c9a0c39dc0173eaf`, basket-item deletion at `routes/order.ts:51`.
- `observation-review-c0cad8177983505d`, wallet selection at `routes/order.ts:148`.

The native question asks whether the actual resource effect exceeds the caller's
authority. It remains unchanged. The cleanup key is the caller's basket path ID;
the wallet key is the body UserId overwritten by the applicable server middleware.
The expected positive and scoped negative have an actual route/check-to-effect
basis; no oracle scope dispute was identified in this source audit.

All arms have the same canonical 1,054 bytes of initial source, including relevant
declared Express-JWT/PDFKit/Sequelize metadata. The frozen factual preparation hook
is matched in native/workspace, and ordinary dispatch checks source parity. No old
answer, question, proposition or verdict is imported. Runtime/skill guidance match
AA. Sol and Terra descriptors use medium and CLI `0.164.0-alpha.11.1`.

Execution is serial: Sol workspace, Sol native, Terra workspace. Each has six calls,
24 query units, 512 KiB received JSON and 900 seconds per bundle; aggregate ceiling
eighteen calls. Unknown usage/global binding failures retain the existing stop
rules. An observed failed arm closes without repair while independent frozen arms
may continue. Native admission affects only a fresh private study store; workspace
has no native admission. No target application/test/build or browser execution.

## Actual cost, including rejected responses

| Arm | Final dispositions | Calls | Input | Cached | Output | Model-call time | Active execution |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Sol workspace | 0 | 4 | 70,413 | 0 | 1,623 | 53.247 s | 61.469 s |
| Sol native | 2 | 5 | 170,821 | 0 | 2,955 | 94.440 s | 100.142 s |
| Terra workspace | 0 | 2 | 31,545 | 0 | 702 | 18.219 s | 22.454 s |
| Total | 2 | 11 | 272,779 | 0 | 5,280 | 165.906 s | 184.065 s |

All eleven paid attempts have observed usage. Preparation adds 23.361 seconds,
including unused Terra native preparation. Outside-model execution is 18.159
seconds. Workspace state/work checks are 25/4.469 seconds in Sol and 13/2.333
seconds in Terra. Completed coverage differs; do not convert these time/token
ratios into package savings or model rankings. Input/output are descriptive costs.

The explicitly named X + Z + AA + AB studies now total 63 observed calls,
1,206,715 input, zero cached input, 28,036 output, 860.135 seconds model-call time
and 1,024.552 seconds active execution. This includes incomplete work and different
interventions; it is not one matched trial or total historical project spending.

Sol's six completed lookup receipts consume eight query units/24,303 JSON bytes;
Terra's four consume four units/17,548 bytes. The rejected responses' new requests
are validated before query reservation, so those requests execute no native lookup
and incur no invented query charge. Their model calls remain charged in full.

## Native source audit and rejected workspace work

Native traces the actual `/rest/basket` middleware and checkout registration,
body.UserId overwrite/rejection, basket ownership fields, checkout handler,
normal order/PDF completion and basket-item model. Its conditional finding retains
the delete effect: an authenticated caller can choose another existing basket's
ID and clear its items when checkout completes, without an owner comparison.
Authentication does not authorize that basket selection.

The scoped wallet negative is also supported. Middleware selects the accepted
authenticated subject before the handler, overwrites UserId and stops on failure;
the selected wallet read and optional debit use that same subject. This is not a
certificate for basket access, pricing/payment/rewards or key integrity. An adjacent
operation concern cannot substitute for the selected owner-binding mechanism.

Sol workspace retrieves the complete handler, actual route/prefix source and both
authorization helpers. Its fourth response proposes a source-cited wallet negative,
records a conditional wallet proposition/applicability, leaves basket policy open,
and asks for basket-owner evidence. The controller rejects that entire response:
none of its proposed judgment/interpretation updates is saved, and its requested
new lookups do not run. The wallet draft remains an **unaccepted paid candidate**,
not a classified/native-validated disposition. Its prefix citation also ends before
the actual prefix statement; a reviewable final result would need that citation
corrected. Preserve the candidate without promoting it after a protocol fix.

Terra retrieves the handler and locates registration. Its second response keeps
separate basket/wallet questions open and asks for route source that benefits both.
It proposes no verdict. That response is rejected before its route reads execute.
These partial investigations remain useful; neither is a completed workspace review.

## The two scope failures

**Sol: narrowed continuation with partial closure.** The saved shared question
names both claims. The next lookup names only basket cleanup, while the response
settles wallet ownership and explicitly says basket policy still needs evidence.
The controller requires exact question/lookup membership equality and raises
`question ID already has another scope`. The natural partial-closure transition
cannot be expressed without additional model bookkeeping.

**Terra: shared retrieval beneficiaries.** The saved basket question owns only the
basket claim; a distinct wallet question also exists. The next lookup lists both
active claims as beneficiaries, but both native query attributions still name the
basket claim. Exact equality rejects this too, even though shared route source is
legitimately useful to both and no answer has transferred between questions.

Stable question ownership, the consumers of a retrieval and settlement of one
claim's part are different relationships. Treating them as one immutable ID set
turns ordinary shared investigation into a fatal protocol error.

## Post-closure surgical implementation

`ddfd867` makes these distinctions in the existing controller/state:

- Lookup beneficiaries can narrow or widen among active claims in the visible
  work item. The question's original IDs/wording remain unchanged. Each query's
  prompting/native attribution must still belong to that question and its declared
  beneficiaries. Cross-work, unseen-question and foreign-attribution checks remain.
- An explicit source-cited settled decision, paired with continuation of that
  shared open question for other claims, can settle only this claim's part. The
  controller records `resolved_questions` on its draft and shows
  `settled_review_ids` in the question view. The shared question remains open for
  its other owners. Narrowing alone, retrieval alone or a `needs_review` decision
  does not settle a sibling.
- Other unanswered questions still prevent closure. Source proofs stay visible
  after focus changes. Changed shared answers or a renewed lookup benefiting a
  settled claim conservatively reactivate affected drafts; stale source still
  blocks reuse/finalization. Broad answer revisions may require reaffirming an
  earlier partial decision rather than silently preserving an outdated conclusion.

The seven new regressions cover widened sharing without answer transfer, foreign
attribution rejection, narrowing without automatic settlement, explicit partial
closure through native finalization, missing-proof atomic rejection, retained-proof
freshness/reopening and foreign question-resolution rejection. All **137 workspace
tests pass in 131.249 seconds** with the actual native scanner and deterministic
provider replies. The current proof is persistence/enforcement, not live model
quality recovery. No old paid answer or workspace is replayed under new code.

Read-only closure verifies 160 frozen AB artifacts, provider usage, deciding-file
hashes and unchanged archived runtime. The post-closure implementation record and
test log are separate from the original audit/gate. All original failed calls and
the two native results remain intact.

## Concrete continuation and progress ledger

An unapplied `carry-source-proposal.json` selects eight non-contained source windows
already captured successfully by Sol, freshly checks their whole-file hashes and
fits the existing `prepare_evidence` limit. It carries the handler, route/identity
source and declared metadata, with no answer/verdict/proposition/question import.
No model call has used it. Fresh runtime-bound completion can therefore reuse
retrieved source instead of rebuilding that context after the code change.

Next complete only these two workspace reviews with the corrected scope behavior,
using that carried-source assistance explicitly and keeping the saved native result
as reference. Match any carried source between the two model variants. Such a
completion is not an autonomous same-input confirmation or paired native latency
estimate; record any natural scope transitions separately from deterministic tests.
There is no reason to rerun native or earlier successful controls merely to finish
this local correction. No generic prompt paragraph or new reviewer fields are
needed for the observed error.

The two formerly deferred R-main IDs now have native completion in independent AB;
their workspace attempts remain incomplete. R's original main execution is still
unrun. Fourteen other R-main IDs and eight reserves receive no dispatch in this
comparison sequence; earlier independent baselines/source audits are not an unseen
holdout. Keep AA's six local outcomes and X/Z successes. The external AA binding
copy remains unrun and outside AB. Full-app dispatch is not authorized by unused
AB allowance.

Raw study: `C:/dmitry/scan-runs/workspace-checkout-20261027-ab`, including original
freeze/execution/metrics/traces, `source-audit.json`, `component-outcome.json`,
`study-closed.json`, `post-close-implementation.json` and the verification log.
