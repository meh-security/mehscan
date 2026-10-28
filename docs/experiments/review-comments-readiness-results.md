# Directus comment mutation readiness AW

**All four actual initial packets pass readiness:** native and workspace for Sol
medium and Terra 6.1 medium. They contain the same physical source fragments and
preserve the exact selected native question/context. Both workspace packets fit
the frozen context bound. There are **zero provider reservations or model calls**,
no target execution and no new reviewer behavior.

This completes the source/packet preparation stage of [AV's frozen-candidate
validation plan](../review-workflow-freeze-and-validation.md#finite-validation-and-stopping-decision).
The implementation remains `a0feb12`; the preparer imports AV's archived
`frozen-candidate/` and checks the current repository against the same 68 hashes.
It does not modify the frozen contract, defaults, grouping engine or memory code.

[Precommitted readiness plan](review-comments-readiness-plan.md).
Artifacts: `C:/dmitry/scan-runs/workspace-comments-readiness-20261028-aw`.
Readiness ID: `7f3b74a59f04631b6be042562490dfb73153a7222a572ae15676d60b70311bd1`.
Private preparatory stores/configuration are in the matching `scan-private/`
directory. This is not yet a live execution freeze or a security result.

## Bounded deciding work

The four admitted markers select bulk/single PATCH and bulk/single DELETE in
`api/src/controllers/comments.ts` at lines 99, 135, 161 and 184. Their actual native
question asks whether the exact unauthorized action is rejected before its
protected effect, including inherited policy. The ordinary selected native
manifest contains one four-claim packet under the unchanged maximum 20.

The supplied source connects each controller branch to `CommentsService`, its
inherited dispatch and the update/delete policy calls and effects:

| Supplied source | Coverage |
| --- | --- |
| `controllers/comments.ts:1–199` | Complete selected controller, accepted request shapes, selectors and response handling |
| `services/comments.ts:1–215` | Complete concrete class, accountability, update/delete overrides and delegation |
| `services/items.ts:1–120` | Imports, constructor, concrete-class fork and query-key helper |
| `services/items.ts:645–1010` | Single/query/batch update dispatch and complete update implementation through return |
| `services/items.ts:1080–1225` | Query/single/many deletion through checks, effect and return |
| `permissions/modules/validate-access/validate-access.ts:1–57` | Complete access validator, admin branch, item/collection dispatch and rejection |
| `permissions/modules/validate-access/lib/validate-item-access.ts:1–175` | Complete item/key/field validation path and permission-query delegation |
| `app.ts:1–365` | Imports, relevant preceding middleware order and `/comments` mounting |

All paths above are under `api/src/`. The profile has eight windows and **51,343
normalized source bytes**, within the existing 400-line/16-KiB per-window and
64-KiB per-target bounds. Each window retains its full-file hash and precise
completeness metadata. Actual line counts are checked before preparation; no
requested proof span is clipped.

This source demonstrates real control/effect and dynamic dispatch code, not
merely similarly named helpers. It still supplies no security verdict. Update
and delete require their own action/key/field analysis; the batch fork does not
make their policies interchangeable. Deployment policy, hook behavior, payload
processing and accountability may remain material where the actual source leaves
a deciding gap. They must not turn automatically into exhaustive application review.

`available-helper-catalog.json` records twelve additional source edges for the
existing lookup API, including authentication, batch/query validation, policy and
payload processing, permission fetching and the permission query builder. It is
an operator preparation artifact, not model guidance or a mandatory checklist.
Source tests are retained as available source evidence and are not executed.

## Actual packet comparison

All four packets have **1,643 identical physical path/line keys**, including exact
source fragments. Native presents twelve source records because ordinary inline
excerpts overlap the explicit profile; workspace presents eight captured windows.
This is the frozen engine behavior, not a new native deduplication intervention.
Native question fields and context are compared through the actual sweep
question/card relationship, preserving bundle-local identities.

| Captured initial packet | Compact packet bytes | Raw prompt bytes | Addressed prompt bytes |
| --- | ---: | ---: | ---: |
| Sol native | 90,680 | 108,476 | 120,957 |
| Sol workspace | 72,950 | 80,835 | 92,473 |
| Terra native | 90,686 | 108,478 | 120,959 |
| Terra workspace | 72,954 | 80,835 | 92,473 |

Workspace fits the explicitly configured 147,456-byte bound without source
truncation or a larger allowance. Prompt bytes are captured formatting measurements,
not model token usage, live budget-injected prompt totals or demonstrated savings.
Native and workspace contract/guidance delivery still differ: this is readiness
for a complete engine-package comparison, not isolated attribution to memory.

Raw/addressed projections round-trip to the entire original packet/fact objects.
Every displayed addressed row is checked against physical source; partial-column
and exclusive endpoint metadata are preserved. No raw source/artifact handle,
question, condition or provenance field is discarded to obtain parity.

## Source/state/accounting checks

Native actual packet capture intercepts `provider_started` before reservation;
a separate execution guard forbids the provider command. Both native offline
jobs record zero calls, no in-flight attempt and zero unknown usage. Their
intentional stop is not a paid review failure or a security disposition.

Workspace actual preparation runs only on offline copies. Both real workspace
state identities remain unchanged, with no sessions, calls, propositions,
questions, applicability or drafts. No old reviewer state or desired labels are
imported. Original native control/workspace execution markers remain absent.

`readiness-bindings.json` verifies **226 immutable input/capture files, eighteen
source files and nine provider configuration/command/executable files**. The
prepared model descriptors are `gpt-6.1-sol` and `gpt-6.1-terra`, both medium, with
`line-addressed-v1` configured in both engines. All closed AR/AS/AT/AU/AV manifest
files remain unchanged. Source/native/profile operations occur, but no target
application build, install, hook or test runs.

The immutable list excludes live databases, owner/claim state, runtime traces,
provider sessions/metrics and other execution sinks. This preserves AT's harness
lesson: appending a runtime trace is not source or prepared-input drift. Initial
state identity is a dispatch precondition, not a claim that state must remain
unchanged after authorized review.

Measured successful stages:

| Stage | Seconds |
| --- | ---: |
| Shared source inventory/bundle setup | 61.335 |
| Sol native/workspace preparation | 28.298 |
| Terra native/workspace preparation | 28.403 |
| Sol / Terra actual packet capture | 4.001 / 3.802 |
| Total recorded preparation/capture | 125.839 |

The first inventory operation accounts for 59.080 seconds of shared setup.
Manual source inspection, harness preparation, verification and documentation
are additional and not fully metered. This is not a full workflow cost or a speed
comparison. No unchanged product test suite is rerun for source-only preparation;
the actual native packet/state/projection checks, compilation and whitespace
checks supply this stage's validation.

## Next boundary

The next step can be the separately frozen four-arm comparison already proposed:
Sol native/workspace and Terra native/workspace, one matched unit each, six
calls/24 query units/512 KiB received JSON/900 seconds per arm, at most 24 calls.
Use ordinary native validation-only review and workspace finalization without
state admission. Keep the candidate unchanged and use counterbalanced engine
order. Preserve supported source conclusions, scoped negatives and actionable
uncertainty; no desired safe/issue labels enter provider input.

Before the first call, recheck these immutable/source/configuration hashes and
the real undispatched state identities under a new execution freeze. These
prepared stores may be retained with their existing bindings; they are not old
paid sessions or retired allowances. Drift requires fresh preparation. AW does
not create a paid execution allowance or launch the comparison automatically.

The four claims already share an eighteen-claim population bucket. Moving only
them to workspace leaves fourteen peers and adds a population context. A selected
one-packet versus one-packet comparison can test quality/state reuse, not fewer
conversations. This potentially clean family is not an independently adjudicated
balanced whole-app benchmark. Stop after the finite comparison decision rather
than forcing a consumer transition or reopening the Juice experiment loop.
