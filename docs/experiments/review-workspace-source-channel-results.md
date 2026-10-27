# Common explicit source channel AF: implemented, review closure still incomplete

Status: **implementation committed; three-family packet matrix passes; bounded
live study closed at 17 observed calls**. The source channel fixes AE's transport
failure. It does not demonstrate faster review or a completed authorization proof.
Keep the successful implementation, Terra's retained uncertainty, Sol's lost final
qualification and native's bounded failure as separate results.

Code: `c2b06c7`. [Frozen plan](review-workspace-source-channel-plan.md).
Raw artifacts: `C:/dmitry/scan-runs/workspace-source-channel-20261027-af`, with the
completed matrix/live study in `matrix-final`. Freeze
`3be9737279ef1dd78c688ae3a72ab9340ac8140d908c10f6e82d06ad695b7572` preceded
all paid dispatches. Closure verifies 342 frozen artifacts; AB/AC/AD stay unchanged.
AE's retained artifact hashes were also checked separately (243 checks).

## Delivered capability

Native review and workspace initialization accept the same `--source-profile`.
The common reader binds source-only windows to repository, inventory fingerprint,
exact native bundle membership, physical ranges and whole-file hashes. It allows
eight windows, at most 400 lines/16 KiB each and 64 KiB per target. Invalid scope,
drift, oversized input and incomplete requested coverage fail before inference;
the controller does not silently clip the profile or infer applicability.

This path is separate from ordinary automatic policy-lead preparation, whose
four-window default stays unchanged. Native maximum reviews stays 20. The common
module is included in installed packages and Action/runtime/recovery bindings.
Workspace freezes the profile at initialization; ordinary review checks it during
inference/recovery. Profile windows enter the existing source cache.

Real packet preparation exposed three additional transport defects, corrected
before the live freeze:

- Preserve terminal blank physical lines using inclusive ranges and a final LF.
- Accept an authentic partial native snippet alongside complete requested source;
  the fragment alone cannot satisfy requested line coverage.
- Keep native bundle-level helper windows even when no per-claim consumer mapping
  is present. Sharing their source does not establish caller applicability.

The original preparation and two intermediate matrix attempts remain preserved
as superseded failures. They dispatched no models. None is relabeled a success.

## Actual packet matrix

These are real ordinary provider packets captured before call reservation and
actual workspace prepared packets. Fresh workspaces have no old questions,
propositions, applicability, answers or drafts. Each row has one native two-claim
bundle under the unchanged maximum 20. SQL uses the ordinary unprofiled path.

| Dataset | Explicit windows | Total source windows | Canonical source bytes | Preparation ms | Additional native packet ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Directus file deletion, Sol | 8 | 10 | 36,263 | 30,208 | 2,513 |
| Juice Shop checkout, Sol | 8 | 10 | 23,735 | 12,990 | 1,129 |
| Juice Shop SQL, Sol | 0 | 3 | 1,508 | 13,079 | 1,076 |
| Directus file deletion, Terra | 8 | 10 | 36,263 | 30,279 | 2,589 |

All four rows pass exact canonical native/workspace source equality, requested
coverage, scope and hashes, with zero reserved model attempts or unknown usage.
Sol/Terra Directus profiles and canonical source match exactly. This establishes
transport across three operation families, not semantic quality on checkout/SQL.
There is no paid checkout/SQL rerun in AF.

Completed preparation costs 86.556 seconds; additional native packets cost 7.307,
for **93.863 seconds**. This includes the unused checkout/SQL/native-Terra setup.
Earlier failed preparation, source selection, prior studies and engineering are
additional costs; failed attempts lack complete timing instrumentation. Do not
present 93.863 seconds as total development cost or subtract only successful
preparation when advertising savings.

The manually selected profile benefits from AD/AE source receipts and an
implementation-agent audit. App lines 1–400 now include the actual authentication
import/registration; shared constructors, wrappers and deletion effects are
supplied. Permission helper bodies remain available through lookup. This is
assisted context, not an automatic selector, held-out test or causal memory trial.
The controller header's actual FilesService import remains a lookup obligation.

## Live comparison

Fresh, serial Sol workspace → Sol native → Terra workspace, all medium reasoning,
CLI `0.164.0-alpha.11.1`. Same two AD claims and canonical initial source. Six-call,
24-query-unit, 512-KiB received-JSON and 900-second bundle ceilings; the frozen
overall ceiling was 18 calls. No paid repair or reuse of the remaining slot.

| Arm | Calls | Input | Cached input | Output | Model seconds | Active seconds | Outside model seconds |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Sol workspace | 6 | 176,618 | 0 | 3,274 | 89.461 | 122.284 | 32.823 |
| Sol native | 5 | 198,744 | 35,456 | 3,519 | 62.724 | 72.050 | 9.326 |
| Terra workspace | 6 | 184,734 | 0 | 3,284 | 70.496 | 106.098 | 35.602 |
| Total | 17 | 560,096 | 35,456 | 10,077 | 222.681 | 300.432 | 77.751 |

Cached input is a subset of input. Workspace state/work checks cost 48.511 seconds
across 95 checks: Sol 45/22.912 seconds, Terra 50/25.599. Preparation is additional
to active arm time. Input/output are descriptive, not acceptance gates.

All 17 reserved calls have adapter usage receipts. Native's raw worker summary
nevertheless conservatively flags one unknown call and incomplete usage after a
post-response `ValueError`. Preserve that flag: reconciled study usage is complete,
native execution is incomplete. No new provider call was needed for reconciliation.

The named X + Z + AA + AB + AC + AD + AF sequence now totals **99 observed
calls, 2,238,895 input, 35,456 cached input, 48,755 output, 1,365.690 seconds
model time and 1,697.012 seconds active execution**. This is neither total
historical spending nor one matched trial. Preparation/acquisition remains
additional; the earlier paid costs are not erased by source assistance.

### Deciding work and outcomes

| Arm | Requested fact → evidence → remaining question | Outcome |
| --- | --- | --- |
| Sol workspace | Delete guard → key-count evaluator → AST cases → DB query → filter composition. Each step exposes the next local helper; `getCases` and `joinFilterWithCases` remain unread. | Two independent `needs_review`; final reasons omit the storage/key qualification already saved in its proposition. |
| Sol native | Actual router import and guard → corrected evaluator lookup → evaluator tail, AST/root-field query; also follows accepted-token verification. | No final dispositions. One filter correction works; fifth response asks for a batch exceeding remaining aggregate units, rejected before execution. |
| Terra workspace | Guard/evaluator/query plus a separate hook question → emitter, registration and reference evidence. Permission enforcement is incomplete; installed key-changing hooks remain unestablished. | Two independent `needs_review`, retaining both local evaluator and storage/key/deployment uncertainty. Two filter-feedback receipts are corrected within the existing budget. |

Workspace Sol charges 18/24 query units and Terra 22/24 (19 native commands plus
three units for two feedbacks). Native retains 16/24 charged units after the
oversized final batch is rejected. Neither workspace naturally exhausts all 24
units: the sixth turn is final-only and offers zero new lookups. Native has eight
units left but requests more than eight. These are distinct stopping boundaries.

Native reads the controller header and actual service import. Neither workspace
does; matching service names and supplied app/constructor source do not close
that receiver binding. Four formal workspace dispositions are not four completed
HTTP proofs. No arm demonstrates a wrong safe dismissal or an unconditional
storage bypass. Matching unresolved labels do not show equivalent reasoning.

Sol's saved `files-delete-check-effect-order` proposition explicitly excludes
policy-case correctness and distinguishes original storage keys from post-hook
database keys. Both final answers omit the latter. The useful fact exists in
state: the failure is retention into the claim-level review package, not failure
to store it. Terra's `file-delete-dispatch` proposition and final blockers retain
that distinction. Existing proposition/applicability support remains useful;
neither arm establishes reuse in a separate consumer investigation.

## Source audit and limits

`lookup-source-verification.json` checks every captured source window against
physical source and records hashes/navigation trails. Counts exclude symbol/text
previews and prompt/history replay; they are not token measurements.

| Arm | Source windows | Returned line instances | Unique lines | Repeated instances | Lines already in initial packet |
| --- | ---: | ---: | ---: | ---: | ---: |
| Sol workspace | 10 | 781 | 777 | 4 | 0 |
| Sol native | 9 | 403 | 403 | 0 | 0 |
| Terra workspace | 9 | 520 | 511 | 9 | 0 |

The dominant observed problem is serial deepening, not repeatedly requesting the
eight supplied windows. Cheap input alone does not remove that sequence. Full
conversation replay remains outside these line-overlap counts.

Post-run implementation-agent inspection confirms a concrete local proof route:
even an empty-child AST registers its root collection; missing collection/action
permissions throw; permission cases combine with the exact-key filter using AND;
the guard requires every distinct key before mutation. This additional inspection
does not repair model answers or prove all dynamic-variable/SQL predicate behavior.
It is not independent human gold. A source-bound conditional contract is plausible,
but its completeness and useful consumer savings still require validation.

The independent storage qualification remains: parent authorization/database
deletion use post-hook keys, while file storage deletion uses metadata fetched
for original keys. A key-replacing hook can matter; its installation, reachability
and trust conditions are not established. A conditional mechanism or precise
deployment unknown can be valid. Authentication or an awaited guard alone cannot
certify the original storage targets.

Compared with AD, the workspace arms still use six calls. Sol active time changes
from 124.830 to 122.284 seconds; Terra from 97.649 to 106.098. Source and runtime
interventions differ, and neither pair completes the package. These figures are
not a speed win, regression estimate or model ranking.

## Validation

- Review-worker suite: 254 outcomes, zero failures/errors, one skip, 1,077.462
  seconds with a 90-second per-test timeout. Two later narrow boundary cases are
  covered by supplementary pilot/helper tests; do not call this one 256-test run.
- Latest pilot suite: ten pass in 5.388 seconds. The separate unmapped native
  helper-window regression passes. Superseded failed/interrupted logs remain.
- GitHub Action suite: 61 pass in 469.941 seconds.
- Installed-package smoke passes native admission and preserves pending work,
  using the installed worker with inference disabled.

## Corrected next slice

1. **Preserve learned qualifications into the review package.** Audit the path
   from exact proposition revision/applicability through draft and export. Retain
   its statement, conditions, exclusions and provenance as attributed per-claim
   material alongside the decision. Test the real Sol omission offline, revision
   invalidation, non-applicable callers and native schema compatibility. Existing
   packets already carry propositions: merely resending them or adding another
   warning is not a demonstrated fix. Do not convert arbitrary exclusion prose
   into a controller-certified blocker or silently rewrite the verdict.
2. **Test sharing the actual permission-evaluation work.** Use existing scoped
   questions/propositions for one source-bound producer contract, distinguishing
   non-admin/accountability, collection/action, exact database keys and predicate
   assumptions from original storage targets. Charge producer investigation once;
   consumers must bind actual imports/receiver/actor/key transformations. Start
   offline with compatible and incompatible consumers and explicit deployment
   unknowns. Earlier helper notebooks did not save complete review turns; this
   experiment must avoid substantive deciding work, not just definition lookups.

Finish those as one coherent implementation/offline package before another live
freeze. A later small producer/consumer comparison must include all acquisition,
preparation, state checks, retries and producer costs, native maximum 20 and a
separate Terra medium arm. Do not rerun this unchanged pair or increase budgets.
Stop expansion on lost qualifications, unsafe applicability or unknown usage;
retain useful partial source results. If consumers still reconstruct the same
permission engine or net work/time does not improve, narrow the contract experiment
instead of adding procedural prompts. Twelve other R-main claims/eight reserves
and full-app review remain outside AF.
