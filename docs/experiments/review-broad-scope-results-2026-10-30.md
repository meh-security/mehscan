# Broader OrchardCore review results — 2026-10-30

The larger workload supports keeping **cached native review plus selective
source/flow workspace review**. The complete measured provider package costs
**$2.022589 for 120 held-out claims and 101 calls**. Affordability is established
for this workload; quality and deterministic completion are the useful next
constraints. Do not choose a mode over a small absolute price difference.

This is a stratified sample of 537 obligations, not a full-app run or an
independent precision/recall benchmark. All 30 calibration claims are excluded.
The [frozen plan](review-broad-scope-plan-2026-10-30.md) selected 105 files,
26 rules and 13 capabilities: 112 reviewed-Value claims and eight explicitly
identified Comprehensive controls. Selection did not use prior verdicts.

## Whole-package measurements

Terra 6.1 medium, unchanged guidance and stable model schema. Native used the
default maximum bundle size of 20, 18 actual bundles and at most six concurrent
provider calls. Five targeted workspaces covered seven claims with at most
three concurrent calls. Every attempt has observed usage; cache writes are zero.

| Measurement | Native | Selective workspace | Combined |
| --- | ---: | ---: | ---: |
| Model calls | 77 | 24 | 101 |
| Input tokens | 3,033,042 | 605,257 | 3,638,299 |
| Cached input tokens | 2,059,904 | 32,512 | 2,092,416 |
| Cache fraction | 67.92% | 5.37% | 57.51% |
| Output tokens | 61,744 | 12,673 | 74,417 |
| Standard API equivalent | $1.384853 | $0.637736 | **$2.022589** |
| Recorded stage wall | 355.937 s | 283.274 s | 639.211 s summed |

Prices use the stored October 30 published rate basis, not an invoice. The
summed stages are **not end-to-end turnaround**: preparation, controller/code
repair, coordination and manual source audit are additional unmetered work.
Both runners retained their execution request through final verification;
post-group verification took about 1.6 seconds each, without the earlier
post-export standby gap. Offline recoveries took another 3.590 and 8.864 seconds
of execution, excluding their implementation and audit time.

The earlier 30-claim native-plus-scope package cost $0.907757 and is a separate
cohort. Its price and timing are not a matched comparison with this wider run.
Do not linearly multiply this sample's average to estimate all 537 obligations.

Native family observations, before selective follow-ups:

| Family | Claims / calls | Price | Negative / issue / uncertain |
| --- | ---: | ---: | ---: |
| Authorization | 36 / 19 | $0.389458 | 31 / 0 / 5 |
| HTML output | 33 / 6 | $0.203364 | 7 / 0 / 26 |
| Outbound | 14 / 3 | $0.120025 | 5 / 0 / 9 |
| Filesystem read/write | 18 / 9 | $0.181290 | 14 / 2 / 2 |
| SQL | 4 / 2 | $0.039430 | 4 / 0 / 0 |
| Other seven capabilities | 15 / 38 | $0.451286 | 10 / 1 / 4 |

HTML uncertainty is the largest remaining quality question. The seven selected
claims do not establish that every remaining uncertainty is irreducible or
requires deployment facts; other readable local helpers may still settle some.
The one-claim families also cannot support a broad cost estimate for their rule.

## Quality and actual outcome provenance

| Stage / authority | Negative | Conditional issue sites | Uncertain |
| --- | ---: | ---: | ---: |
| All 120 native decisions, after offline source-lead repair | 71 | 3 | 46 |
| Replace only normally completed workspace results | 73 | 4 | 43 |
| Include four independently validated, manually assessed paid candidates | **74** | **4** | **42** |

The final assessed package contains 113 retained native decisions, three
normally completed workspace decisions and four manual paid candidates.
**The original runs remain incomplete; clean unattended acceptance is unpassed.**
No finding was admitted to native state. All 284 decisive source excerpts in
the assessed package match current frozen source. That proves source validity,
not semantic accuracy. All 71 native negative summaries were screened for
scope shortcuts, with cited-source/effect checks on flagged or high-risk cases
and changed negatives. There is no complete independent semantic gold audit of
all 120, so no numerical precision/recall claim is justified.

The four supported issue sites represent three conditional mechanisms:

- **File-store move, source and destination:** the full-path string-prefix check
  lacks a directory boundary. A suitable root, same-prefix sibling, caller path
  control, existence conditions and filesystem permissions permit crossing the
  store boundary. Two scanner sites share this mechanism. Remote exposure is
  not established.
- **Build restart shell construction:** the interactive Node-version-manager
  path joins argv into shell command text. Lower-trust argument control and
  activation remain conditions. CI version mismatch exits before this branch;
  this is not a demonstrated remote or CI exploit.
- **Menu parent authorization, newly resolved by workspace:** `CreatePost`
  checks `ManageMenu`, loads the submitted parent ID without checking Menu type
  or target edit authority, adds menu-item data and can save a latest unpublished
  parent. Default permission composition does not turn `ManageMenu` into edit
  authority for unrelated content types. Conditions include access to the admin
  action, suitable grants, valid child/model input and a writable draft. No
  deployed role or persisted exploit was demonstrated.

The menu finding follows the grant-to-write relationship rather than treating a
missing per-item check as sufficient. The taxonomy control remains negative:
its tag action requires an existing `TaxonomyPart` before mutation and has the
global taxonomy-management guard. These superficially similar actions should
not inherit each other's verdict.

## What the selected follow-ups contributed

| Investigation | Claims / calls | Price | Result and remaining question |
| --- | ---: | ---: | --- |
| Remote export | 2 / 6 | $0.171851 | Archive-path negative completes normally. Outbound remains a manual uncertainty candidate: intended destination/redirect recipient authority and effective client policy. |
| Liquid summary | 1 / 1 | $0.016888 | Negative, normally completed: actual imported decode/strip/truncate construction settles ordinary HTML text emission. No producer inventory required. |
| Sanitizer callers | 2 / 6 | $0.157034 | Manual candidates: normal sanitizer wrapper negative under the shown binding; Markdown opt-out retains actual caller/writer-policy uncertainty. |
| Preview grant/effect | 1 / 5 | $0.130221 | Manual uncertainty candidate: own/type-only bypass is not supported by default handlers; cross-principal preview-token write policy remains unresolved. |
| Menu parent effect | 1 / 6 | $0.161742 | Normally completed conditional issue, with grant, target, mutation and persistence source. |

The last three uncertainty candidates are useful results, not failures to find
a vulnerability. A configured outbound client, intentional raw-HTML option or
global preview permission does not alone establish a prohibited flow. The
normal sanitizer wrapper's local guarantee does not cover custom replacement
services, unsafe options or attribute/script contexts.

## Runtime failures and surgical corrections

Native initially finalized 106 claims. One 14-claim outbound bundle failed when
a legitimate source lead selected one 27,772-character minified line. The main
citation renderer already supported bounded fragments; the auxiliary lead
renderer incorrectly required one fragment.

The formatter now preserves every bounded chunk and the full lead location.
The engine permits more than four references only for one exact contiguous
source range, bounded to 64 KiB / 400 lines and 32 fragments. Existing unknown,
duplicate, unseen and mismatched-source rejection remains. The model wire
schema/guidance is unchanged. The CLI's exported native response schema reflects
this constrained representation. Offline replay recovered all 14 decisions
using the **unchanged paid draft and full source lead**, with no inference.
The original package, failure and paid reply remain frozen.

I also seeded four workspace questions above the native check's 300-character
limit. The workspace accepted them; my preflight missed that mismatch. Menu
completed because its question was answered, while three groups failed when
rendering uncertainty. These are controller setup/export failures, not model
quality failures. All their attempts remain charged above.

Question creation now enforces the same 300-character, single-line bound as
the model protocol/native check. Answer creation enforces the corresponding
700-character reason bound. Rejected actions leave state and budgets unchanged.
An offline replay of the five actual seeds rejects all four oversized questions
before inference and accepts the valid Liquid question. No prompt change or
budget reset was made.

For this failed run only, an independent offline candidate export splits the
original questions losslessly across bounded native check fields: joining the
pieces reproduces every original character. Paid verdicts, summaries, reasons,
diagnoses and source are unchanged. Every citation is checked against the actual
supplied context before ordinary native finalization. Four candidates validate;
their semantic assessments are separately recorded. No rejected auxiliary update
is applied, original workspace state/completion is unchanged, and this does not
make the original response accepted or the workflow unattended.

Validation passes all 16 CLI investigation tests, two engine fragmentation
guards and 210 workspace tests, plus the five actual-question preflight replays.
Formatting and diff checks pass. A shared-record test fixture was corrected to
keep its long blocker within the native 700-character bound; its preservation
assertions remain. See stored logs for exact commands and superseded attempts.

## Practical operating profile and stopping point

Keep native as the first pass for complete local constructions. The four SQL
controls took two calls / $0.039430; no workspace was necessary. The wider native
outbound bundle also retained its nine meaningful uncertainties instead of
closing client configuration from fixed route/scalar facts. Native continuation
input still accounts for 86.08% of its input; cheap price does not prove repeated
context reconstruction is solved.

Provide the actual deciding helper/import/registration source early, with file
hashes and scoped applicability. The one-call Liquid closure suggests a source
preparation improvement, not a reason to route every such claim through workspace.
Use workspace where an actual authority-to-effect relationship or compatible
shared implementation warrants it; menu demonstrates a material quality gain.
Keep verdicts separate and preserve the learned question/lookup records.

Freeze guidance and this routing direction. **Stop widening or buying repeated
answers for this experiment.** Before unattended rollout, verify normal handling
of valid bounded questions and saved replies through the existing controller
path, with all known findings, uncertainties, counters and source guards retained.
Use offline replay first. A later paid run must answer a named remaining rollout
or cross-application quality question; there is no sub-dollar savings threshold
and no need for another model/mode tournament now.

Artifacts: `C:/dmitry/scan-runs/orchard-broad-scope-20261030-ch`. Start with
`audited-package.json`, `family-analysis.json`, `formatter-recovery/verification.json`,
`verification/verification.json` and
`verification/independent-question-export/verification.json`. Full raw attempts,
selection, runtime/source freezes, independent candidate bindings, original
failures and source-bound question histories remain available. Changes are
uncommitted.
