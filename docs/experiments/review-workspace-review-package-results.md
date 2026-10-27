# Review-package fidelity AH

The workspace now exports a reviewer-visible JSON package and Markdown view from
its existing state. Exact linked qualifications survive alongside claim results;
no new model action, inferred condition or rewritten verdict is introduced.
This addresses the export boundary identified in AG. It does not establish
investigation savings, complete permission proof or model-quality recovery.

Raw artifacts: `C:/dmitry/scan-runs/workspace-review-package-20261027-ah`.
No paid calls, new live comparison, admission to historical review state or
main/reserve/full-app run occurs. Native tests use disposable fixture stores.
Archived outputs remain unchanged; all historical spending remains.

## Why this correction

In AF, Sol created a proposition distinguishing original storage keys from
post-hook database keys in its final response, then omitted that qualification
from its native claim answers. It was not forgetting an earlier saved fact across
contexts. The exporter previously returned only claim results, and native blockers
were derived only from saved questions. The qualified interpretation remained
inside working state.

The correction makes that existing interpretation available to a capable reviewer
with its conditions, exclusions and proof. It does not automatically classify an
exclusion as a blocker or claim that contradictory/missing reasoning has been
resolved. A condition still requires an actual applicability judgment.

## Delivered behavior

`Workspace.review_package()` reads one revision and projects complete original
bundles. The package contains:

- Exact original claim results and properties, with canonical per-bundle draft IDs.
- Only linked proposition revisions, retaining statement, scope, conditions,
  exclusions, reviewer origin and evidence.
- Separate `caller_applicability_recorded` and `context_only` note links. Both
  remain reviewer interpretations. Context exposure is not applicability.
- Current deciding questions, latest recorded answer/proof, and a separate marker
  for resolution limited to one claim rather than the shared question.
- One shared catalog of captured source, original attribution and file hashes.
- Explicit omitted workspace claim IDs when exporting a selected complete bundle.

Unrelated facts are excluded. Missing drafts, reconsideration, stale/disputed
dependencies, foreign applicability and changed cited source prevent a current
export. Export preserves draft history, state revision, reservations and usage.
There is no partial native-bundle export or hidden source expansion.

The existing CLI offers `review-package`, with JSON output or `--format markdown`.
See [usage](../review-workspace.md#reviewer-visible-package). Markdown retains all
native result fields, shows linked notes/questions and links their evidence to
the common source catalog. Source and reviewer text are fenced literally.

Native-bound finalization writes `review-package.json` and `review-package.md`
beside `draft.json`/`response.json`; `validated.json` binds their hashes. Only the
unchanged brief-result payload reaches native finalization. A revision change
during finalization prevents package publication. Batch comparison also writes
one aggregate package beside `treatment/findings.json`, checks its draft IDs
against the finalized bundles and returns both package paths.

This is experimental workspace functionality in repository/controller packages;
it does not add a released native command or change the release allowlist. No
new module is needed. Existing workspace implementation hashes bind the change.
Ordinary native maximum 20, policy-lead defaults, prompts and budgets are unchanged.

## Saved-state check across nine exports

Fresh output directories use **copies** of archived DBs with their original seed
bindings. The new exporter checks captured source and projects existing records;
it does not resume/rebind old runtime sessions or perform new native validation.
Each output has an explicit derivation/provenance receipt. All original DB,
closure, result and source hashes are checked before and after; 66 inputs verify.

| Saved workspace | Claims | Distinct linked notes | Recorded applicability links | Context-only links | Source windows | Export ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AF Sol deletion | 2 | 1 | 2 | 0 | 10 | 15 |
| AF Terra deletion | 2 | 1 | 2 | 0 | 11 | 13 |
| AC Sol checkout | 2 | 2 | 2 | 1 | 8 | 12 |
| AC Terra checkout | 2 | 1 | 1 | 1 | 6 | 8 |
| Z Sol HTML | 1 | 1 | 1 | 0 | 4 | 5 |
| Z Terra HTML | 1 | 0 | 0 | 0 | 4 | 4 |
| AA Sol conditional controls | 3 | 1 | 3 | 0 | 6 | 8 |
| AA Terra conditional controls | 3 | 1 | 3 | 0 | 6 | 9 |
| L2 seven grouped operations | 12 | 7 | 11 | 1 | 33 | 47 |

All **28 result objects are exactly unchanged**. AF Sol's original-key storage
qualification is now visible in the package while both decisions remain
`needs_review`. Terra keeps both evaluator and hook questions. Where Z Terra
saved no linked proposition, export invents none. Context-only AC/L2 dependencies
are explicitly distinguished from recorded applicability.

The AA external-control fixture defect and AC Terra's missing source qualification
remain historical quality limitations. Producing a faithful view does not repair
those outcomes or certify the underlying reviewer interpretations. No new
human-usability, accuracy, token or speed result follows from these exports.

Observed export/Markdown rendering takes 4–47 ms per archived workspace (121 ms
sum). This excludes prior research and native execution and is an engineering
measurement only. Captured source is deduplicated by evidence identity within
each package; overlapping ranges remain separate original evidence records.

## Validation and boundaries

Seven new focused tests cover same-response qualification retention, unchanged
native results/blockers, context-only versus explicit applicability, unrelated
note exclusion, revision/dispute/source invalidation, per-claim shared-question
resolution, complete-bundle scope/omissions, CLI parity and literal Markdown.

Native/adapter integration also exercises a same-response proposition plus caller
applicability and uncertainty: the package retains the exclusion, the native
blocker stays exactly the recorded question obstacle, and the validation receipt
binds both new files. The batch report test checks the aggregate package alongside
its native finding records. New artifacts do not change usage or state.

Broader core/bridge/action/batch verification and the final receipts are retained
in the raw directory: **79 distinct checks pass across segmented verification**
(35 core, 11 bridge, 21 action, five batch and seven package checks), with a
90-second per-test bound. An early concurrent run has 77 passes and two
implementation-binding rejections because the exporter was edited during
execution. Those failures remain preserved. The two affected cases pass with
the code frozen; a third targeted check also confirms the final aggregate-draft
identity comparison. This is not one uninterrupted 79-test all-pass run.

## Next direction

Keep this as a package-fidelity correction. It removes the need to reconstruct
linked qualifications from raw workspace state, but it does not make a review
complete or avoid a model turn. Do not add a summarizer, semantic blocker inference,
another fact store, generic helper expansion or a deeper contract producer solely
to extend this export feature.

The next efficiency question remains selective shared investigation and practical
batch fallback against native maximum 20 on a small diverse package. Preserve
supported SQL/deluxe behavior and evaluate findings, scoped negatives and genuine
unknowns together with their visible conditions. Actual compatible consumers and
counted producer work are required before deeper permission-contract investment.
Prepare a new design/source/readiness freeze before dispatch; do not resume AF or
spend its unused slot. The main/reserve/full-app scope remains separate.
