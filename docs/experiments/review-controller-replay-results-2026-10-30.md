# Normal controller completion gate — 2026-10-30

**Passed offline:** all seven saved follow-up claims complete through the normal
workspace controller, bundled provider adapter and native export. All five
workspaces accept their auxiliary updates normally; none uses candidate fallback.
Every paid verdict, confidence, summary, reason, diagnosis and source lead is
unchanged. There are **zero new live model calls / zero new provider spend**.

Implementation: `cc4fe2b` (`Harden review completion and preserve source-bound
follow-up evidence`). This implements milestone 5 of the
[latest plan](../review-flow-hardening-plan-2026-10-30.md), following the
[$2.022589 broader workload](review-broad-scope-results-2026-10-30.md).

## What was exercised

Fresh native ownership/plan/work bindings, source-bound workspaces, fake-only
provider configuration/authentication, stable schema and line-addressed source.
The real bundled adapter validates each returned reply and records a synthetic
fixture receipt. The normal controller applies its updates and drafts, and
`export_completed` runs ordinary native source validation and report generation.
No independent candidate exporter, rejected-action bypass or native admission
is involved.

Each fixture reuses the exact source windows already present in its last paid
context, checked against current file hashes. Auxiliary source handles are
rebound by exact path/range/text equality into the fresh supplied context. The
decision objects themselves remain identical JSON values. Only auxiliary
handle aliases change where necessary.

The controller seeds bounded questions about the actual remaining relationship:

| Workspace | Claims | Question belongs to | Normal outcome |
| --- | ---: | --- | --- |
| Remote export | 2 | Outbound destination/credential/redirect authority | Archive-path negative; outbound uncertainty |
| Liquid summary | 1 | Actual imported HTML text construction | Negative; question answered |
| Sanitizer callers | 2 | Actual Markdown opt-out caller/writer trust | Normal-wrapper negative; Markdown uncertainty |
| Preview | 1 | Effective grant through editor/cache effect | Uncertainty; question blocked |
| Menu parent | 1 | Actual parent identity and persisted mutation | Conditional issue; question answered |

This corrects question ownership as well as length. Sharing source does not make
every open relationship a prerequisite for every claim. The archive filename
and normal sanitizer construction can close locally while their companion
caller-policy questions remain open. An open question that actually belongs to
a claim must still prevent its closure.

The new seven-claim export contains three negatives, one conditional issue and
three uncertainties. Replacing their earlier exports/candidates leaves the
assessed 120-claim package unchanged: **74 negatives / four conditional issue
sites / 42 uncertainties**. The remaining 113 decisions are retained native
results from the earlier workload, including its explicitly recorded offline
source-lead repair.

## Integrity and negative controls

- All 33 decisive source excerpts in the seven-claim normal export match the
  frozen source; all 12,872 source-file hashes remain unchanged.
- All 264 bound historical artifacts retain their hashes, including original
  paid replies, task/context packets, receipts, failure records and workspace
  databases. The previous run is not rewritten as successful.
- Five oversized-question controls fail before state change. Four additional
  controls prove that adding an unanswered claim-owned question still prevents
  a settled decision. Five unseen-proof controls remain rejected. All 14
  controls leave workspace state, drafts and budgets unchanged.
- Every fresh workspace records one synthetic fixture call and zero research
  queries. Synthetic receipts use the explicit `saved-paid-reply-fixture` model
  identity and are kept outside the measured live usage ledger.

The copied package matches the committed implementation. Against the frozen
paid package, the changed files are the question/answer creation guard and the
packaged `docs/codex-reviewer.md` documentation; model prompt/reference files and
wire schema are unchanged. The replay's runner/script hashes, inputs, runtime,
source and historical bindings are retained.

Preparation caught two harness issues before any fixture dispatch: an expected
packaged-document difference and incorrect normalization of a source window
ending on a blank line. The latter was corrected by capturing the full verified
range directly. Already staged groups were resumed with their existing bindings
and zero used calls; no budget was reset. These were fixture-preparation errors,
not new provider or product-runtime failures. Their logs remain available.

The broader commit checks also complete:

- Review worker: 353 tests, one optional skip.
- Provider adapter: 69 tests, one optional skip.
- Action: 60 passed in the full run; two environment errors were missing the
  declared PyYAML dependency. After installing the pinned CI requirements, both
  affected tests pass on targeted rerun. No product-code change was needed.
- Native Value selection: four pass, two opt-in tests remain ignored. The prior
  16 CLI investigation and two engine fragmentation guards remain source-matched
  validation for the committed formatter change.
- Diff checks, new document links and script compilation pass.

Exact commands and superseded logs are retained under the broader workload's
`commit-*.log` artifacts. The missing-dependency errors are not erased.

## What this result does and does not establish

The bounded-question and scope correction works through ordinary completion,
including mixed closed/unresolved claims and accepted answer/applicability
updates. Manual candidate recovery is not required for these fresh fixtures.
The original paid run's manual recovery remains part of its historical result.

Source and deciding relationships were acquired during the earlier paid study.
The five deterministic fixture turns therefore **do not demonstrate** a live
five-versus-24-call saving, new model quality, cache improvement or unattended
live acceptance. The 48.163-second replay wall is an offline compatibility
measurement, not a model-performance comparison. Preparation, coordination and
source audit remain additional unmetered work.

Keep the operating profile: native for complete local constructions, including
SQL; selectively share workspace investigations for concrete implementation or
authority-to-effect relationships. Keep verdicts and unresolved questions scoped
to the actual claims. Preserve learned source facts without inheriting caller
applicability or a global safe verdict.

**Stop this experiment here.** Guidance and routing direction are frozen. The
broader workload and this offline completion gate provide a concrete basis for
using both modes; another full-app/model tournament is unnecessary. HTML is the
largest remaining quality area, but its unresolved cases need specific deciding
questions rather than a blanket second reviewer. Any later paid test must name
an actual rollout or cross-application quality question.

Artifacts: `C:/dmitry/scan-runs/orchard-controller-replay-20261030-ci/run`.
Start with `verification.json`, `completion.json`,
`combined-120-source-validated-results.json` and each group's normal native
export. The parent directory retains preparation/resumption, replay and
verification scripts and logs.
