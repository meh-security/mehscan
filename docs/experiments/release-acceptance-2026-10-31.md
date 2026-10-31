# Local release acceptance — 2026-10-31

The release candidate now has bounded live app-plus-skill acceptance and a
complete local deterministic acceptance pass with separately verified corrections.
No paid inference, tag, publication or hosted CI run was performed in this slice.
The version remains 0.8.0 pending a release-version decision.

## Scope and revisions

Acceptance began at `7594e9f`, using the clean isolated checkout
`C:/dmitry/mehscan-release-check`. Runtime corrections end at `f978b9d`.
Unrelated identity-skill work in the primary checkout was excluded. Rust checks
and the optimized build use the minimum supported toolchain, Rust 1.88.0.
Python checks use Python 3.13.15 on Windows.

Logs, receipts, timings and archives are retained externally in
`C:/dmitry/scan-runs/release-acceptance-20261031-dc`. The earlier bounded live
quality/cost result is in [installed-default acceptance](review-installed-defaults-2026-10-31.md).
Synthetic replies below check execution and admission, not reviewer accuracy.

## Completed checks and qualifications

| Check | Result |
| --- | --- |
| Rust formatting on 1.88.0 | Pass |
| Full Rust all-target run at `cbb42c6` | 913 passed, one YAML-flow regression failed, 60 ignored |
| Seven affected native targets after the final correction | All 10 tests pass, including YAML and evaluator/object negative controls |
| Full worker suite with optimized scanner | 378 tests: 365 pass, four failures, eight errors, one Windows skip |
| Corrected workspace fixtures | A 70-test rerun passes 69; its remaining final-checkpoint expectation is corrected and the entire 13-test feedback module passes |
| Corrected recovery-budget test | Pass; configured six-call bound replaces stale four-call assertion |
| Provider adapter suite at final runtime revision | 75 pass, one POSIX-only skip |
| GitHub Action/lifecycle suite | All 62 pass locally, including synthetic native admission |
| CLI acceptance | Pass; inventory, one uncertainty review and reporting |
| Windows installer | All 32 checks pass |
| Unix installer tests on Windows | 10 pass, two platform skips |
| Release tag handling | Five cases pass with publisher mocked; no remote writes |

The full runs are preserved as failed historical executions. They were not
silently relabeled green. Each failing target or test is covered by the corrected
reruns; no second uninterrupted full-suite pass is claimed. The Action suite
used the frozen initial development executable; affected native tracing was
verified separately after correction. Hosted supported-platform CI is still
required before release.

## Corrections made

- Candidate projection now checks all matching positive fixture paths rather
  than an obsolete literal count. Projection equality remains enforced.
- Typed scalar evaluator contexts can reach the existing explicit VM proof.
  Scalar assignment checks reject unread transforms and whole-object seeding.
  Recognized upload-buffer `.toString()` conversion is retained for constant
  YAML wrappers, including typed member-expression captures. Guarded cases
  retain uncertainty about control flow.
- Next.js alias fixtures declare their real TypeScript path mapping. Production
  resolution does not invent `@/` aliases. Capability rules regain required
  provenance links. Flow expectations distinguish supported guarded transfers
  from local helper transforms without treating a missing flow as a dismissal.
- Controller guard fixtures explicitly use legacy dynamic/raw wire mode so
  deliberate malformed replies reach the controller under test. Stable-schema
  validation retains its dedicated coverage; shipped defaults stay stable and
  addressed. A final-only rejection cannot be exported as a settled candidate.
- Feedback tests respect the final checkpoint: the sixth paid call cannot request
  more research, and rejecting it does not create another model slot. Recovery
  assertions read the bound runtime allowance instead of hardcoding four calls.

## CI cost and cleanup decision

The full optimized-scanner worker run took **1,439.061 seconds (24.0 minutes)**.
Per-test timing totals are 1,365.991 seconds for 322 product tests and 73.060 seconds
for 56 research tests. Research tests account for only about 5% of this run.
`test_worker` dominates at 1,085.170 seconds, including recovery, revalidation,
source admission and resume behavior. Deleting research tests would leave most
of the runtime and lose retained-feature coverage.

CI therefore retains every test on all three supported operating systems, builds
an optimized scanner for native-backed Python suites and records complete
membership/status/duration. Its timeout increases from 30 to 60 minutes. The
initial optimized build took about 7.5 minutes; the debug worker run was stopped
after 11.5 minutes and did not complete. There is no matched full debug/release
comparison establishing a numerical speedup. Hosted cold-build timing may
require a later job split; the local timings do not guarantee the timeout on
every runner. Do not delete safety regressions to meet a cosmetic count target.

## Remaining release work

1. Finish acceptance of the corrected optimized paired Windows archive and
   record its exact source revision and checksum.
2. Run hosted CI for the final commit across supported platforms and verify
   both macOS release targets. This session has no authenticated `gh` login,
   and the available connector cannot dispatch a new workflow.
3. Choose the next version, generate and verify exact versioned release assets,
   then publish with the concise user-facing release notes. No version choice
   or publication is inferred from the local candidate archive.

Further app/model tournaments, automatic second review and broad workspace
routing remain optional follow-up work. They do not replace these release gates.
