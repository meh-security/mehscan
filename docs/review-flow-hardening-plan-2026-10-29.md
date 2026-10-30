# Review flow hardening and Value selection — 2026-10-29

**Latest follow-through:** see the [2026-10-30 plan](review-flow-hardening-plan-2026-10-30.md) for the completed Value audit and concrete 30-claim acceptance gate.

This is the next implementation plan after the [OrchardCore review](experiments/review-orchard-recheck-results-2026-10-29.md). Keep the measured results and both promising modes. Fix deterministic execution defects before buying another full-app run. Quality and complete-package price remain primary; fewer selected claims are not themselves a quality improvement.

## Why the run was large and fragile

The 537 count represents review obligations, not 537 independent suspected vulnerabilities. The main inventory had 415 claims; the experiment deliberately drained another 122 authorization-marker claims from continuation pages for full comparison coverage. Twelve eventual filesystem site findings shared one mechanism.

The saved plans used `policy: value` but selected every ID, with no deferrals. The plan template historically selected all IDs for both policies; the Action passed that template through unchanged. The experiment also used explicit larger research allowances. A Value policy label therefore did not establish a priority-filtered workload.

Existing native hints would select **510/537**, deferring 27. Against the audited package, those deferrals are 16 scoped negatives, ten uncertainties and **one supported conditional workflow redirect**. That redirect remains Comprehensive work, with its exact ID and evidence. It is not safe or discarded. Value is a useful first queue; its existing hints cannot explain away most of this CMS's review volume.

Twenty-six of those deferred claims occupied five whole bundles in the historical run, with 22 calls/$0.348105 attributable spend. This describes that saved run, not projected rerun savings; mixed bundles, different evidence and changed investigation paths are not repriced.

Five long-line citation failures blocked 66 claims at bundle finalization. A locator/source proof mix-up blocked another six. Workspace then rejected an invented handle, and its final attempted turn had no returned usage before the investigation deadline. These are distinct failure classes, not one flaky model problem. A debug scanner also dominated some local lookup time.

## Flow audit and corrections

| Stage | Observed problem | Correction and boundary |
| --- | --- | --- |
| Scope/inventory | Full marker-page coverage and generated/dependency copies increase work. | Record why each scope is included. Use source/build provenance for duplicate-artifact decisions; do not exclude all wwwroot/assets/build-like paths by name. Keep explicit dependency/deployed leads. |
| Priority selection | Value label selected everything in the template/handoff. | **Implemented:** explicit `plan-template --selection policy`; Value honors existing hints as reasoned unreviewed deferrals. Action opts in. Manual default `all` and Comprehensive coverage remain available. No new rule suppression. |
| Bundling/routing | Family bundles spend a common lookup allowance across unrelated implementations. | Group by deciding implementation and compatible callers; preserve separate effects. Keep local SQL/API/authorization closure native. Use shared workspace investigations for actual shared relationships. Avoid simply shrinking every bundle or enlarging every budget. |
| Evidence preparation | Normalizer, Razor import, serializer or caller binding was missing or rediscovered. | Prepare the specific deciding closure. Reuse source/version-bound facts with explicit applicability; no inherited safe verdict. Record missing versus ambiguous versus complete returned source. |
| Model/adapter | Valid paid replies can fail local handle validation; last-message file is overwritten on continuation. | **Implemented:** retain the exact reply privately per round before local validation. Keep metrics and continuation records before rejection. Do not strip/remap bad proof handles. |
| Finalization | A physical line over 4,000 characters cannot fit one full-format artifact. | **Implemented:** split the cited range into exact Unicode-character/UTF-8-byte/column spans. Existing 4,000-character/40-line artifact and 64-KiB/400-line range limits remain. Missing/outside paths and invalid ranges still fail. Source materialization does not certify what the model inspected or semantic correctness. |
| Failure recovery | Known validation failures, unknown provider usage and missing claims need different handling. | Remaining work: typed bounded correction and partial-result export. Use only remaining allowance; preserve failed attempts. Unknown usage stops the affected arm pending reconciliation; independent work may continue. Never relaunch a full app for one failed claim. |
| Finding promotion | Five native positives described construction/different checks without an established security boundary. | Targeted source/flow review of authority, intended contract and actual effect. Keep hardening observations and conditional mechanisms. No automatic second model for every candidate. |
| Measurement/build | Debug wall time and incomplete receipts distort comparisons. | Use a fresh optimized frozen build for the next timing comparison. Require preflight end-to-end fixtures before inference. Keep known-price lower bounds and unknown attempts explicit. |

## Milestone 1 — deterministic fixes and offline replay

Implemented in normal product paths:

- Native brief finalization handles long physical lines using bounded full-format spans, preserving bytes, columns, verdicts and reason text.
- `state plan-template --selection policy` partitions every ID into selected or explicitly deferred work using the existing native hints. Without the option, manual all-ID templates stay compatible. The advisory Action selects its configured policy explicitly. Changed-path review obligations remain intact.
- The adapter saves `round-N/response.json` privately, including replies later rejected by exact local validation. It does not export private authentication or accept invalid replies.

Offline replay saved in `C:/dmitry/scan-runs/orchard-flow-hardening-20261029-ca`: **all five original failed drafts / 66 claims finalize normally**, with decisions and summaries unchanged. Actual CLI selection on all four saved inventories produces **510 selected / 27 deferred**. No model calls, target execution, historical-state edits or live cost-saving claim.

Regression gates cover Unicode/CRLF and mid-line locations, unchanged byte slices, oversized ranges, outside/missing paths, Value/Comprehensive partitioning, invalid selector rejection, real Action handoff selection and private rejected-reply preservation. Original source-validation checks remain active.

Passed checks: CLI unit tests, review-state and Value-selection integration tests, the complete Action handoff suite, the complete provider-adapter suite, formatting and diff whitespace checks. Optional external-tool/credential tests remain skipped according to their existing conditions. These are local uncommitted changes. Changed engine/skill bytes require fresh runtime/plan/work bindings; historical Orchard/PyGoat packages must not be resumed under them.

A fresh optimized release package also passed the installed worker/admission smoke check, preserving pending uncertainty, with no inference or target-application execution. Its scanner SHA256 is `5e9fd2a140ac14571d0af4df7366f3277209b806516c0d247c3272a07b5f1837`. Saved `implementation-checks.json` and `installed-smoke.json` accompany the offline replay. This is executable/package acceptance, not a new full-app latency or price result.

## Milestone 2 — bounded recovery and independent completion

Implemented locally; regression results and acceptance limits are recorded below.

1. Give a returned-but-invalid reply a typed local-validation outcome with exact error paths and eligible handles. When allowance remains, permit a correction in the same bound conversation. Charge it and consume existing limits. Do not automatically retry provider/account/security failures or invent a successful draft from invalid proof metadata.
2. Preserve completed independent judgments when another claim blocks a native bundle. Export their source-validated results and keep unresolved IDs explicit, without fabricating workspace completion or changing original failed states.
3. Carry one absolute investigation deadline through preparation, continuation and recovery. Do not reset time/call/query allowance during a retry. Preserve partial provider events, exact returned replies and receipt status.
4. Test failures after payment, before metrics, after draft save, during finalization and after partial export. Verify no duplicate admission, zero-cost assumption, missing-ID clearance or repeated whole-slice launch.

Stop if recovery would need weaker provenance, discarded costs, arbitrary handle substitution or a fabricated verdict. Keep the failure/actionable uncertainty visible instead.

### Implementation and acceptance boundary

- Stable local validation emits an exact-task typed diagnostic. Native and workspace controllers permit at most one same-thread auxiliary proof-reference correction, consuming original limits. The adapter protects the rest of the response and permits replacements only in originally invalid slots; it rejects stripped references, changed reasoning and unbound continuation.
- Unknown-usage native failures no longer trigger a fresh automatic conversation. Independent native jobs finish, with `partial-results.json` indexing finalized artifacts and missing IDs. Explicit recovery requires exact observed counters; late receipts retain their original location through multiple attempts and enter aggregates once.
- Workspace `export-completed` creates a new source-validated subset run/report from unchanged saved judgments. Original membership, missing IDs and incomplete status remain explicit. Original full-bundle finalization stays strict. Export leaves native admission, failed dispatches, unknown costs and workspace state unchanged.
- Persisted absolute deadlines span native recovery and workspace context replacement/splits. Comparison wrappers forward the work-item deadline and count correction turns against the existing allowance.

This closes deterministic recovery paths, not the semantic accuracy question. It does not establish new live price/time savings, automatically correct arbitrary invalid replies, resume historical Orchard/PyGoat bindings, or approve an unattended full-app rollout. The next gate remains the offline Value/coverage audit, followed by one frozen representative acceptance slice if that audit warrants it.

Validation: **343 passed / two optional skips** across the native worker (71 tests), adapter (69), workspace (193) and hybrid (12) suites. Focused checks additionally cover a crash after subset source export and deadline expiry after replacement/splitting. The fresh installed-package smoke passes native admission while preserving pending uncertainty; Python syntax and diff whitespace checks pass. All inference is deterministic fixture output, with no paid model calls or target-application execution. Runtime/test hashes, suite logs and package acceptance are recorded in `C:/dmitry/scan-runs/orchard-flow-hardening-20261029-ca/m2-implementation-checks.json` and `m2-installed-smoke.json`. Changes remain uncommitted.

## Milestone 3 — evidence-driven Value calibration

Do an offline selection audit before changing admission rules. Preserve a complete active/deferred/excluded ledger, separate from verdicts. Check currently retained mechanisms, the custom owner/publish flow, clean controls and meaningful unresolved cases across both queues.

Candidate improvements are source-confirmed generated duplicates, integration-only trusted-markup contracts, ordinary browser requests and repeated shared implementation research. Each needs source/provenance evidence and controls that retain authored mixed directories, post-control transformations, independent source/destination effects and different caller authority. Do not blanket-defer all HTML, filesystem, authorization or build-tool rules, and do not invent a low-value score from CWE/severity/file names alone.

Promote a deferred case when concrete source establishes a consequential mechanism or justified fix. Keep custom/deployed caller questions available in Comprehensive. A cheaper Value run must report the supported conditional redirect it defers, not silently compare itself against the old complete package.

## Milestone 4 — bounded acceptance, then decide expansion

After the relevant recovery/calibration changes, use one representative slice with real previous failures, complex positives, scoped negatives and genuine uncertainty. Freeze source, optimized runtime, selection, prompt/schema, prepared evidence, provider and limits. Compare actual quality, all paid price, cache and elapsed time. Do not mix the scope-selection change with a model/mode tournament.

Acceptance requires zero deterministic finalization failures on the 66 saved cases; continued rejection of invalid/unseen proof; complete selected/deferred/failed accounting; retained supported mechanisms and useful uncertainty; and reduced manual recovery without new unsupported promotions or wrong dismissals. A deferral is not a negative and raw closure counts are not accuracy.

Stop after those questions are answered. Expand to another full-app run only for a specific remaining rollout question. Do not require perfect agreement or zero uncertainties, and keep useful native/workspace modes when results are mixed.
