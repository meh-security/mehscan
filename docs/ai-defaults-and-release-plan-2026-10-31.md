# AI defaults, optional review and release cleanup — 2026-10-31

Status: default-profile implementation complete locally; paired live acceptance
has a bounded passing targeted run after one diagnostic correction. CI
timing/classification is implemented, with all tests still enabled.
This supersedes the release direction at
the top of the [previous plan](review-flow-hardening-plan-2026-10-30.md).

## Implementation progress — 2026-10-31

**Latest acceptance, DA/DB:** the installed 12-claim run finalizes 11; one final
uncertainty draft fails an auxiliary source-handle check. Detailed boundary tables
are now explicit `boundary_checks=true` opt-in, while ordinary evidence and
finalization guards remain. A fresh six-claim retest admits all six, retains both
complex authority positives and the own-profile/parameterized-SQL controls, and
preserves two concrete uncertainties. Combined 49/49 calls are receipted at
$0.6127784 Standard API equivalent; no 403s occur. See the [exact results, quality
limits and correction](experiments/review-installed-defaults-2026-10-31.md).
Freeze further experiment expansion; finish exact-candidate platform/asset checks.

- Value and Comprehensive now share five research rounds, 24 query units,
  512 KiB and 900 seconds; native runtime binding still preserves explicit and
  previously admitted limits. The AI skill and default worker example explicitly
  select Value with policy selection. Manual all-ID templates remain available.
- The adapter now defaults to stable schema and line-addressed source. Explicit
  dynamic/raw modes remain supported; conversation bindings reject incompatible
  resumes. Usage receipts include the effective schema/presentation modes.
  Setup and its example explicitly select these settings and default to Terra
  6.1 medium. The example installs validation dependencies before credential setup.
- The installed-package smoke now checks policy selection and exact native
  limits. A development archive built from the current debug executable passes
  membership, scanner/report/finalization and installed Changed-worker checks.
  This is a deterministic package check, not live reviewer quality acceptance
  or verification of an optimized release asset.
- `scripts/test-review-suites.py` inventories all 378 worker tests: 322 product
  and 56 clearly research-driver tests. It defaults to all, rejects duplicate IDs
  and discovery failures, and records test ID/tier/status/duration. CI retains the
  full three-platform suite and uploads its report. No tests have been deleted
  or excluded. Mixed and safety-relevant pilot tests stay in the product tier.
- The research tier passes all 56 tests in 70.099 seconds locally using the
  preceding optimized executable and current Python sources. This is initial
  timing evidence, not acceptance of the new native defaults. It does not justify
  a blanket exclusion. Collect the regular CI/platform timings before splitting.

Focused acceptance includes five Rust runtime tests, the full adapter suite
(73 pass, one existing platform skip), seven setup tests, profile/selection
handoff checks and a worker override guard. Source/skill checks and development
archive acceptance pass. The configured-provider-to-native Action integration
also passes with omitted adapter modes, using the new defaults and a synthetic
reviewer (52.866 seconds). The separate POSIX-only worker fixture is skipped on
Windows; its synthetic reply now also supports the stable schema. Logs and timing inventory are under
`C:/dmitry/scan-runs/value-defaults-*-20261031*`.

**Next:** complete exact-candidate hosted/platform acceptance and versioned assets.
The bounded installed live package above is complete. Selective automatic
follow-up, deep audits and experimental preloading remain at the positions below.
The earlier deterministic changes alone established no live quality result;
the DA/DB report above supplies the subsequent bounded evidence. No release version,
tag or publication is created. The current-state table below records
the pre-implementation gaps that motivated this slice.

The release unit is **the app plus AI review through the skill**. Close the
preparation experiments, finalize a reproducible Value profile, and accept that
paired product. Optional automated GitHub/company-auth execution has its own
acceptance requirements. Its failures do not establish that manual skill use is
broken, and native-only acceptance does not certify the AI phase.

## Previous gaps — before implementation

| Setting | Current behavior | Consequence |
| --- | --- | --- |
| Value research limits | `ReviewResearchLimits::for_policy`: two research rounds, eight query units, 128 KiB, 300 seconds | Three total model calls before recovery accounting; materially smaller than the recent live studies |
| Documented starting limits | Worker guide recommends three rounds, 12 queries, 128 KiB, 600 seconds | A third configuration, distinct from both native defaults and latest studies |
| Recent TS/JS and five-app studies | Six total calls, 24 query units, 512 KiB, 900 seconds per investigation | Evidence for this operating configuration cannot certify the smaller shipped defaults |
| Value selection | `--policy value --selection policy` applies native hints; omitting selection retains all IDs | A Value label alone does not guarantee Value selection |
| Provider representation | Adapter defaults to dynamic schema and raw source; stable and line-addressed are explicit config | The measured cache-conscious configuration is still not the adapter default |
| Review mode | Ordinary single-model worker is shipped; mixed dispatcher is explicitly experimental and absent from release catalog | Research demonstrations of selective workspace are not a turnkey default product feature |
| Trace | Worker records events and provides a read-only trace tool | Useful default observability already exists; it does not certify reasoning |

Relevant implementation: `crates/core/src/review_runtime.rs`,
`crates/cli/src/review_state.rs`, `scripts/review_worker.py`,
`skills/mehscan-security/scripts/codex_reviewer.py`,
`skills/mehscan-security/scripts/codex_protocol.py`, `scripts/release-files.json`.

## Recommended release profile

AI remains explicitly invoked by the user. Once invoked without advanced
options, it should run one documented **Value** profile:

- Native policy selection with exact selected/deferred IDs and reasons. Deferred
  means unreviewed. Preserve promotions supported by newly inspected evidence;
  no app-specific exceptions or broad family suppression.
- One configured capable model. Terra 6.1 medium is the best-supported operating
  candidate from these studies, subject to available account access. Retain
  explicit model overrides; do not silently substitute models on failure.
- Stable schema plus local exact-turn validation and line-addressed source for
  the bundled adapter. Validate dependencies before dispatch. Preserve explicitly
  configured legacy modes and require fresh conversations after a mode change.
- Start release acceptance with the already exercised ceiling of five research
  rounds (six total calls), 24 query units, 512 KiB and 900 seconds per native
  investigation. Finish early when settled. These are bounded operating limits,
  not a spend promise or instructions to exhaust the budget. Do not introduce a
  whole-run three-minute cutoff or claim these limits are optimal.
- Ordinary source preparation, category guidance on demand, direct deciding
  lookups and snapshot-bound fact reuse. Import/export navigation is available
  to the reviewer; broad dependency/chain preloading remains opt-in.
- Native first for SQL and other complete local constructions. Share concrete
  implementation evidence with compatible callers; keep individual judgments.
- Always retain query attribution, returned evidence, usage/cache counters,
  unresolved questions, execution failures and native finalization results.
  Missing usage remains unknown. Evidence identity is checked mechanically;
  reasoning correctness still requires evaluation.

This requires aligning native templates, adapter configuration/setup, skill
instructions and installed documentation. A recommended CLI example alone is
insufficient. Keep the independent all-ID template option for manual audits;
the ordinary AI entry point must explicitly choose policy selection.

The selection audit found a conditional finding outside initial Value selection.
Therefore this profile is a priority queue with visible coverage limits, not an
assertion that every useful finding is selected. Comprehensive widens selection;
it must not be defined merely as more calls on the same selected IDs.

## Follow-up after the base review

Make **completion accounting and structural checks default now**: reconcile all
selected IDs, validate citations/current source, preserve deferred/failed/pending
items, and check report counts against canonical results. Existing bounded
protocol repairs remain part of the ordinary flow. These checks do not validate
security reasoning.

Keep **selective model follow-up as the next promotion candidate**, rather than
claiming it already works automatically. Recent successes used manually selected
groups and source windows. Release the base profile first if generic selection
cannot be accepted without another research cycle.

The proposed follow-up contract is one cycle, with its allowance disclosed and
reserved before execution. It operates on a selected subset and preserves the
base assessment and replacement history. Eligible work has:

1. A concrete decision-changing question, such as an unread named policy helper,
   unresolved token implementation, or contradictory check-to-effect binding.
2. A reachable source/evidence lead or specific counterevidence worth testing.
3. Compatible implementation and caller scope if several claims share work.

Do not select every uncertainty, every authorization claim, every positive, or
all members of a file/CWE. Do not use confidence alone. Missing deployment-only
facts with no available way to answer them remain actionable uncertainty. A
supported local negative remains closed for that property while a distinct
identity or downstream question stays separate.

Start with the ordinary worker and existing evidence APIs. Use workspace only
where persistent shared relationships are actually needed; do not ship the
comparison/pilot harness as the product dispatcher. New follow-up source must
pass the same freshness, attribution and native admission checks. A failed
challenge never silently replaces an accepted prior assessment.

Promote follow-up to default only after the same accepted base package plus a
generic selector preserves supported mechanisms/controls and produces useful
corrections or additional evidence at a measured total package price. If it
merely repeats research, leave it opt-in. This is one rollout decision, not a
new multi-model tournament.

## Optional depth and audit modes

| Capability | Release position |
| --- | --- |
| Comprehensive selection | Supported explicit wider coverage; same evidence/verdict standards |
| Targeted challenge/revalidation | Explicit request now; candidate for selective default follow-up above |
| Source/flow and guide-compliance audit by another model | Opt-in; inspect actual producer, transformation, control and effect, plus counterevidence |
| Report-quality review | Optional editorial/actionability pass; cannot certify source reasoning or rewrite verdicts silently |
| Execution trace recording and inspection | Default cheap recording; inspection on demand, no extra model required |
| Dependency/chain preloading | Experimental opt-in; no demonstrated whole-package improvement warranting default |
| Tiered models, blind dual reviews, helper agents, automatic broad workspace routing | Experimental; exclude from default UX |

Guide compliance cannot be established from a valid citation or a trace flag.
The deep audit should identify evidence-backed mistakes and remaining gaps,
not rubber-stamp agreement. Retain its own cost, provenance and disagreements.

## What the experiments support

- [Stable native](experiments/review-stable-full-native-hybrid-results-2026-10-29.md):
  116 claims completed; cache-adjusted price fell from $3.410960 to $1.562765
  against the saved dynamic baseline. Input and elapsed increased. This supports
  cache-friendly representation, not less investigation or improved precision.
- [TS/JS Value](experiments/review-ts-js-value-results-2026-10-30.md):
  214 selected claims finalized, 40 deferred, $2.277609 original native price.
  Selective shared investigations supplied useful closures and mechanisms;
  112 composed uncertainties remain. This supports the base plus targeted
  follow-up direction, not universal automatic routing.
- [JWT combinations](experiments/review-jwt-combinations-results-2026-10-29.md):
  combined relevant source and guidance was useful; the control also corrected
  the known error. Retain category guidance and evidence reuse without claiming
  that adding instructions alone fixes reasoning.
- [Helper isolation](experiments/review-subagent-isolation-results-2026-10-29.md):
  the completed Terra pair cost more including helper production. No default
  helper agent is justified by that comparison.
- [Latest preparation comparison](experiments/review-dependency-navigation-2026-10-30.md):
  partial completion and unknown provider usage prevent a clean package ranking.
  Keep navigation fixes; leave broad preparation optional.

These are development studies with source audits and overlapping cases, not a
general precision/recall benchmark. No new live result was generated in this review.

## Test and code cleanup

Inventory on 2026-10-31: unittest discovery finds **378 worker tests across 29
modules, with no duplicate test IDs**. CI runs the full worker suite on Linux,
Windows and macOS after native tests. Existing native fixtures repeatedly create
inventories/state and default to the debug executable. No per-test duration
inventory exists in this review, so test count is not a measured savings claim.

Do not remove guards simply because an experiment first exposed the bug. Keep
freshness, path/ID scope, ambiguity/type erasure, source/proof integrity, final
checkpoint behavior, recovery budgets and unknown-usage accounting as product
regressions. Imported fixture modules are not duplicate tests in current discovery.

Use three tiers:

1. **Every PR, supported OS matrix:** native tests; ordinary worker, package,
   adapter and lifecycle regressions; platform-sensitive process/auth/path and
   installation tests. Keep one end-to-end installed app-plus-skill path.
2. **Research/optional suite, Linux on relevant changes and manual dispatch:**
   comparison/planner/pilot, experimental routing, old protocol compatibility
   and experimental tiered scenarios. Keep Windows/macOS platform smoke for
   retained executable experimental features. Shared runtime changes trigger
   this suite. Do not mark experimental correctness failures as allowed failures.
3. **Pre-release and scheduled full suite:** all retained tests on supported
   platforms, including optional features being shipped. Paid live acceptance
   is separate from deterministic CI.

First classify methods as well as modules: `test_worker.py` mixes ordinary and
tiered tests; `test_workspace_pilot.py` includes source coverage/accounting guards;
`test_context.py` verifies the release catalog. Moving entire files blindly would
hide useful product checks. Six `test_work_formation_experiment.py` cases are
clearly research-tool tests, but they are not established as the runtime bottleneck.

Measure test ID/duration/status under the normal CI build before broad exclusions.
Reduce repeated expensive fixture setup only where isolation survives. Evaluate
an optimized scanner for integration tests using the existing
`MEHSCAN_TEST_SCANNER` hook, including its build cost; do not require another
full LTO build without demonstrating net savings. Emit tier membership and fail
if any test is omitted or selected twice. Keep a manual full-suite command.

Delete code only after checking release-catalog membership, runtime imports,
documented entry points, test-fixture dependencies and replay needs. Start with
unshipped standalone comparison drivers; preserve compact reports and immutable
external experiment artifacts. Do not delete workspace primitives merely because
automatic routing is experimental. Do not remove tests while shipping the code
they alone protect. Code deletion follows classification, not a bulk purge.

## Milestones and stop rules

1. **Finalize Value settings:** one named effective configuration emitted in work
   artifacts; align selection, native limits, adapter/setup and docs. Preserve
   explicit legacy overrides. Verify config parsing, binding and installed package.
2. **Classify and time CI:** publish complete test membership and durations; move
   pure research coverage to its own required-on-relevant-changes job. Keep
   platform risks covered. Stop when the split has no coverage holes; do not
   chase tiny unit tests for cosmetic count reduction.
3. **Accept the paired release:** one bounded live package using the installed
   default app and skill, spanning SQL/local closure, shared helper authorization,
   token version/binding, HTML context and a genuinely unresolved case. Reuse
   audited controls without putting expected answers in reviewer input. Check
   supported mechanisms, wrong dismissals, actionable uncertainty, completion,
   actual input/output/cache/price and elapsed. Run full deterministic acceptance
   alongside it. Unknown-price failures stay visible and block a clean live claim.
4. **Decide follow-up promotion once:** use the accepted base, a frozen generic
   selection rule and one bounded cycle. If source-supported quality improves
   enough to justify total price, enable it; otherwise ship it opt-in. No default
   universal second reviewer and no repeated full-app matrix.
5. **Package and release:** verify exact versioned executable/skill assets,
   installers, platform CI and concise release notes. Fix concrete release
   failures. Stop experimentation when these gates pass; record optional audit,
   preparation and routing work as later improvements.

Latest-candidate local deterministic checks still stand. They do not certify
the newly proposed default settings, fresh live quality or hosted acceptance.
