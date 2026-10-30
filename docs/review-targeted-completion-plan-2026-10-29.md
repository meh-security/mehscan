# Balanced review workflow and implementation milestones — 2026-10-29

**Final decision: 2026-10-29 23:17 UTC (19:17 America/Toronto).**

**Current implementation follow-through:** use the [flow hardening and Value-selection plan](review-flow-hardening-plan-2026-10-30.md). Deterministic source/selection fixes have an offline Orchard replay. Bounded proof correction, deadline-preserving recovery and explicit workspace subset export are implemented locally. The offline priority audit and the 30-claim live diagnostic are complete. Native delivery passes; one workspace auxiliary failure still needs explicit independent recovery, so clean unattended acceptance remains gated. Historical paid outcomes and failed states are preserved, with no new full-app inference queued.

**Latest rollout correction, after OrchardCore:** the [537-claim archive results and implementation gates](experiments/review-orchard-recheck-results-2026-10-29.md) keep Terra plus relationship-specific native/workspace review, but do not clear unattended CMS rollout. The assembled base needed 72 offline recoveries; source audit rejected five security promotions. Seventeen workspace judgments were retained and six additional source uncertainties closed. Known spend is $4.5397108 plus one unpriced aborted attempt. The next milestones are normal evidence-format/recovery support, preparation of deciding shared evidence, and targeted security-effect review. Preserve completed experiments; no further paid run is queued until a concrete change needs validation. This later qualification supersedes the broad rollout implication of the earlier decision, not its preserved measurements.

**Fresh-app validation added after that decision:** the user-requested
[PyGoat test](experiments/review-fresh-app-pygoat-results-2026-10-29.md) completed
all 201 claims and a seven-claim selective follow-up for $1.5673714 in measured
reviewer API equivalents. Keep the selected profile. The observed next narrow
improvements are carrying implementation-bound source into evidence-completion
work and distinguishing a demonstrated security effect from a UI/encoding
defect. Automatic selection/acceptance was not implemented in this test; no
further paid experiment is queued. Production-app generalization remains open.

The small experiment sequence is closed. The [final working workflow](review-workflow-final-2026-10-29.md)
supersedes the older “next experiment” recommendations retained below. Select Terra
medium, stable schemas and serial native review for the price-focused profile;
workspace for compatible shared investigations; selective flow review; optional
source-receipt reuse and two-worker speed mode. No automatic helper/supervisor or
second-model pass is enabled. Native bundle defaults remain 20.

The [last concurrency check and integration report](experiments/review-final-concurrency-results-2026-10-29.md)
closes M4: two workers were 25.9% faster for 28.0% more review price, so they remain
an explicit speed option. The normal adapter now implements stable wire schemas,
exact local validation, dependency preflight, mode-bound continuation and private
failure diagnostics. Product regression checks and saved-response replay pass.
No additional paid experiment is queued. Fresh-application generalization remains
a rollout limitation; it is not an automatic extension of this bounded task.

The [two-consumer reuse validation](experiments/review-evidence-reuse-live-results-2026-10-29.md)
is complete: both Terra arms reviewed 13 claims, all 17 calls have receipts, and
rendered source/questions and provenance checks pass. Direct preparation cost
$0.127680; receipt reuse $0.139438. Both corrected expiry wording and preserved
independent guards. Storage was already deduplicated in both paths. Keep the
opt-in receipt-reference API for deliberate preparation/provenance, without
claiming model-cost savings or changing routing defaults. M5's integration gate
passes; its efficiency gate remains unproven. Next is M4 bounded concurrency with
unchanged review inputs, separate scheduling/accounting and failure checks.

The [source-evidence receipt reuse implementation](experiments/review-evidence-reuse-implementation-2026-10-29.md)
now extends the existing controller `prepare-evidence` path. A recipient references
an inspected receipt and supplies its own deciding question; provenance, source
freshness, local dependency observations and atomic replay remain explicit.
Source storage is deduplicated, but no verdict/applicability or model usage is
transferred. CLI-to-fresh-packet and stale/rollback/privilege tests pass. The path
is opt-in within the same workspace/source root; it is not automatic external
dependency resolution. The completed two-consumer validation above preserves
the measured limits; bounded concurrency remains a separate experiment.

Latest [JWT combination results](experiments/review-jwt-combinations-results-2026-10-29.md):
all four Terra arms completed 13 claims with 38 total receipted calls. Every arm,
including control, corrected the six-hour expiry premise. Combined guidance/source
used eight calls, 31 lookups and $0.1219762 versus control's ten, 41 and $0.136968.
Retain the combination as a scoped candidate, not proof of a guidance-caused quality
gain. The one verdict disagreement preserves the same independent IP restriction.
No further JWT tournament now: implement source-bound dependency evidence reuse,
preserve caller-specific checks, then test bounded concurrency separately. Fresh
token implementations remain a generalization gate before broader promotion.

Latest user steering narrowed the guidance retest to [13 JWT-related claims](experiments/review-jwt-combinations-plan-2026-10-29.md),
with four Terra combinations: control, routed token guidance, prepared dependency
source, and both. BS used two complete original groups and identical evidence
access/budgets; all four completed after concurrent dispatch. The proposed
68-claim BR comparison was closed before dispatch with zero model calls. The
completed BP 68-claim package remains the broader regression reference.

Latest [larger completion and workspace results](experiments/review-large-completion-results-2026-10-29.md):
Terra completed all 68 claims for $0.569060 extra, $2.1318248 including the saved
base, with 78.43% cached input. Sol remains stopped on the Daybreak account gate.
The review is promising but not promoted: six-hour JWT wording persists without
reading the available signer; four selector verdicts lack an established protected
effect; adjacent workflow findings sometimes replace scoped negatives. Preserve
useful amendments and test these narrow corrections. BQ2 passed provider schema
acceptance and eight workspace reviews for $0.180969; four claims passed native
finalization, four await their original-bundle peers. The reusable unbound schema
now has the tested alias pattern with exact local membership retained.

Next concrete work: carry the already-inspected versioned signer source to the
credential consumer using existing source/evidence records, and assess whether
the four selector cases establish a consequential effect. Keep BP's 68 claims as
the broad regression set, with changes tested on affected complete groups first.
This supplies a demonstrated M5 handoff case while M4 concurrency remains a
separate execution experiment. No full-app rerun or universal reviewer is needed.

User expansion: the [larger targeted completion comparison](experiments/review-large-completion-plan-2026-10-29.md)
now runs 68 claims in eight complete original groups per model, replacing the
earlier 30–40-claim estimate. Terra and Sol receive identical saved first-pass
outcomes, source and versioned vendor access, with explicit flow/amendment fields.
This is a bounded reviewer diagnostic, not product-native admission or a blinded
production selector test. The [workspace format retest](experiments/review-workspace-format-live-plan-2026-10-29.md)
is separate. Preserve the remaining 48 base claims in amended diagnostic packages.
See the [current larger-slice progress](experiments/review-large-completion-progress-2026-10-29.md):
Terra is running; Sol stopped on another Daybreak account-security block during
the first group, with six receipts and one unknown attempt. The frozen inputs are
preserved. BQ's separate workspace retest exposed unsupported regex lookaround;
BM2's simpler pattern passes offline checks and awaits a new bound live test. Do not
present these as completed paired results or retry through another route.

The [Sol native recovery](experiments/review-sol-native-recovery-2026-10-29.md)
is complete: 116 validated claims, 98 reconciled receipts out of 99 actual calls,
$3.8097692 known price, 66.53% cached input and 42m 11s summed paid-attempt elapsed.
One historical actual receipt remains unknown; no new receipts are missing.
All 434 decisive excerpts match source bytes and the original 86 results are
unchanged. M1 now has three complete-coverage arms and partial Terra hybrid;
Sol native's price remains qualified. The recovery does not change the direction:
Terra first pass, then targeted evidence-and-flow review. Sol native still repeats
the six-hour JWT premise that Sol hybrid avoids. Preserve the historical partial
comparison alongside the recovered one; do not buy another full-app rerun.

The user-requested [Daybreak retry](experiments/review-sol-daybreak-retry-2026-10-29.md)
succeeded on the same Sol thread/prompt/schema/provider route after refreshing
normal configured authentication. Its seven-claim final response was validated
without repurchasing it; the $0.0498184 retry cost is included in the recovered
total above. The [original Sol report](experiments/review-stable-sol-results-2026-10-29.md)
preserves the earlier partial execution and the complete $4.203882 Sol-hybrid arm.
There is no current account-security block on this completed recovery; the missing
historical receipt remains an accounting limitation.

The target is a cheap parallel first
pass, source-backed shared state, and selective review of flow correctness and
verdicts. Quality and complete-package price remain primary; latency is secondary.
The milestones below govern implementation and promotion. Existing experiment
contracts remain frozen; this document does not rewrite completed experiment inputs.
M2's [offline citation-format and isolation checks](experiments/review-workspace-format-readiness-2026-10-29.md)
now pass, including replay of the exact BK rejection. Provider acceptance and the
eight-claim live retest are next, together with M3 offline readiness. No paid calls
have yet been made for M2.
User steering after that result added two Sol comparison arms. The
[Sol native/hybrid plan](experiments/review-stable-full-sol-plan-2026-10-29.md)
used the unchanged BK schemas and evidence with Sol 6.1 medium in parallel;
the workspace syntax fix was deferred to isolate this comparison. BL2 passed
model binding, adapter, failure-isolation and all 49 initial packet checks before
dispatch. Keep the targeted-completion sequence below after these results; the
completed Sol hybrid demonstrates useful corrections but also missing mechanisms,
so it is not promoted as the full-app default.
The earlier [BH direct-versus-helper test](experiments/review-subagent-isolation-plan-2026-10-29.md)
on Terra and Sol is closed partial. BH has its own fresh
state, finite allowance and accounting; it does not reopen BG or execute this
plan's targeted-completion comparison.
The [BH partial result and cache report](experiments/review-subagent-isolation-results-2026-10-29.md)
preserves one completed Terra JWT pair. All four arms were interrupted when the
pinned runtime disappeared; four actual calls have unknown usage. Remaining BH
work is recorded separately and must not be mistaken for a completed comparison.
This supersedes the next-experiment recommendation in the full-app plan, not its
historical execution contract or results. BG remains closed.

Latest execution order: the user requested a [full Terra native cache/cost/time
rerun](experiments/review-terra-full-cache-rerun-2026-10-29.md) after BH's interruption.
That measurement is complete: 116 claims, 84 calls, $3.410960 Standard API
equivalent, 18m 18s review elapsed, and zero cached input tokens. Thirteen verdicts
changed; the new package is not automatically promoted over the baseline.
The subsequent [stable-schema paired slice](experiments/review-stable-schema-results-2026-10-29.md)
completed 27 claims per arm with matching verdicts/severities, no local schema
rejections, 71.7% cached input and 61.4% lower total price. It retained known
quality limitations, including the JWT lifetime premise. Keep the study variant;
the full Juice Shop follow-up is now complete, including the omitted ORM bundle.
That bundle contains controls and positives, not 19 clean controls. Targeted completion remains the subsequent
quality/price plan. Another unchanged dynamic-schema full rerun is unnecessary.

The user authorized that wider comparison: [BK full native and hybrid stable-schema
test](experiments/review-stable-full-native-hybrid-plan-2026-10-29.md). Both Terra
arms ran in parallel with original source and routing. The [BK results and exact
disagreements](experiments/review-stable-full-native-hybrid-results-2026-10-29.md)
show complete native at $1.562765 (116 claims, 66.06% cached input, 21m 02s),
54.2% below BI2 price despite more input and time. Recovered hybrid costs $1.421542
for 102 claims, with 14 explicit execution gaps; it is not a complete cheaper arm.
Native continuations account for the cache benefit. Both workspace calls missed
cache, and one was rejected for navigation IDs used as source handles.

Next bounded checks after the active Sol comparison, without another full-app rerun:

1. Constrain the stable workspace evidence-string syntax to source aliases while
   retaining exact local membership checks. Test invalid navigation IDs, plausible
   but unavailable aliases, rejection accounting and independent-unit continuation
   offline. Preserve failed groups and their costs; do not admit rejected facts.
2. Retest the same eight-claim workspace group with the narrow fix and frozen
   evidence. Report the additional cost separately and cumulatively; do not splice
   it into the original full-run timing. Restore native fragment coverage separately
   if a full hybrid package is needed. Stop if the fix does not prevent the known
   format error or compromises exact evidence validation.
3. Resume the completion comparison below using source-bound JWT contracts,
   the retained NoSQL test-source evidence, CAPTCHA reuse, registration's downstream
   contract, and consequential unresolved writer-to-effect links. Both arms show
   useful mechanisms and gaps. NoSQL improvements in hybrid came from native-routed
   groups and do not establish a workspace advantage.

## Decision

Use Terra native as the first-pass candidate, followed by selective evidence
review. Test whether that second stage needs Sol before making Sol the default
reviewer. Keep native local SQL/API closure and workspace for compatible shared
investigations. Do not generalize one approach across rules.

First establish the cheapest way to correct consequential gaps; then improve
reusable state around that proven workflow. The audit demonstrates missing or
incorrect implementation facts. It does not yet demonstrate that a larger memory
system, or a more expensive model everywhere, solves them.

This is an experimental direction, not production-default promotion or a claim
that any saved package is sufficient without qualifications.

## Target workflow

The controller owns scheduling, claim coverage, budgets, receipts, progress,
failure isolation and package assembly. Models investigate a bounded operation,
selected claims and deciding questions using relevant source and lookup access.
Move reconstructable procedural bookkeeping out of repeated model instructions.

| Work | Execution mode | Closure requirement |
| --- | --- | --- |
| Local SQL construction, binding or a complete API contract | Native | Settle the exact local mechanism with its applicable contract; no automatic exhaustive caller search |
| Claims sharing implementation and compatible caller context | Workspace investigation | Share source and qualified facts while retaining separate claim verdicts |
| Authorization, credentials or workflow transitions | Native or workspace according to actual shared dependencies | Establish the relevant identity/object/check-to-effect relationship and independent guards |
| A missing implementation contract blocking several consumers | Optional bounded helper | Produce inspectable, version-bound facts with explicit applicability and unresolved edges |

File/category/operation proximity alone is insufficient for grouping. SQL stays
native where local closure works. Neither native nor workspace is mandatory for
every claim in a rule family. Current hybrid NoSQL improvements came from native
groups and cannot be attributed to workspace routing.

Shared state distinguishes implementation facts, caller/configuration applicability,
open questions/conflicts and derived conclusions. Reuse existing evidence,
proposition and applicability records first. Each reusable fact links to source,
version/hash and scope; invalidate or recheck it when those bindings change.
Another model's summary or verdict is not independent evidence. Workers retrieve
the relevant records and supporting source, not the entire application history.
Controller/CLI views should expose pending deciding questions, available evidence,
dependencies, accepted amendments and gaps; an interactive CLI is a view over the
same durable state, not another mandatory conversation or source of truth.

Subagents first mean bounded parallel workers for independent investigations.
The existing review conversations already supply much of that isolation; the
new benefit is concurrent scheduling within an arm. Keep dependent work ordered
and state writes scoped/atomic. Do not add a model supervisor that re-summarizes
every claim. The completed BH helper pair cost 19.85% more overall: helper
production and consumer validation must earn their cost through observed reuse.

The output is one complete review package: separate verdicts, inspectable flow
support, retained mechanisms and conditions, traceable amendments, and explicit
execution/evidence gaps. A report may be useful while incomplete; it must say so.

## Milestones and promotion gates

Milestones are evidence gates, not calendar promises. M2 and M3 can proceed as
separate experiments after M1; do not combine model, routing, prompt and concurrency
changes in one treatment. Offline preparation can proceed while Sol runs. Paid
dispatch must use its own frozen protocol and accounting.

| Milestone | Status / dependency | Deliverable | Advance when | Stop or correct when |
| --- | --- | --- | --- | --- |
| M0 — Establish stable-schema economics | Complete for Terra native; hybrid partial | BK receipts, claim audit and explicit 14-claim gap list | Native has 116 validated claims, known usage and observed cache-adjusted savings | Do not treat this as proof of precision or workspace cache savings |
| M1 — Close the model comparison | Closed with recovered Sol native: 116 claims; one historical missing receipt. Terra hybrid remains partial | Four-arm comparison with common-claim audit, mechanism coverage, failures, total price and elapsed time | Every actual call is reconciled or explicitly unknown; full versus partial coverage is clear; disagreements have source-informed assessments | No winner from label agreement or partial-package cost; reconcile failures before ranking |
| M2 — Repair workspace execution narrowly | Format compatibility passed on BQ2; eight workspace outcomes, four native-finalized; reusable schema updated | Offline source-alias/validation/recovery tests, then the original eight-claim workspace retest | Known navigation-ID error is prevented, exact local membership checks remain, accepted work survives failure, independent groups continue | Do not strip bad citations, admit rejected facts or reset budgets; preserve a partial result if another failure occurs |
| M3 — Test evidence-and-flow completion | Terra 68-claim diagnostic complete; surgical quality corrections needed; Sol blocked | Frozen selector and handoff; Terra versus Sol completion on the same saved BK native base; two complete amended packages | Supported corrections and actionable uncertainty survive; risky negatives and unsupported impacts are checked; added cost is justified by source-audited improvements | If both models lack the same contract, fix acquisition; if selection misses confident errors, fix selection; retain scoped useful modes |
| M4 — Parallelize independent work | Complete: serial price profile; two workers optional for speed | Bounded worker pool using existing native/workspace sessions, shared budgets and dependency-aware scheduling; sequential versus concurrent comparison | Complete coverage, receipts and state integrity are preserved; no observed consequential quality loss; measured wall-time gain is worth any price change | Back off on rate-limit churn, duplicated work, state races, unknown usage or loss of useful cache reuse |
| M5 — Reuse deciding facts where duplication remains | Two-consumer integration verified; model savings unproven. Retain opt-in receipt reference | One demonstrated shared-fact/helper case, source-bound reuse and invalidation checks, whole-package direct-versus-helper accounting | Multiple compatible consumers actually reuse the fact; total cost or critical-path time improves with supported conclusions preserved | No speculative amortization; if producer plus consumers costs more without compensating quality/time benefit, retain direct review |
| M6 — Validate the balanced package and integrate | Working opt-in profile integrated and regression-checked; fresh-app rollout qualification remains explicit | Final configuration/workflow, native finalization checks and recorded limits; fresh-app qualification before broad promotion | Preserve tested scope and inspectable failures, amendments and accounting; no claim of automatic selector or cross-app precision | Correct concrete regressions before broader rollout; do not restart a tournament by default |

M3 precision is evaluated through source audit, not model confidence. Record
supported positives, wrong dismissals, unsupported impacts, flow errors,
retained/lost mechanisms and actionable unresolved questions separately. Include
otherwise unflagged samples and identify the audited denominator; do not present
a selective audit as application-wide precision/recall. Agree on any release-level
numeric quality threshold before M6, using the relevant product risk tolerance.

For M4, start with a small fixed pool (for example, 2–4 independent groups), keeping
the model, packets, prompts, budgets and routing unchanged. A provisional useful
latency target is at least 30% less arm elapsed with no more than 10% extra total
price and no observed consequential quality regression. These are experiment
targets to freeze before dispatch, not established performance or hard truncation
limits. Retain a smaller gain if it is operationally useful and transparently priced.
Repeat a borderline result before promotion; distinguish stochastic model changes
from scheduling effects. Dependencies must never be bypassed to meet a speed target.

The next implementation deliverable is M3 offline readiness plus the M2 narrow
format/recovery fixture, not a new generic memory subsystem. M4 can reuse the
existing conversation workers; M5 helper agents are conditional rather than a
prerequisite for a useful product.

## Historical evidence and practical ranking (BG/BD, before stable schemas)

Sources: [full BG report](experiments/review-full-hybrid-comparison-results.md),
[previous plan](review-full-app-comparison-plan.md), and the exact
`C:/dmitry/scan-runs/workspace-full-hybrid-comparison-20261029-bg/source-quality-audit.json`
and `comparison.json`. All four packages contain the same 116 claims.

| Rank | Saved arm | Reason | Material limitation |
| --- | --- | --- | --- |
| 1 | Terra native | Cheapest; preserves like-selector/YAML questions, privileged-registration mechanism and unpaid-entitlement lead | Available source remains unread; some legacy-auth negatives overstate the effective contract |
| 2 | Terra hybrid | Essentially price parity; useful shared cookie investigation and additional local closures | Drops unpaid-entitlement lead, changes broad-CRUD mechanism coverage, leaves precise `$where` contract unresolved |
| 3 | Sol hybrid | Useful targeted-review candidate: tracking/admin HTML chains, Product PUT authorization and legacy-verifier questions | Repeats consequential like-selector/YAML dismissals and inconsistent expiry assumptions; higher cost |
| 4 | Sol native | Useful mechanisms and adjacent leads, but weaker purchase than alternatives | Higher cost with consequential dismissals and overstated expired-token reasoning; lacks several new Sol closures |

This historical ranking is not the current stable-schema leaderboard and must
not set today's cost headroom. It is a practical selection ranking, not an accuracy leaderboard. Terra arms
are close; their $0.025 difference should not decide the choice. Sol hybrid and
Terra native have complementary quality strengths. Most new Sol closures arose
in native portions: do not attribute them causally to workspace routing.

| Arm | Standard credits | Standard API USD equivalent | Recorded provider time | Summed attempt time |
| --- | ---: | ---: | ---: | ---: |
| Terra native | 89.017690 | 3.560708 | 17.2 min | 20.0 min |
| Terra hybrid | 89.638110 | 3.585524 | 17.7 min | 23.3 min |
| Sol native | 206.939900 | 8.277596 | 40.0 min | 42.7 min |
| Sol hybrid | at least 210.425250 | at least 8.417010 | 44.8 min plus unmeasured call | 65.1 min |

Retain the frozen October 28 Standard equivalents, not invoices. One actual Sol
hybrid invocation has unknown usage. Attempt time includes stalls/recovery and
excludes offline gaps; it is not clean end-to-end latency. Preparation and human
correction are incompletely measured. Terra native is 57% cheaper than Sol native
and uses roughly 43% of its recorded provider time.

## Why an additional reviewer must challenge evidence

- Reviewing only `needs_review` misses confident legacy-verifier dismissals.
- Sol is not an automatic adjudicator: it could turn Terra's useful selector and
  YAML uncertainties into unjustified dismissals.
- Verdict-label agreement misses different CRUD mechanisms and lost payment
  leads. Compare the complete mechanism set, qualifications and remaining work.

The second stage receives a specific deciding question, source references,
relevant first-pass evidence and lookup access. A changed verdict needs a
source-supported reason. Model agreement is not proof. Preserve first-pass
results and record amendments separately; do not silently overwrite history.

Its review object is **claim → applicable operation → input/identity →
transformation or guard → sensitive effect → conclusion**. Audit each consequential
edge, including object equality, ordering, rejection behavior, dependency semantics
and independent controls. A reviewer may retain the verdict while correcting its
impact or conditions, request a deciding lookup, preserve uncertainty, or retain
an adjacent mechanism separately. Do not require a label change to count a useful
correction. Do not require full application reconstruction to validate a local edge.

Use an independent reviewer session with a stable contract and a source-backed
evidence package. Present the first-pass conclusion as a proposal to challenge,
not an authoritative fact. Do not silently reuse the investigator's conversation
as the independent reviewer merely to seek cache hits. Select Terra or Sol by
observed incremental correction, including their shared failure modes.

Reuse established facts with source/version/hash provenance and caller-specific
applicability. Do not turn evaluator conclusions into reviewer facts or introduce
a new memory schema before existing workspace evidence/question records prove
insufficient.

## Next experiment: same saved base, two completion strategies

Reuse the stored **BK stable Terra-native** 116-claim package without buying another first
pass. The user expanded this to 68 selected claims in eight complete original
bundles for BP; these are declared development regression groups. Freeze the
exact selection and complete peer coverage before dispatch.

| Work family | Deciding test |
| --- | --- |
| Legacy JWT/cache/guards | Correct unsupported expiry/verifier assumptions while preserving independent caller checks |
| Like-review branches | Establish whether the checked record equals the updated record |
| YAML consumers plus traversal controls | Separate safe filename selection from content integrity and consumer-specific effects |
| Generated CRUD/registration | Preserve distinct mechanisms and complete the relevant authority chain |
| Tracking/admin HTML | Close the actual producer-to-consumer gaps |
| Payment lead | Preserve the separate entitlement transition |
| Available local producers | Close log/CAPTCHA questions economically |
| Cookie conditions and clean controls | Preserve justified uncertainty and scoped negatives without exhaustive investigation |

Run two new treatments:

1. Terra 6.1 medium targeted completion.
2. Sol 6.1 medium targeted completion.

Both get identical starting evidence, source access, routing, workflow and stopping
rules. Use workspace for a shared deciding fact with compatible caller contexts,
and native review for local closure. Isolate reviewer-model choice; do not also
change prompts, evidence or routing between arms. Neither sees the other arm's
answers or evaluator adjudication. Existing saved Sol packages are comparators,
not answer keys supplied to reviewers.

Exact dependency source must be equally available. Reviewers establish its
meaning from inspectable source. Count acquisition, preparation and any model
assistance. Evaluator-only vendor reads do not become retrospective BG evidence.

The primary question is whether Sol buys enough additional supported correction
over a properly equipped Terra reviewer to justify its premium.

## Selection must be tested, not supplied by an oracle

Freeze general triggers against first-pass artifacts before scoring them:

- Material unresolved questions with accessible deciding source.
- Negatives depending on an unestablished verifier, selector, sanitizer or
  framework contract.
- Positives whose asserted impact, reachability or flow exceeds their evidence.
- Conflicting assumptions or unresolved adjacent mechanisms across the package.
- A stratified sample of otherwise unflagged negatives.

Count consequential audit problems missed by selection as workflow failures.
The author has already seen this Juice audit; freezing a new selector now does
not make its development independent or blind. Keep known regression coverage
distinct from claims selected by general triggers, and report that overlap.
Do not tune until every known ID is selected and call that generalization.

The proposed families are regression requirements, not production rules keyed
to application names or claim IDs. After a successful small test, validate frozen
selection on a fresh application. Do not repeat the full Juice tournament merely
to obtain cleaner labels.

## Price, time and whole-package accounting

Use the actual saved first-pass cost once per candidate package, plus all new
routing/preparation/reviewer/recovery/assembly costs. Shared experimental costs
and cumulative study expenditure should be reported separately and transparently.
Carry all 116 IDs and retained mechanisms into each amended package, including
unselected outcomes and unresolved selected work.

| Illustrative added model cost | BK Terra base plus completion |
| --- | ---: |
| $0.50 | $2.062765 |
| $1 | $2.562765 |
| $2 | $3.562765 |

These are scenarios, not forecasts or dispatch caps. The saved BK first-pass cost
is $1.5627648. Replace the obsolete BG-based $4.7168884 headroom calculation with
the completed BL2 Sol-native price minus that base, once comparable coverage and
quality are established. A cheaper first pass does not automatically justify a
large reviewer budget: measure marginal supported correction and remaining review
work. Keep total output, helper production, retries and rejected responses in cost.
Do not extrapolate cost linearly from claim counts or charge experimental alternative
arms as though every production package runs all of them.

Measure input, cached input, output, all actual calls, provider time and real
end-to-end completion time. Measure preparation and human correction separately;
do not invent labor costs. Independent groups may run concurrently once their
first-pass evidence is ready. No blanket three-minute or 3M-input cutoff.

### Cache accounting — added 2026-10-29 at user request

Keep the contract, tool definitions and wire schema stable; append changing
evidence after stable material where the protocol supports it. Retain exact
turn-specific local validation. Continue an investigation in its existing native
session when appropriate; distinguish that from a new independent reviewer.
Workspace's fresh-context protocol has not demonstrated the native cache benefit.
Any workspace prefix/session change needs its own bounded comparison, preserving
state authority and offered-handle constraints. Do not pad prompts or include
irrelevant source to inflate cache-hit percentage.

Track evidence reuse separately from cache reuse: the former avoids rediscovery
and conflicting assumptions; the latter discounts repeated input. Measure source
duplication, repeated deciding questions and helper overhead alongside price.

Treat cache behavior as a first-class price dimension in the small comparison
and subsequent larger runs. Preserve per-call receipts and aggregate by model,
mode, family, role and session. Report total input, cached input, uncached input,
output, separately reported cache writes, calls with cache hits, and token-weighted
cached-input fraction (sum cached input / sum input, not mean call percentages).
Missing counters are unknown, never zero.

Show observed cache-adjusted Standard equivalents alongside the same receipts
repriced without cache-read discounts. The difference is the observed discount
under the stated rate schedule, not a measured cold-cache run or an invoice.
Account for applicable cache-write/context/tier charges when present; do not
assume a single rate schedule across billing routes. Keep output price included.

Separate less work from cheaper repeated work: source duplication and total input
can remain high while cache-adjusted price falls. Quality and complete-package
price remain primary. Provider elapsed time is observed; no latency improvement
may be causally attributed to cache without a controlled comparison.

Record model/effort, runtime and prompt/schema revisions, execution order,
concurrency, request timestamps, prefix identity where observable, and whether
the measurement is a first call or continuation. Do not call a fresh conversation
a cold cache or assume a resumed conversation is a hit. Concurrent alternatives
may share cached prefixes; provider-side cache attribution/eviction is unobserved.
Do not buy synthetic warm-up calls to improve a benchmark. Include any actual
warm-up or failed-call costs in the package. Report both observed cache behavior
and no-discount sensitivity before projecting savings to larger deployments.

## Continue, correct, stop or expand

Advance when the completed package corrects consequential unsupported conclusions,
preserves supported mechanisms/actionable uncertainty, avoids new wrong dismissals
and invented impacts, and reduces remaining reviewer work at a useful total price.
Do not score closure counts, severity totals or label agreement as accuracy.

- If Terra completion is comparable, keep Terra for both stages.
- If Sol improves particular families materially, route those families to Sol.
- If both fail on the same missing contract, fix evidence acquisition before
  buying more reasoning.
- If selection misses confident errors, correct selection before expansion.
- If a narrower mode is useful but imperfect, keep it with its qualifications.

Dig further only when the next source/contract fact can change the selected
conclusion or substantiate an explicitly stronger impact. Stop when the scoped
mechanism or negative is supported; preserve a precise unavailable fact as
uncertainty. Do not force deployment proof for every conditional source finding.

Before paid execution, freeze concrete packets, fresh state, source bindings,
provider/runtime configuration, finite per-unit limits, accounting and recovery
behavior. Retired BG slots and states stay retired. Unknown actual usage stops
the affected arm pending reconciliation. Keep mutable progress outside frozen
dispatch inputs. Do not reopen or modify historical artifacts.

## Immediate implementation readiness

Existing components to reuse:

- `review_workspace.py`: evidence, scoped propositions, caller applicability,
  deciding questions, partial drafts and review-package views.
- `review_workspace_bridge.py`: binding, preparation, question-linked evidence,
  review and finalization.
- `review_workspace_planner.py`: bounded native source/caller grouping.

Initial read-only inspection found two constraints to resolve before dispatch:

1. The planner documents a 1–32-ID intake. A proposed 30–40-claim slice may need
   complete partitions with an app-wide ledger; do not silently truncate or widen
   intake merely to meet the estimate.
2. Planner application requires fresh unassigned state. Saved Terra outputs need
   an explicit source-bound first-pass evidence/amendment handoff into fresh
   completion state; do not resume or mutate the completed native/BG sessions.

Next deliverable: offline readiness artifacts containing the saved-base binding,
general selection rules and reasons, known-regression versus selected coverage,
compatible work groups with complete peer coverage, identical model packets,
versioned source access, and amendment/accounting checks. Check existing handoff
support before adding code. No AI grouping pass or generalized memory subsystem
is required by this plan.
