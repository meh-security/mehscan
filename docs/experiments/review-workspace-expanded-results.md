# Expanded workspace comparison — 2026-10-26

Follow-up: the [fresh fixed-controller confirmation](review-workspace-confirmation-results.md)
is complete: 31 versus 21 calls, no controller errors and matching claim verdicts.
Its report qualifies the basket cap and distinguishes unvalidated leads from
classified findings. The repair-affected measurements below remain unchanged.

Status: **completed**. Four approaches reviewed the same twelve native claims.
All 48 final dispositions passed native source validation; none was admitted to
native state. There are no unassessed cases or unknown provider counters left in
this experiment. A `needs_review` disposition is still unresolved security work,
not a supported finding or an affirmative dismissal.

The useful direction is narrower than a universal winner: **share investigations
where they share deciding work; keep rule-specific closure and independent
verdicts; retain source-backed facts and unavailable dependencies in application
state.** Grouping helped SQL and deluxe substantially in this slice, did not
settle the basket dependency gap, and did not improve the code-fix pair. Merely
supplying larger operation regions did not solve repeated investigation.

This supersedes the earlier two-consumer stop decision. Input is cheap and
output currently negligible for the user's decision. Their measured volumes
remain in the ledger, but percentage token reductions are not acceptance gates.

## What ran

The [frozen plan](review-workspace-expanded-plan.md) compared:

- A: native windows plus bounded route references, singleton investigations.
- B: complete bounded operation/effect regions, singleton investigations.
- C: the same complete regions, seven concrete working groups.
- D: complete-region singletons with the unchanged wallet notebook delivered
  only to six selected claims whose actual route calls its helper.

All used the same model, effort, provider, pinned application snapshot and lookup
API. Native bundles stayed singleton; groups shared investigation, not verdicts.
The selected slice includes SQL positives, ownership and parser/file controls,
deluxe workflow branches, a generated resource and a password-change case new to
the live workspace comparisons. These are development cases from one application,
not a held-out accuracy benchmark. SQL has two positives and no bound-query control.

## Actual execution, including repairs

| Approach | Paid calls | Model-reported time | Active execution time | Input | Output | Final validated dispositions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| A: thin singletons | 35 | 554.0 s | 657.6 s | 572,572 | 16,700 | 12/12 |
| B: complete-region singletons | 36 | 608.5 s | 717.2 s | 685,647 | 17,629 | 12/12 |
| C: complete-region groups | 21 | 406.4 s | 475.5 s | 400,197 | 12,625 | 12/12 |
| D: complete regions + seed | 29 | 578.8 s | 671.1 s | 573,488 | 17,686 | 12/12 |

Active execution adds each arm's first pass and repair execution. It excludes
time waiting for other serial arms and evaluator work. Shared matrix preparation
cost **90.606 seconds**. The artifact audit was taken **3,352 seconds after matrix
freeze**, including serial scheduling, diagnosis, code/test work and waits; that
is a development-cycle measurement, not model latency. A local migration helper
aborted before dispatch in 1.534 seconds; it made no provider reservation or call.

Actual new matrix spend is **121 observed provider calls**, **2,231,904 input**,
**64,640 output**, **6,528 cached input tokens** and **2,147.630 seconds of reported
provider time**. Nothing unknown was treated as free. The seed was an existing
artifact: producing it previously cost another **2 calls, 25,140 input, 979 output,
31.507 seconds reported model time and 177.825 seconds preparation-through-result**.
The main D row measures consumers; adding that producer gives D 31 calls and
598,628 input. Do not double-charge that historical production as a new matrix call.

There is a measured 15-call difference between B and C, but **41.7% fewer calls
is not a clean estimate of the grouping effect**. The first pass exposed state
defects, and repair affected arms differently. Call counts, source-volume ratios
and timing here include those failures. A matched repeat under the fixed
controller is needed before claiming a reliable operational saving.

## Compare deciding work by family

Cells are paid calls / reported model seconds. Rejected turns remain charged.

| Investigation | A | B | C | D |
| --- | ---: | ---: | ---: | ---: |
| Two SQL constructions | 3 / 51.4 | 2 / 46.8 | **1 / 35.8** | 2 / 41.4 |
| Two basket PUT claims | 8 / 119.7 | 11 / 157.1 | **6 / 103.0** | 8 / 129.2 |
| Wallet/card control | 2 / 27.9 | 5 / 66.3 | 3 / 36.9 | 3 / 67.5 |
| Three deluxe branches | 6 / 100.0 | 9 / 154.2 | **2 / 41.5** | 5 / 133.9 |
| File read + YAML pipeline | 6 / 123.4 | **3 / 86.8** | 4 / 100.8 | 3 / 87.5 |
| Generated resources | 6 / 78.7 | 3 / 52.0 | 3 / 53.5 | 5 / 75.7 |
| Password change | 4 / 53.0 | 3 / 45.3 | 2 / 34.9 | 3 / 43.6 |

**SQL:** the grouped call retained both independent injection mechanisms and
login's second-factor qualification. This supports a small local-construction
batch; it does not establish safety on bound queries, dynamic identifiers or
mixed safe/unsafe constructions. These are similar closure questions, not a
shared implementation fact.

**Deluxe:** three branches share the same identity middleware, handler and
membership effect. One investigation reused that relationship and retained
separate decisions. This is the strongest concrete grouping example here.

**Basket:** grouping made both claims use one consistent uncertainty record,
but still took six calls. The model investigated global middleware, the model,
associations and immutability hooks, missing dependency paths, API tests and
Cypress tests. The common unresolved question was the generated update's
selection/authorization/persistence behavior. Fewer conversations did not supply
that missing fact.

**Code-fix pipeline:** C took four calls versus B's three. After closing the
path read, it investigated YAML version, asset references, an example fixture
and an offline maintenance utility. Shared files and a shared prerequisite were
insufficient to guarantee a better investigation. Keep partial closure and allow
different rule strategies instead of forcing every same-pipeline pair into a batch.

**Memory:** for the six seed-eligible claims, B used 25 calls / 377.584 seconds,
while D used 16 calls / 330.558 seconds. The seed avoided some identity-helper
reconstruction and two deluxe branches closed in one call each. Adding the
producer leaves only about 15.5 seconds of reported model-time difference on this
subset; adding its preparation makes the timing case weaker. These repair-affected
numbers support further targeted fact delivery, not a general memory index or
a claim that fewer calls necessarily means proportionally less review time.

## Quality and uncertainty audit

`I` = finding, `N` = scoped local negative, `U` = actionable unresolved question.
Every row represents a separate native claim even when the investigation is shared.

| Claim / operation | A | B | C | D |
| --- | --- | --- | --- | --- |
| Product-search SQL | I | I | I | I |
| Login SQL | I | I | I | I |
| Basket PUT registration | U | U | U | U |
| Basket-item lookup | I | U | U | U |
| Wallet/card ownership | N | N | N | N |
| Deluxe user selection / upgrade | N + payment lead | I: payment bypass | N + payment lead | I: payment bypass |
| Deluxe wallet selection | N | N | N | N |
| Deluxe card selection | N | N | N | N |
| Code-fix metadata path | N | N | N | N |
| Code-fix YAML load | N | N | N | N |
| Generated Product authorization | I | I | I | U |
| Optional password reauthentication | I | I | I | I |

Both SQL mechanisms survive in every package. Login findings correctly retain
the TOTP condition; the password findings require possession of an accepted
session and do not describe an unauthenticated password reset. D rates that
password mechanism high while the others rate it medium: severity remains variable.

Ownership negatives trace the overwritten caller identity into the selected
query and effect. They do not certify payment correctness. Every package retains
the deluxe unsupported/omitted-payment-mode bypass, either as a finding or an
adjacent lead. B/D attach the workflow finding to the broader user-selection
claim; A/C close cross-account selection and retain the payment lead separately.
That retains the concern, but an unvalidated lead is not a classified finding;
the follow-up report makes that workflow gap explicit. D additionally keeps
a useful wallet credit-amount/payment-settlement lead.

The file/YAML negatives use the actual filename-prefix prerequisite and local
asset provenance. They do not treat `existsSync` alone as path containment or
certify `yaml.load` for hostile YAML. No wrong dismissal was identified in these
selected local controls; this is a source audit, not measured whole-app precision.

The basket disagreement is material. A's item finding infers the generated CRUD
effect while its registration claim remains unresolved. B/C/D require the
downstream contract and retain the exact ownership-to-write gap. Their tests
do not directly demonstrate a cross-owner PUT. Do not count two scanner anchors
as two independent demonstrations, force agreement by dismissing the concern,
or score a precise uncertainty as an established finding.

Generated Product review also exposes inconsistent evidentiary thresholds. A/B/C
report the unguarded Product PUT; A also cites the anonymous update test. D sees
the same missing guard but requires dependency code or a persistence-verifying
test and leaves it unresolved. Native source validation does not resolve that
security disagreement. This prevents declaring all four packages quality-equivalent.

An evaluator-only download verified the integrity of published `finale-rest`
1.2.2 source: its update path fetches the instance, applies attributes and saves
it. This is a useful common dependency contract for the basket/Product questions.
The corpus declares `^1.2.2` but has no root lockfile, so that reference does not
prove the deployed resolution. It was not supplied to any review arm, and was
not used to rewrite their verdicts. See the [published package](https://www.npmjs.com/package/finale-rest?activeTab=versions)
and the saved evaluator dependency receipt. No application runtime/exploit test
was run in this comparison.

## What the application state must own

The first pass ended with 27/27/19/21 calls and 3/5/2/5 unassessed claims. Fifteen
paid answers hit controller failures. A later unseen-proposition-name collision
rejected one more paid answer. These are real costs, not reviewer-quality misses.

The implemented corrections address the state model:

1. A deciding question remains open while each lookup records its own narrower
   requested wording. Exact text equality is not a continuation requirement.
2. Independent contexts can choose the same question/proposition name. The
   controller scopes unseen collisions to the work, maps references consistently,
   and preserves separate revision and applicability histories. It still rejects
   answering/applying unseen foreign knowledge or changing a visible question's scope.
3. Loaded category guidance stays with the investigation that requested it.
   It must not silently alter every later context.
4. A citation spanning supplied definitions can be split into supplied ranges
   across verified blank separators. Gaps containing unseen code remain rejected.

Original first-pass stores, answers and results remain intact. Repair phases use
explicit isolated runtime forks, retain all paid counters, and verify deciding
context/source-handle equality before replay. When context changed, a fresh turn
was charged within the original six-call work allowance. The last proposition
repair replayed an unchanged final answer with **zero provider allowance**.
A migration-helper duplicate-key abort was recorded before dispatch and retried
under a separate manifest; it was not a zero-token model call.

All final counts respect six calls per investigation, 48 per arm and 192 overall,
plus the original query/source ceilings. **61 workspace tests and 8 protocol
tests pass.** All 48 native finalization response files were checked against
their selected IDs and decisions. No decisions were admitted and ordinary
worker scheduling/default bundle size was not changed.

## Repeated source, without making it the selection gate

| Arm | Paid-packet source bytes | Distinct source line/text bytes | Repetition across work items | Repetition including continuation packets |
| --- | ---: | ---: | ---: | ---: |
| A | 508,303 | 82,886 | 2.235× | 6.133× |
| B | 802,353 | 104,795 | 2.542× | 7.656× |
| C | 467,251 | 97,564 | 1.681× | 4.789× |
| D | 595,882 | 83,424 | 2.757× | 7.143× |

This measure deduplicates exact path/line/text identities, preserves partial AST
line identities separately, and counts only packets delivered to paid calls.
It is not an exact tokenizer or a whole-file repetition estimate comparable
without adjustment to the historical 7.5× figure. Native lookup reuse reduced
I/O but did not automatically eliminate a fresh model turn or repeated source
delivery. C had only 6,528 cache-hit tokens; provider caching is not the explanation.

## Corrected next implementation and experiment

1. **Confirm B versus C under the fixed controller**, with fresh isolated state,
   unchanged twelve IDs, source profiles, provider and separate verdicts. Retain
   raw and repaired K as development evidence. Freeze at most 48 calls/arm,
   six/work and 2,400 seconds active/arm; stop an affected arm on unknown usage.
   Do not repeat A/D merely to obtain prettier numbers. This clean confirmation
   precedes a quantitative savings claim. The subsequent [confirmation](review-workspace-confirmation-results.md)
   has now run; its measurements and qualifications are separate from K above.
2. **Close the shared dependency gap once.** Add controller-owned observations
   for absent source and a version/provenance-aware dependency-reference path.
   Distinguish declared range, resolved version, fetched source and observed
   runtime effect. Offer the same reference to both basket anchors and Product
   review; never transfer an ownership verdict. A missing dependency must not
   cause each claim to repeat path/test exploration or become a dismissal.
3. **Make the state inspectable through a small interactive CLI.** Provide a
   queue of work/claims, deciding question, requested fact, returned evidence,
   remaining gap, fact consumers/revisions, actual usage and resume/split actions.
   Status inspection should make no model call. Build on the existing SQLite,
   view and controller APIs; a dashboard or new storage engine is unnecessary.
4. **Compare a compact AI grouping pass with deterministic groups.** Give it
   claim IDs, rule/closure family, implementation anchors and available caller
   relationships. Separate a local SQL construction batch from a shared
   authorization/workflow investigation. Require exact claim coverage and
   explicit reasons for compatibility; uncertain caller compatibility stays
   separate. Count planner time and check proposed groups before dispatch. This
   hypothesis remains untested; the present grouping was deterministic.
5. **Use a held-out mixed slice**, including real bound-query controls and
   dynamic-fragment exceptions, multiple protected callers and unavailable
   dependencies. Keep mechanisms, wrong dismissals, actionable uncertainty and
   time as the decision criteria. Larger useful inputs and modest outputs are
   acceptable. No full-app run before the workflow passes this review.

Proceed with a component when its specific deciding work is reused and supported
mechanisms survive. Dig deeper when a named missing contract can change the
decision, grouping compatibility is uncertain, or scope/severity diverges. Stop
that investigation when its decisive fact is unavailable under the actual lookup
capability; retain the precise gap and dependency record. Stop a component or
split a group when it transfers a verdict across incompatible callers, loses a
mechanism, or adds investigation without useful closure. **No token-percentage
threshold, shorter-output target or candidate-count reduction substitutes for
those decisions.**

Artifacts: `C:/dmitry/scan-runs/workspace-expanded-20261026-k` contains the frozen
matrix/source recipes, original `matrix-result.json`, repair manifests/results,
final per-arm `final-result.json`, `comparison-accounting.json`,
`artifact-audit.json`, and evaluator-only dependency receipt. Earlier failed
experiments and their unknown turn remain in their original ledgers; K does not
erase them or establish a comparison against the historical 104-candidate run.
