# Persistent review workspace implementation plan

Status: the [fresh shared-policy regression](experiments/review-workspace-recovery-results.md)
is closed with **partial recovery**. In five paired claims/26 observed calls, both
arms retain three findings, one scoped negative and one actionable unknown. The
workspace now emits the conditional SDK finding, but does not read its authority
binding; native verifies it. Matching verdicts therefore do not pass the frozen
full source-quality gate. Workspace remains slower: 270.133 versus 237.113 active
seconds, despite twelve versus fourteen calls. No paid repair or unknown usage.

Next complete two independent tasks: make local mechanism versus required caller
applicability explicit in review state, and consolidate duplicate native validation
through an equivalent freshness/publication boundary. Do not add another generic
prompt patch or buy an unmodified SDK retry; test compatible/incompatible bindings
and stale-source/owner/paid-answer behavior offline first. The new run reproduces
the overhead: 107 state/work checks take 47.887 seconds. Greater budgets, generic
memory or a CLI do not resolve these measured gaps. Ordinary native review remains
the operational reference; no broader workspace acceptance is claimed.

The [broader comparison's failed safety gate](experiments/review-workspace-batch-results.md)
also remains closed: five native versus four workspace findings across eight paired
claims/62 calls. Its omitted API-policy paragraph is restored from the same bound
source and now tested live, with the limits above. The sixteen prepared main claims
and eight reserved claims remain unreviewed. A genuinely changed mixed package
needs a fresh freeze after the quality/execution tasks, not either closed study's
unused allowance. Do not run a full application.

### Next implementation milestones and stopping rules

**A. Preserve closure scope, not just a final label.** Inspect the existing claim,
question and proposition-applicability records in `review_workspace.py`, their
provider rendering in `review_workspace_bridge.py`, and final decision conversion
in `review_workspace_actions.py`. Reuse those records before adding another state
subsystem. A completed local contract must remain distinguishable from its
application authority binding; show the exact remaining relationship without a
running checklist or requiring all callers. Keep reviewer interpretations distinct
from controller-validated source/binding receipts. The controller cannot certify
semantic correctness merely because a question was marked answered.

Verify source-bound packet/state behavior with compatible and incompatible callers
of the same implementation, missing registry binding, custom/unknown dependency
contracts, and a complete local SQL control that needs no wider caller discovery.
Preserve independent verdicts and actual source assumptions. Fake-provider tests
prove persistence and enforcement only; the next live check must contain diverse
boundary cases before any quality-recovery claim. Stop this implementation if it
only adds bookkeeping, universally requires caller discovery, or merely changes the
previous SDK wording. Do not repeat the unchanged SDK case as another policy trial.

**B. Consolidate validation at an equivalent publication boundary.** Use the saved
R/S native traces as the baseline. Follow `guarded`, `prepare`, `review`, `check`
and `_lookup` through source capture and receipt persistence. Specify which fresh
state/source/runtime/owner check protects each externally visible publication and
paid dispatch before removing a call. Keep paid usage and actual query spending
durable even when a stale answer or receipt is rejected. Avoid a cross-turn cache
or an unrelated SQLite redesign.

Adversarial tests must change source during inference and lookup/capture, supersede
owner/generation, alter provider/skill/packet bindings, and exercise incomplete paid
usage plus replay. Stale source/answers must not become usable by another model
turn or native finalization. Then measure actual native-check counts and elapsed
time on identical offline fixtures/source roots. Stop or revert an optimization
that only hides checks, loses costs, weakens rejection, or does not reduce the
measured overhead. Neither task authorizes paid repairs of R/S. Refreeze the still
unreviewed mixed package only after these milestones have reviewable evidence.

The [cross-app work-formation diagnostic](experiments/review-work-formation-results.md)
is complete: eight operations/twelve claims outside workspace tuning, three AI
calls and source-adjudicated operation/dependency proposals. Useful relationships
extend beyond the deterministic path, but six proposed research containers are
not six verified operation groups or demonstrated savings. It led to the
roughly 24-claim native-default versus batch-first workspace package comparison,
with eight reserved confirmation claims. That attempted package's safety wave and
the subsequent targeted recovery are now closed as above. A separate AI planner
remains optional.

The [breadth reassessment](experiments/review-workspace-breadth-reassessment.md)
governs that wider validation; dependency contracts and a
richer state interface are not prerequisites. A new zero-model-call structural
audit groups 11 of 116 saved Juice Shop candidates and none of 138 Directus
candidates. This exposes narrow work-formation coverage and the need to compare
fallback with native 20-review batching. Its operation diagnostic and initial
package safety comparison have now run, followed by targeted policy recovery.
The mixed main wave and full-app review have not run.

The [fresh fixed-controller confirmation](experiments/review-workspace-confirmation-results.md)
remains the clean manual-grouping result: 31 singleton versus 21 grouped calls,
612 versus 439 seconds active execution, matching twelve claim verdicts and zero
controller errors/unknown usage. SQL/deluxe provide an uncapped five-call benefit;
the other five-call difference is basket review reaching its shared cap. Both
packages leave three relationships unresolved and retain payment bypass as an
unvalidated lead rather than a classified finding. This supports a selective
optimization, not whole-app acceptance. Token-percentage gates are retired.

The earlier [expanded four-arm comparison](experiments/review-workspace-expanded-results.md)
remains development evidence: 121 calls and 48 source-validated dispositions,
including controller repairs. The confirmation used fresh state and the same
complete source profiles. It adds a clean result without erasing earlier costs.

Implementation update: the [deterministic planner](review-workspace-planner.md)
now recognizes local SQL batches and source-bound same-operation groups, and
applies them atomically to fresh experimental state. The [offline check](experiments/review-workspace-planner-results.md)
recovers eight work items for all twelve existing claims with zero model calls.
Adversarial native-source tests cover incompatible callers, aliases, shadowing,
truncation and rollback. This is planning/preparation evidence; live validation
on a held-out mixed slice, shared dependency evidence and independent operation
mechanism records remain outstanding. No new savings result or ordinary-worker
integration is claimed.

Shared-evidence update: [question-linked source/dependency preparation](review-workspace-evidence.md)
now supplies existing helper source and bounded local metadata observations
before dispatch, with atomic persistence, separate consumer questions and stale
absence rejection. The [offline check](experiments/review-workspace-evidence-results.md)
stores one helper definition and one dependency observation for three consumer
contexts, with no model calls. Automatic relevance selection, dependency effect
contracts and live savings from this delivery path remain unproven.

Red flag clarified: missing root lockfiles or an installed package manifest do
not prove that dependency source is unavailable everywhere, and a declared range
does not establish deployed behavior. Reuse the bounded observation; pursue a
concrete alternate source/version relationship when available, otherwise retain
the exact unresolved effect. Do not substitute an absence receipt for a contract
or transfer an ownership verdict between callers.

Automatic helper selection is now [implemented and checked offline](experiments/review-workspace-auto-evidence-results.md)
through the planner's opt-in `--prepare-helpers` path. Explicit registration
references supply native definition/import/call-site source; grouping and
delivery commit atomically. This removes manual helper-target preparation for
supported bindings. It adds source and packet bytes and has no new live savings
result. Do not repeat the closed helper-only memory test to demonstrate a benefit
it previously failed to show. The subsequent breadth audit corrects the proposed
dependency/operation-record prerequisite: validate generalization now, while
tracking those specific quality gaps independently.

The earlier [pilot](experiments/review-workspace-pilot-results.md) and [first notebook producer](experiments/review-workspace-notebook-results.md) remain failed/incomplete experiments. Receipt preservation, route-source preparation and controller rendering of outstanding checks were subsequently verified. Their paid costs and the older unknown provider turn remain in the accounting; the successful local producer does not erase them.

The earlier two-consumer result showed that avoiding a helper read can fail to
remove a deciding turn. The expanded result now shows useful targeted reuse on
a wider eligible subset, while larger operation regions alone did not improve
overall review. Prefer concrete shared investigations and deciding facts over a
general memory index or mandatory delivery. Do not reject useful context merely
because its input grows, or score fewer native queries as a completed review.

This preserves the ten-step plan from the preceding discussion, with project-specific integration details and explicit corrections where the original wording could lead to an unsafe or expensive implementation. Section 11 explains those corrections and their reasons.

The objective is a **persistent review workspace with bounded model contexts**, rule-specific investigation strategies, and reusable source-backed knowledge. A conversation is a temporary investigation context; the workspace retains the evidence, questions, applicability judgments and independent native claim decisions.

“Stop, skip/defer, or dig deeper” applies both to individual investigations and to investment in each experimental approach.

## 0. Execution correction after the first live pilot

The architecture below remains the target. This section preserves the historical
pilot correction; its listed smoke/producer/consumer sequence is completed or
closed, not the active next-work queue. The [breadth reassessment](experiments/review-workspace-breadth-reassessment.md)
now governs execution. Confirmation is complete. Work formation, fallback and
cross-app package evaluation take priority over more helper/dependency/CLI
infrastructure. Independent operation records remain a visible quality gap. The
[earlier diagnostic and reuse plan](experiments/review-workspace-next-plan.md)
remains the historical record of the closed smoke/producer/consumer phases;
its small-sample stop decision and percentage gates do not govern this expansion.

The pilot established integration, one source-validated workspace decision and
effective stopping on unknown usage. It did not establish live knowledge reuse,
grouping value, or cost reduction. The corrected search answer saved no
proposition; the next claim used another implementation; the attempt ended
before the shared identity-helper cases. A state store and a literal-text
knowledge API are implemented, but automatic relevant-fact delivery is not.

The next steps are ordered by the question they answer:

1. Fix loss of distinct navigation receipts under one question; verify context
   preservation, interrupted-call accounting and accidental-restart protection.
2. One fresh replay of the saved post-lookup login task, with unchanged review
   semantics, to check bounded completion and usage reporting. This is a smoke
   test, not a diagnosis of the previous latency.
3. Run the wallet fact producer once. Compare deluxe and basket consumers with
   its bounded notebook supplied versus absent. Reuse existing focus/state APIs;
   defer a general retrieval index. Charge producer cost to both comparison
   alternatives while reporting actual experimental spend separately.
4. A separately budgeted SQL construction batch versus singleton comparison,
   once the action path completes reliably. It need not wait for a singleton
   package to reach 30% savings: grouping is itself a savings hypothesis.
5. A complete mixed development slice and then reserved held-out evaluation
   before considering a full application run.

Do not change the model, effort, source preparation, schema, session policy and
grouping together in the next diagnostic. Do not simplify away a legitimate
deciding question to obtain a fast verdict. Keep optional AI grouping and rich
CLI work behind evidence that deterministic work formation/reuse is useful.

## 1. Freeze the scope and comparison

The first implementation targets one frozen application snapshot, one configured capable model, independent claim verdicts, and evidence reuse across conversations.

Retain the existing native inventory, source validation, bundle finalizer, report importer and state journal. Preserve the currently uncommitted exported-helper lookup and inherited-prompt changes as identifiable supporting changes. Their presence is not evidence of workspace savings.

Before live runs, save an experiment manifest containing:

- Source, executable, skill, controller and adapter hashes.
- Exact selected claim IDs, properties and source anchors.
- Model, effort, concurrency and aggregate budgets.
- Initial evidence policy and any preparation costs.
- Strategy, grouping and knowledge-reuse assignments.
- Evaluator-only supported mechanisms, clean controls and unresolved relationships.
- Actual saved baseline usage for those IDs and provenance of the source audit.
- Maximum additional calls, tokens or spend, elapsed time, and permitted repeats for the experiment.

Use the saved Juice Shop treatment as the historical comparison. Run matched fresh controls for causal comparisons because package changes prevent attributing historical differences to a single component. Saved source-audit labels are provisional evaluator judgments, not independent ground truth.

Native bundle defaults remain 20 reviews. Singleton settings belong to the experiments; they are not a historical product default. Older skills that encouraged unsupported dismissals are not an acceptable efficiency target.

Relevant saved artifacts, outside the repository:

- `C:/dmitry/scan-runs/single-model-juice-full-gate-20261025/final-results.json`
- `C:/dmitry/scan-runs/single-model-juice-full-gate-20261025/input-amplification-audit.json`
- `C:/dmitry/scan-runs/single-model-juice-full-gate-20261025/source-audit.json`
- `C:/dmitry/scan-runs/security-operation-shared-gate-20261024-v2/frozen-design.json`
- `C:/dmitry/scan-runs/security-operation-shared-gate-20261024-v2/results.json`

The earlier shared-operation test required operation assessment before local verdicts and increased the allowed sequential research rounds with group size. It did not isolate bounded category batches, workspace memory or context replacement.

**Stop:** no live experiment until inputs, aggregate cost ceiling and evaluation criteria are frozen. No full-app run during development.

## 2. Implement the workspace state

Add a workspace layer alongside the current worker. Reuse native decision admission rather than creating another authority for verdicts.

Suggested implementation boundaries are provisional; avoid splitting modules solely to match this table.

| Component | Responsibility and existing integration |
| --- | --- |
| `scripts/review_workspace.py` | Persist working state and validated action updates; use the current worker's locking/checkpoint conventions |
| `scripts/review_knowledge.py` | Retrieve propositions, record dependencies and mark invalidated interpretations |
| `scripts/review_strategies.py` | Select strategies and form bounded work items |
| `scripts/review_context.py` | Assemble bounded views using current source-window and trusted-guidance facilities |
| `scripts/review_worker.py` | Scheduling, evidence broker, lookup execution, usage, native finalization and recovery |
| `scripts/review_orchestration.py` | Reuse or adapt scoped dependency knowledge and aggregate budgets |
| `skills/mehscan-security/scripts/codex_protocol.py` | Versioned model action schema and prompts |
| `skills/mehscan-security/scripts/codex_reviewer.py` | Explicit session lifecycle and provider usage |
| Initial CLI entry point | Operate the same workspace API as the model; begin as a Python controller interface |
| `crates/cli/src/review_state.rs`, `review_completion.rs` and native finalization | Continue to own native plan, admission, completion and immutable decision history |

The workspace needs six record types:

| Record | Required contents |
| --- | --- |
| Claim | Native ID, exact property, anchor, working assessment state and native decision reference |
| Evidence | Snapshot, path/range or lookup identity, bytes/hash, completeness and original attribution |
| Proposition | Statement, scope, conditions, exclusions, evidence references, provenance, revision and status |
| Applicability | Proposition revision, affected claim, caller-specific evidence and unresolved conditions |
| Question | Deciding missing fact, affected claims, attempts, returned evidence and current obstacle |
| Work item | Strategy, claim membership, dependencies, active questions and aggregate-budget identity |

Keep the distinctions explicit:

- Retrieved source is evidence; retrieval does not prove that the model inspected or understood it.
- A proposition is a reviewer interpretation, never trusted instruction material or a certified scanner fact.
- Applicability is a separate judgment.
- A verdict belongs to an exact native claim.
- Source receipt does not automatically answer a question.
- Working drafts and reconsideration flags do not replace admitted native decisions.

Use transactional updates, stable identifiers and idempotent operation keys. Retain previous proposition revisions and action receipts. Record which exact proposition revision each draft or decision relied upon. Start with one writer per workspace, consistent with the existing controller ownership model, before attempting concurrent mutations.

Bind working state to the native snapshot, plan/runtime and selection. A changed source snapshot creates a new workspace. Recovery under the same binding preserves accumulated usage and completed work. A changed executable, skill or protocol follows the existing native rebind/replan requirements; it cannot silently resume an old provider session.

**Validation:** interrupted update recovery, duplicate action replay, stale source/runtime rejection, concurrent mutation rejection, conflicting propositions and dependency tracking. Extend `tests/review_worker/` and the existing native state tests only where native behavior changes.

**Early feasibility gate:** demonstrate one source-backed proposition being reused in a fresh model context through a minimal vertical slice before completing a general workspace, rich CLI or additional strategies. This is an ordering refinement to avoid building an entire platform before testing the cost hypothesis.

**Stop:** defer advanced retrieval and broad live review until recovery and provenance work.

## 3. Expose an interactive CLI and structured action API

The operator CLI and model interface call the same underlying operations. Initial command names are illustrative, not supported Mehscan subcommands:

```text
review workspace open
review queue
review show <work-item>
review next --strategy sql
review evidence <evidence-id>
review knowledge --symbol <symbol>
review question <question-id>
review split <work-item> --claims <ids>
review status
```

Start with a script interface under `scripts/`. Promote commands into `mehscan` only after the workflow is useful and command ownership is decided. A terminal UI is optional.

Model responses express bounded updates:

- Request targeted lookups.
- Add or revise a proposition.
- Record applicability.
- Submit decisions for some claims.
- Split remaining claims into another work item.
- Defer a question with its precise obstacle.

Replace full progress-inventory rewrites with these updates. Preserve semantic explanations in propositions, applicability, decisions and unresolved questions. Validate action schemas, references, current bindings and available evidence in trusted controller code. Repository content and saved model notes remain evidence rather than instructions.

Allow partial completion within a work item. Completed claims leave the active view immediately, but their dependencies remain recorded.

**Native finalization integration:** the present finalizer requires a complete response for every ID in a bound bundle. Partial workspace decisions therefore remain drafts. The controller assembles and validates a complete draft for the original bundle before native admission. Each claim retains its own source evidence, diagnosis and attribution. Do not describe a partial draft as admitted, mutate an existing bundle's membership, or assume `--allow-partial` permits incomplete present responses. If independent admission is later necessary, design separately bound exact-ID bundles and verify coverage/journal handling explicitly.

**Validation:** a mixed work item resolves two claims, continues a third and defers a fourth; restart preserves each state, and eventual complete-bundle admission happens once without omitted or duplicated claims.

**Stop:** if the action contract still requires repeatedly restating application-owned state, simplify it before expanding.

## 4. Build bounded context assembly

Each context contains:

1. A short common contract.
2. Selected strategy guidance.
3. Active claims and exact properties.
4. Relevant propositions and decisive supporting evidence.
5. Caller-specific differences.
6. Open deciding questions and lookup operations.

Full source, lookup history and abandoned exploration remain available in the workspace without automatic replay. Reuse native source handles and preserve original query attribution.

Continue a short session for tightly dependent lookups. Start a fresh context when a batch finishes, work splits into a different question, history substantially exceeds relevant working evidence, or persisted state can reconstruct the next work item. Freeze the triggering policy and context size limits before the experiment.

Implementation gap: `workspace-actions-v1` currently starts a fresh provider
conversation for every turn, including dependent lookups. That is an
experimental restriction, not validation of this planned session policy. Keep
it fixed in the next diagnostic/reuse comparison; evaluate bounded continuation
separately if repeated setup remains material. Do not add continuation as an
unmeasured repair during a knowledge experiment.

Context replacement is explicit and recorded. Save a checkpoint listing active claims, unresolved questions, proposition revisions, evidence handles, parent session and remaining aggregate allowance. Allocate a new provider conversation identity and immutable packet. Preserve the existing packet/schema binding and monotonic continuation checks within each session.

Session replacement, splitting and recovery never replenish work-item or run budgets. Record unknown provider usage after interrupted calls rather than treating it as zero. No exactly-once remote execution guarantee is implied.

Do not add a separate summarizer model. Useful propositions are normal review outputs. Include them in a dedicated evidence section, not trusted guidance. Compare compact propositions with small decisive excerpts; expand source when required. The existing `review-facts` command embeds all cited excerpts, so placing its current output into every fresh packet is not by itself a compact-memory implementation.

**Validation:** a fresh context preserves decisive evidence, uncertainty and claim boundaries; it cannot cite hidden/unavailable artifacts, reset its allowance or bypass stale-session checks. Extend `tests/review_worker/test_context.py` and `tests/provider_adapter/test_codex.py`.

**Dig deeper:** if context replacement changes judgments materially, inspect lost or misleading state before increasing context or adding instructions.

## 5. Implement two review strategies first

Start with SQL construction and authorization. They exercise different closure requirements.

| Strategy | Initial view | Reusable knowledge | Reason to split |
| --- | --- | --- | --- |
| SQL construction | Actual API/import, complete query expression, bound operands and dynamic grammar | Wrapper behavior, parameter-binding contracts and fixed mappings | Unresolved wrapper, dynamic fragment, different interpreter or exposure question |
| Authorization | Actor, entry point, guard, selected object and protected effect | Middleware behavior and shared policy implementation | Different actor/object binding, route order, bypass branch or effect |

SQL may use small batches across files when API and construction questions are comparable. Category is a scheduling aid, not evidence of equivalent behavior. A complete bound-value construction can close its injection property without certifying ownership or the enclosing operation. Use the existing [SQL guide](../skills/mehscan-security/references/categories/sql-query.md).

Authorization reuses implementation behavior while requiring the relevant caller's check-to-effect relationship. Use existing [authorization guidance](../skills/mehscan-security/references/buckets/authorization.md).

Strategies select questions and evidence needs; they must not become a new expanding list of mandatory checks for every claim. Adapt the generic agenda in `scripts/review_orchestration.py` so local construction claims are not automatically forced through operation-wide obligations. Keep detailed guidance available through the existing catalog.

Batch size follows estimated working context and question complexity, not only count. Start small, record splits, and remove settled claims from later views. Do not multiply sequential research rounds by member count. Budget shared dependencies and exceptions within one aggregate experiment allowance.

Add credential/workflow and HTML strategies only after the first two demonstrate useful behavior.

**Stop:** narrow closure criteria if a strategy repeatedly expands local claims into operation-wide investigations.

## 6. Make knowledge reuse operational

Adapt the existing source-bound notes in `crates/cli/src/review_facts.rs`, dependency register in `scripts/review_orchestration.py`, and broker in `scripts/review_worker.py`. Their current schemas and retrieval behavior are foundations, not a complete memory API.

Retrieve propositions using exact implementation/declaration identity, known imported API or receiver identity, source artifacts, strategy/property and explicit claim/question links. An observed symbol name alone is insufficient. Begin with deterministic retrieval; consider semantic retrieval only after measuring missed useful propositions.

Current implementation exposes optional literal-text knowledge lookup and
explicit work-item focus. It does not yet select relevant saved propositions
automatically for each fresh work item. The next reuse slice uses bounded
delivery through the existing focus API; it tests useful consumption before
investing in a general dependency-to-proposition index. After that gate, add
deterministic selection with misses and exclusions. A model being able to ask
for knowledge is not sufficient evidence that the application remembers it usefully.

A retrieved proposition carries scope, conditions, exclusions, provenance and a small decisive excerpt. Consumers establish remaining applicability conditions instead of reconstructing the original investigation.

For example, a proposition that middleware replaces `body.UserId` with the authenticated subject may be reused. Each consumer still establishes middleware order and whether the protected effect uses that body field rather than an unconstrained route ID.

Reopen a proposition when contradictory evidence appears, its scope was overstated, binding differs, or evidence is incomplete for the asserted behavior. Retain both interpretations where necessary. Mark dependent drafts and decisions for reconsideration; do not automatically invert a verdict or rewrite immutable native history. Fresh decisions use existing explicit supersession requirements. Workspace status must visibly report reconsideration even while the old native decision remains in history.

Persist unsuccessful lookup scope, limits and attempts to prevent identical fruitless exploration. Absence from a limited result does not establish absence of a control. Store attempted scope and material changes in strategy, rather than relying on exact wording of a model's question as the sole reuse identity.

**Validation:** reuse one helper between a protected caller and an unsafe caller; preserve different verdicts. Dispute a proposition and identify every recorded consumer, including consumers from retired contexts.

**Stop:** a wrong dismissal caused by transferred applicability blocks expansion until corrected and retested.

## 7. Add lightweight AI grouping as an optional planner

Implement after deterministic work formation and knowledge reuse are usable.

Supply a compact claim index and short excerpts: exact question, anchor, enclosing declaration, API/receiver identity where available and known relationships. The planner proposes strategy, group membership, shared dependencies, important differences and separate cases.

It cannot remove, dismiss or finalize claims. Membership is provisional and can change after inspection. A claim may have distinct property-specific work, but native coverage and decisions remain keyed to exact claim IDs; avoid duplicate admission.

Compare deterministic grouping with AI-assisted grouping using the same reviewer and workspace. Include planner tokens/time and all splits or regrouping overhead. Do not pass evaluator labels or previous verdicts as planner hints.

**Stop:** remove the planner if its cost exceeds downstream savings or it repeatedly creates groups the reviewer must split. AI planning is optional.

## 8. Define investigation stopping rules

| Situation | Action | Required record |
| --- | --- | --- |
| Complete evidence establishes the selected property | Stop and decide | Decisive evidence and scoped reasoning |
| A supported weakness is established with explicit conditions | Stop that claim | Mechanism, effect and conditions |
| One known local fact could change the verdict | Dig deeper | Deciding question and targeted lookup |
| Several claims need the same implementation fact | Investigate once | Shared question and affected claims |
| Retrieved proposition applies and caller conditions are established | Reuse and decide | Proposition revision and applicability evidence |
| Lookup repeats without new scope or evidence | Change approach or defer | Attempt history and remaining obstacle |
| Required deployment, dependency or human-policy fact is unavailable | Defer as `needs_review` | Exact missing fact and why available source cannot settle it |
| Budget expires with decisive evidence unread | Defer as `needs_review` | Unread relationship and exhausted limit |
| Inspected source exposes an adjacent concern outside this claim | Record a separate lead | Source and distinct question |
| Scope policy defers a claim | Skip transparently | Native plan deferral reason; no verdict |

A lookup is justified when possible answers can change verdict, conditions, assessed severity or applicability. “Understand more of the application” is insufficient. Track requested fact, returned evidence, remaining question and resulting decision or deferral.

A failed lookup does not immediately end investigation. Try a materially different concrete navigation route when one exists. Avoid a universal attempt count: judge progress by new evidence and the remaining plausible route, within the aggregate ceiling.

Deferral inside a selected investigation uses `needs_review`; omission from the selected scope follows native plan policy. Comprehensive selection does not gain new deferral permissions from this workspace. Keep source-only leads and changed-path obligations visible using existing mechanisms.

## 9. Evaluate in stages

The diagnostic and three-claim reuse phases in section 0 are historical. Follow
the [current breadth plan](experiments/review-workspace-breadth-reassessment.md):
first assess six to eight diverse operations, then freeze approximately 24 real
claims across at least two pinned applications and eight reserved confirmation
claims. Include simple
SQL positives and clean constructions, shared wrappers with different arguments,
authorization positives and clean ownership controls, a complex
registration/credential mechanism, unresolved questions, useful shared facts,
and incompatible callers designed to catch unsafe reuse.

Select from saved baselines where available. If Juice Shop lacks a needed clean construction or genuinely shared SQL wrapper, include an explicitly pinned second corpus and its baseline; do not silently replace production claims with easy synthetic examples. Keep small fixtures for deterministic state and correctness tests separate from evidence of live review savings.

| Stage | Comparison | What it establishes |
| --- | --- | --- |
| A | Current workflow vs workspace with singleton work items | Combined state/context-contract effect |
| B | Workspace singleton vs rule-specific batches | Strategy/batching effect |
| C | Reuse disabled vs enabled on a dependent subset | Learned-knowledge effect |
| D | Deterministic vs AI-assisted grouping | Planner net value |
| E | Combined workflow on a held-out slice | Generalization beyond development cases |

Stage A combines changes and cannot establish the contribution of each. Match category guidance and prepared evidence where possible; add a narrow ablation only when attribution affects the next implementation decision. Do not run a full factorial experiment.

These stages identify questions, not an unconditional sequence or a full
factorial. Execution reliability and the narrow grouping comparison have been
tested. The new coverage failure justifies a small compact-AI versus deterministic
work-formation diagnostic now. The main wider comparison includes the current
native workflow's 20-review default; singleton experiments are not a substitute
for that baseline. Dependency contracts and an interactive CLI do not gate the
generalization test. Full-app expansion still waits for broader package quality
and reserved confirmation. Closed experiment allowances remain closed.

Start with a small feasibility subset after the state/action/context vertical slice, before completing all strategies or the CLI. Stop losing variants early. Repeat only promising or ambiguous results within the frozen experiment ceiling. Reserve held-out cases before tuning and do not repeatedly tune against them.

Measure:

- Supported mechanisms retained, wrong dismissals, unsupported findings and actionable uncertainty.
- Actual total input, cached input, output, model time and wall time.
- Source delivered repeatedly, both across contexts and through continuation replay where observable.
- Repeated investigation of established propositions, with trace-based evaluator assessment.
- Lookup usefulness, remaining deciding questions and unjustified repeated attempts.
- Planner, preparation, context replacement, recovery and protocol-repair overhead.

Use provider counters for tokens; bytes and source-line counts are separate measurements. Interpret “useful lookup” from its contribution to a deciding question, not solely the model's self-report. Closing a question without changing its verdict can still be useful.

Adjudicate disagreements from source. Do not grade solely on matching old verdicts, candidate count or response length. Keep all selected IDs and limits accounted for, including missing provider usage.

## 10. Decide whether to continue investing

The old percentage input gates are retired. Use these criteria, with operational
limits frozen before running; they are not achieved savings or statistical guarantees:

- **Immediate block:** wrong dismissal, unsafe applicability transfer, lost
  supported mechanism or unknown usage. Stop affected paid expansion, preserve
  costs and diagnose. A mechanism retained only as an unvalidated lead has not
  passed a required classified-finding check.
- **Promising:** supported mechanisms and actionable uncertainty survive, with
  useful reductions in deciding work, repetition or total time across more than
  one favorable family, including preparation/planner costs. Confirm on reserved
  cases before expanding.
- **Ambiguous:** benefits are confined to known SQL/duplicate-observation cases,
  are offset by fallback/planning overhead, or coincide with different caps.
  Report by family and test one concrete cause; do not claim broad efficiency.
- **Insufficient:** no useful sharing beyond development cases, singleton
  fallback worsens the package, or a targeted correction repeats quality
  regressions. Narrow or stop that variant rather than add procedural prompts.

Match concurrency and aggregate investigation allowances. Identify censored
cap-affected outcomes separately. Measure actual input/output/cached input and
absolute time/cost without treating a larger useful input as failure. Small
samples do not establish whole-app recall or precision.

No full-app rerun until the combined workflow passes the pilot and a held-out slice. Context resets, new work items and planner retries share the same frozen allowance. An experiment reaching its ceiling ends with evidence, partial results and a reason; it does not silently extend itself.

The first milestone remains: **resolve a mixed batch, persist a useful proposition, reuse it in a fresh conversation for another caller, split an exception, and resume after interruption while retaining independent native decisions and complete usage accounting.** A small live feasibility gate exercises the reuse portion before the full milestone is built.

When implementation is ready for packaged validation, update `scripts/release-files.json` for added runtime modules and the worker/adapter protocol bindings and documentation. Keep this proposal separate from claims of released behavior in [review-worker.md](review-worker.md), [review-state.md](review-state.md) and [codex-reviewer.md](codex-reviewer.md).

## 11. Review corrections and red flags

The architecture and original ten stages are retained. The following are concrete risks in the original wording, not reasons to abandon its direction.

| Red flag | Why it matters in Mehscan | Plan correction |
| --- | --- | --- |
| Partial completion sounds equivalent to partial native admission | The finalizer requires every ID in a present bundle response. Report `--allow-partial` skips missing response files, not missing results inside one | Keep partial decisions as workspace drafts, then assemble a complete original-bundle response before admission |
| Context replacement sounds like changing an existing session's packet | `codex_reviewer.py` pins packet, schema and provider binding and rejects stale/incompatible continuations | Allocate a new explicit session identity with a checkpoint; retain immutable bindings within sessions |
| Session resets and splits have no explicit budget inheritance | A fresh conversation could regain per-session allowances and erase apparent savings or hide repeated work | Keep work-item/run budget identity and usage across all contexts, retries and splits |
| Existing saved facts are assumed to provide compact memory | `review_facts.rs` embeds every cited excerpt; broker caching saves native execution but still delivers evidence to each consumer | Retrieve compact scoped propositions with bounded decisive source and expandable provenance; measure model input separately |
| Reconsideration sounds like changing a historical verdict | Native decisions are immutable, and supersession is explicit | Record workspace reconsideration/dependency state; admit fresh decisions through native supersession |
| The full workspace could be built before testing its central hypothesis | The problem is excessive review cost; a large state/CLI project could fail to reduce model input | Insert a minimal fresh-context reuse experiment before completing the general interface and strategy set |
| Stage A could be presented as isolated proof of state savings | State, action contract, guidance and context assembly change together | Label it a combined package comparison; use targeted ablations only when needed |
| A Python CLI sketch could be mistaken for supported native commands | Mehscan has a Rust CLI, packaged controller scripts, trusted runtime bindings and a release allowlist | Begin with a controller script, label commands illustrative, and integrate native commands/packaging deliberately |
| Singleton savings become a prerequisite for testing grouping | This can block the very mechanism expected to reduce duplicated investigations, even though the singleton trial never reached related claims | Require reliable bounded execution before a small grouping diagnostic; retain mixed and held-out gates before expansion |
| “Knowledge enabled” means memory was tested | Optional literal lookup and an empty fact store do not deliver a shared fact to a consumer | Order a producer before compatible/incompatible consumers, record delivered proposition revisions and measure avoided work |
| A timeout is interpreted as model investigation failure | No completed usage or response exists for the stalled turn; elapsed time alone does not identify reasoning, schema or provider cause | Separate execution diagnostics from semantic closure and memory experiments |
| Only the last lookup per question is presented | Multiple navigation answers can be stored but disappear from the next fresh context before the reviewer sees them | Preserve the complete newly returned batch and distinct unresolved facts within the context bound |
| A retrieval index is required before testing a three-claim notebook | This adds product machinery before demonstrating that consumers benefit from a supplied scoped fact | Use existing bounded focus/proposition delivery first; generalize retrieval after useful reuse |
| Avoided helper lookup is equated with avoided model work | The live notebook removed definition requests, but unique handler/effect reads still required the same turns and input increased | Select reuse/grouping by the deciding-work dependency and measure complete input/output/time, not query count |
| Dependency contracts or operation-record implementation gate every wider test | This defers external validation while repeatedly improving infrastructure on twelve development cases | Run work-formation/fallback and cross-app tests now; keep those quality gaps explicit |
| Singleton comparisons stand in for native defaults | Native bundles default to 20 reviews; experimental singleton fallback can itself recreate excessive conversations | Include the current native workflow and measure the unsupported population |
| Multiline callback support is assumed to create groups | Directus often has one marker per route; useful reuse may instead concern a service contract across distinct caller policies | Audit actual shared deciding work before extending syntax or choosing AI grouping |

Two operational safeguards are also explicit: saved model interpretations remain untrusted evidence rather than instructions, and scope deferral remains subject to native Value/Comprehensive plan policy.
