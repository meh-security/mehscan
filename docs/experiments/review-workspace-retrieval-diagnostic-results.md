# Retrieval diagnostic AG: do not implement blanket expansion

The offline diagnostic covers **14 historical work items/arms, 49 already-paid
calls and 27 definition requests** across the two pinned applications. It makes
**zero new model calls**. Neither tested retrieval alternative justifies a broad
workflow change. A separate audit finds a concrete native comparison-harness
defect: the reviewer was shown more query units than the harness would accept.

Raw artifacts: `C:/dmitry/scan-runs/workspace-retrieval-diagnostic-20261027-ag`.
The first replay and the source-deduplicated/per-work-cached `v2` replay have
separate freezes and closures. Old AF/AC/Z/L2 inputs and closure receipts remain
unchanged. This is diagnostic development evidence, not a fresh quality trial.

## What was compared

AF Sol/Terra workspace and Sol native deletion; AC Sol/Terra checkout; Z Sol/Terra
HTML configuration; and all seven L2 grouped work items: SQL, basket PUT, wallet,
deluxe, code-fix/file/YAML, generated resources and password change.

Every work item starts with its actual first source packet. At each successful
definition request, alternatives can inspect that declaration and deterministically
selected source. Future requests, answers and evaluator judgments are scoring
data only. They do not choose branches, helpers or source windows.

- **Complete declaration:** replace the 120-line prefix with the unique full
  declaration when it fits 400 lines/16 KiB. Otherwise retain the saved result.
- **One-hop implementation:** add value-import source and up to four directly
  called same-file/named-relative-import functions in lexical call order. Include
  their import context, with eight windows/64 KiB per response; do not recursively
  traverse their calls. V2 deduplicates already-visible source before applying
  packet limits and caches outline metadata within each work item.

Selection uses the existing conservative JS masker and native AST declarations.
Package, member/dynamic and unresolved bindings are not expanded. This is not a
complete TypeScript scope or deployed-module resolver; relative `.js` → `.ts`
resolution is a source candidate. Coverage is therefore an optimistic visibility
bound, never a certified call graph or a forecast of model behavior.

All added metadata queries/source windows are counted. A later receipt is called
pre-covered only if its exact captured physical source was supplied earlier by
the changed retrieval. A whole lookup turn is pre-covered only if every request
in that turn meets that condition, including navigation/feedback requests.

## Results after deduplication and per-work caching

| Historical arm | Complete declaration: later receipts pre-covered | One-hop: later receipts pre-covered | One-hop: complete lookup turns pre-covered | Extra one-hop query units |
| --- | ---: | ---: | --- | ---: |
| AF Sol workspace | 2 | 5 | Turns 2 and 4 | 55 |
| AF Terra workspace | 1 | 3 | None | 38 |
| AF Sol native | 1 | 2 | None | 48 |
| Other eleven work items/arms | 0 | 0 | None | 9 |
| Total | 4 | 10 | Two historical Sol turns only | 150 |

Complete declarations add no lookup units under the existing symbol+source cost
model. They pre-cover **no complete lookup turn** in the saved paths. This is a
plausible retrieval usability improvement, not demonstrated review acceleration.
The four redundant receipts all concern Directus deletion declaration tails.

Even optimistically omitting pre-covered requests, one-hop Sol workspace uses
65 query units against the original 18, and Terra uses 55 against 22. These are
counterfactual work counts, not executed reviews under enlarged allowances.
The native replay's base count is the worker's 16 successful units, not the
harness's 22 charged units; the separate reconciliation below explains the gap.

**Higher query counts alone do not establish worse latency.** V2 executes 30
distinct read-only native outlines in 3.159 seconds, reads 104,452 whole-file
bytes and completes in 5.344 seconds. Native execution is cached across replays;
first-use metadata work remains charged per work item. This is diagnostic timing,
not the overhead of a deployed source/publication workflow. V1 costs another
4.454 seconds/36 commands and remains preserved. Cheap source input and fast
lookups could still be worthwhile if they remove actual deciding turns.

The stronger objections are selection and coverage:

- Every later-receipt benefit is confined to the known deletion chain. Other
  operations either use short definitions or pursue source/navigation/configuration
  questions this definition-triggered policy does not address.
- Generic lexical selection spends packet slots on pagination, sorting, collection
  activation and error helpers. In Sol's query builder it eventually supplies
  `joinFilterWithCases`, but stops before `applyFilter`; in `processAst` it leaves
  `validatePathPermissions` outside the packet. More earlier source does not
  establish the remaining permission mechanism.
- Two fully pre-covered historical turns do not mean two saved model calls. The
  reviewer may ask different questions, need additional interpretation or retain
  the same deployment unknown. No alternate model path was executed.

Do not implement blanket one-hop expansion, tune lexical selection to the AF
answer, or buy another AF run to obtain a favorable measurement. Keep complete
bounded declarations as a narrow optional candidate, without presenting it as
the solution to repeated investigations. Existing selective SQL/deluxe grouping
evidence remains independently useful.

## Correct the native failure interpretation

`native-budget-audit.json` reconciles AF's actual provider responses, worker trace,
feedback, outer budget and five usage receipts. It inspects only the provider's
structured final responses, not private reasoning or credentials.

| Point before provider response | Worker advertises | Outer harness actually has |
| --- | ---: | ---: |
| Turn 1 | 24 | 24 |
| Turn 2 | 20 | 20 |
| Turn 3, after rejected six-unit batch | 20 | 14 |
| Turn 4 | 14 | 8 |
| Turn 5 | 8 | 2 |

The final request is **six units**, which fits the advertised eight. The harness
rejects it because its separate ledger has only two left. It had charged the
earlier six-unit invalid batch, whereas the worker had executed none of that batch
and retained its old local remainder. The outer ceiling is enforced, but its
effective allowance is not communicated to the reviewer.

This is a harness visibility defect, not evidence that the model exceeded its
offered allowance. The earlier AF report's “oversized request” interpretation is
corrected. Five calls and all token/time measurements remain unchanged; native
still has no final decisions. No unused AF slot is reopened.

The narrow correction is to clamp the dispatched task's query allowance to the
smaller of the worker remainder and the outer frozen remainder. Preserve the
charge for the rejected batch, the existing correction limit and the paid-call
ceiling. Do not refund queries, execute a partial rejected batch, grant a repair
turn or change the underlying security-review contract. This applies to the
experimental comparison harness, not ordinary native defaults.

The new native/adapter integration regression fails before the correction with
offered allowances `[24, 24, 22]` instead of `[4, 2, 0]`, then passes after it.
It exercises a rejected directory-filter definition, two valid source reads and
final native admission with zero global query units left. The rejected definition
remains charged only in the outer ledger; neither it nor an added repair executes.
The complete batch suite passes **five tests in 183.267 seconds**, and the pilot
suite passes **ten in 38.545 seconds**, all using deterministic providers. The
separate targeted regression also passes; it is not an additional distinct test.
Logs, including preliminary fixture failures, remain in the raw directory.

## Correct the qualification diagnosis

The replay verifies that Sol creates `files-delete-check-effect-order` on **turn
six, in the same response as its decisions**. No earlier Sol packet contains that
proposition. Terra creates its related proposition on turn one and receives it
in subsequent packets.

Sol's inconsistency is real, but it does not demonstrate an earlier learned fact
being dropped by context replacement. Model packets already carry persisted
propositions. Another memory store, reminder or mandatory contract producer does
not follow from this observation.

The actual export boundary still merits a smaller correction: native blockers are
rendered from unresolved questions, and the exported bundle contains claim results;
conditions written only in proposition exclusions can remain outside that package.
Preserve explicitly linked reviewer interpretations as attributed review material.
Do not promote every exclusion to an unresolved blocker or change its verdict.

## Next implementation boundary

First finish and regress the measured harness allowance correction, with no paid
replay. Then address claim-package fidelity through the existing proposition,
applicability and question records. Reuse saved Sol/Terra artifacts to distinguish
same-response inconsistency from persisted-state loss and to define what a human
reviewer should see. Keep this a quality correction, not an efficiency claim.

For efficiency, return to the broader plan: selective shared investigations and
native batch fallback, independent verdicts, rule-specific closure and a small
representative package. Preserve the proven SQL/deluxe result. Require actual
compatible consumers before investing in a deeper permission contract; count its
producer cost and do not make that machinery a prerequisite for wider evaluation.
Do not expand into the main/reserve/full-app wave until the changed package and
execution boundaries are reviewable. No model run occurs in AG.
