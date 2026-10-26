# Deterministic review work planner

`scripts/review_workspace_planner.py` proposes bounded investigations from native
inventory anchors, AST function units and source-bound direct registrations.
It makes no model call, emits no verdicts and performs no native admission.
Ordinary worker scheduling and native bundle defaults remain unchanged.

Two strategies are implemented:

- **Local SQL construction candidates:** the JavaScript/TypeScript database-query
  rules, with complete native function windows, independent source chains and
  separate claim decisions. A full function does not prove that an imported
  query builder, query text or driver contract is resolved. Safe and unsafe
  constructions can share a batch; the planner does not classify either.
- **Shared operations:** resource-access/authorization claims in the same native
  function unit, tied to one identical direct registration and callback chain.
  A registration anchor can join a handler anchor when its explicit relative
  import resolves to the same native declaration. This is scoped investigation,
  not proof of authorization, transparent wrapper behavior or exhaustive callers.

Defaults are at most four claims and 32 KiB of distinct implementation source
per group. Every selected claim appears once. A singleton records why grouping
was unavailable. No application-specific claim IDs or expected verdicts are used.

## Generate and inspect

```powershell
python scripts/review_workspace_planner.py `
  --scanner target/release/mehscan.exe `
  --source-root C:/authorized/application `
  --inventory C:/scan-runs/inventory `
  --review-ids ID1,ID2,ID3 `
  --output C:/scan-runs/work-plan.json
```

Select 1–32 inventory IDs. Output and its sibling query journal must be outside
the application and must not exist. Discovery allows 96 native query attempts
and 180 seconds; no provider is invoked. Native AST/reference receipts, actual
query/time counters, file hashes, caller frames and limitations are retained.
Zero-query selections do not fabricate a native journal. Content identities
and source/inventory/engine/planner-code bindings provide integrity/freshness checks, not
authentication of third-party grouping claims.

Add `--prepare-helpers` to select source for explicit references in an already
identified registration chain. Direct relative named/namespace imports resolve
through native symbols to bounded exported function/const declarations. This
includes arrow-function constants; their initializer semantics remain for review.
The selected handler itself is not duplicated as helper evidence. Call arguments,
wrapper syntax, import and registration source stay visible. No helper's name is
treated as evidence that it enforces authorization.

Selection considers at most twelve static references per work, retains at most
four helper declarations, eight windows and 8 KiB per target, and creates at most
sixteen targets. Native query caching shares definition lookup across groups;
the existing 96-attempt/180-second preparation ceiling still applies. Missing,
ambiguous, oversized, truncated, shadowed or explicitly reassigned references
produce visible limits, not new caller searches. Incompatible/unresolved callers
receive no automatic helper target. SQL work does not gain caller exploration.
There is no recursive inspection of helper dependencies or automatic dependency
contract retrieval. This small syntax recognizer does not prove runtime binding.

The generated plan stores helper selections, limits and source hashes. Applying
it includes [deciding evidence](review-workspace-evidence.md) in the same atomic
transaction as work preparation. A late helper failure rolls back grouping too.
The default without this flag remains grouping/source preparation only.

## Apply to a fresh experimental workspace

Initialize a native-bound workspace with the existing bridge (use the
`workspace-actions-v2` experiment profile for lookup continuations), then run:

```text
python scripts/review_workspace_bridge.py plan <the existing native binding flags> --plan C:/scan-runs/work-plan.json
```

Use the same scanner, source root, inventory, store, stream, claim receipt, work
package, skill/provider contract and directory flags used for `init`. Under the
native guard, the command checks coverage, current source hashes and the native
binding, saves the plan, and applies one replayable `prepare_work` transaction.

Application requires fresh unassigned state: no sessions, calls, questions,
propositions, lookups, deciding-evidence receipts or drafts. It preserves every claim/bundle identity and
supplies the members' initial evidence plus bounded implementation, registration
and import source. Contained snippets are removed from the focused view. No
verdict or caller applicability is inferred. Source capture consumes the existing
source allowance; planning discovery is preparation, not model-requested research.

Stale source, duplicate/missing claims, invalid frames, source-budget overruns or
context-view overflow roll back the whole transaction. Identical retries replay
the receipt; a different plan cannot replace active work. Model actions cannot
invoke preparation. The planner is part of new workspace runtime bindings, so
older workspaces cannot silently resume under changed controller code.

Use existing `prepare`/`review` operations with the resulting work IDs. Planning
grants no additional execution budget. A shared call cap is not evidence of
avoided reasoning when an unresolved group reaches that cap.

## Deliberate limits

The recognizer supports direct local or relative named/namespace imports,
single-line literal-path GET/POST/PUT/PATCH/DELETE registrations, static callback
chains and bounded unary wrapper syntax. Native AST units, current raw source
and import bindings establish the proposal; previews or matching names alone do
not establish a caller. Unrelated frontend names and unbound code examples do
not count as registrations of the selected function.

A route-shaped call does not prove its receiver is Express or its wrapper is
transparent. Those semantics remain review questions. Cross-file binding requires
a direct named function/const export; indirect export lists are not resolved.

Multiple known registrations, reference truncation, shadowing, bound alias
escapes, spread/conditional/multiline dispatch and unresolved re-exports cause
abstention where encountered. Default imports, dynamic/computed routing, JSX
and a general call graph are outside this implementation. The small lexical
recognizer is not a JavaScript parser/type checker. Unknown indirect callers
remain outside the recorded scope; one direct registration is not proof of all
application callers. Reviewers still establish applicability and protected effects.

Oversized generated-CRUD configurators stay separate. File-read, YAML and
credential rules have no grouping strategy here; a shared file/pipeline alone
does not merge them.

See the [offline check](experiments/review-workspace-planner-results.md). This
establishes planning/preparation behavior, not live reviewer quality or new
savings. Next live validation requires a frozen held-out mixed slice and
comparable allowances. Shared dependency evidence, operation mechanism records,
interactive inspection and an AI grouping pass remain separate work.
