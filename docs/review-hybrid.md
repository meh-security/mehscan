# Experimental mixed review dispatcher

`scripts/review_hybrid.py` executes a prepared
[routing proposal](review-routing.md). Native fragments use the ordinary worker
and its continuation/research contract. Workspace investigations use existing
questions, scoped propositions, caller applicability and partial drafts. Both
paths draw from one persistent outer ledger. This is an opt-in experimental
controller, separate from the ordinary review default.

## Prepare a fresh comparison

Use the existing comparison design/provider inputs, with both `batch_mode` and
`hybrid_mode` true. Retain the original maximum-20 native manifests. The routing
proposal, inventory and manifest must match the design's selected source/claims.
Preparation creates fresh native ownership and workspace state; it imports no
old verdict or paid session. Provider preflight performs no inference.

```powershell
python scripts/review_hybrid.py prepare `
  --design C:/scan-runs/hybrid-design.json `
  --output C:/scan-runs/hybrid-comparison `
  --private C:/scan-private/hybrid-comparison `
  --scanner C:/trusted/mehscan.exe `
  --provider-config C:/private/provider.json `
  --provider-executable C:/trusted/codex.exe `
  --routing C:/scan-runs/routes/routing.json `
  --routing-inventory C:/scan-runs/inventory/inventory.json `
  --routing-manifest C:/scan-runs/bundles/manifest.json
```

Supply the original `--planner-plan` and `--selections` files when the route
proposal uses them. Preparation validates those inputs before creating native
state, then verifies that fresh inventory/bundle generation reproduces the
proposal's bindings. It creates bounded native subset bundles/work packages and
prepares workspace work items atomically. Native fragments inherit any explicit
source target of their original bundle, preserving its source windows with the
fragment's exact IDs. Workspace work receives initial source and the selection's
additional bounded evidence/questions. These preparation costs/source differences
belong in the experiment's readiness and accounting, not an assumed saving.

When auditing cross-bundle packets, resolve a sweep question ID inside its
original bundle, then join by review ID. Question IDs are bundle-local. Compare
source across the complete affected package when units split or combine original
bundles; requiring each fragment to include unrelated peers' source is not the
same check. [AM](experiments/review-native-boundary-audit-results.md) verifies this
boundary offline on three original packets becoming two hybrid packets.

`references` also accepts an unambiguous existing directory supplied as `path`,
including the identical directory repeated in `path_prefix`. The controller uses
the offered `path_prefix` operation and records original/effective arguments in
`filter_normalization`. Different scopes and tools requiring a file retain their
validation behavior. Equivalent reference requests reuse source results while
each requested lookup still spends its original query allowance. The receipt is
controller metadata, never source evidence or a safe verdict.

The hybrid binding captures input files, native requests/packages, current runner
code and the prepared workspace state identity. At most 32 units are supported
in this first slice. Selections that cannot fund even one final turn per unit
within original/global budgets are rejected. No additional budget is inferred.

```powershell
python scripts/review_hybrid.py check --root C:/scan-runs/hybrid-comparison
python scripts/review_hybrid.py run --root C:/scan-runs/hybrid-comparison
```

`check` validates frozen inputs/source without dispatch. `run` reserves a fresh
execution once. Modified preparation, active/changed workspace state, earlier
execution or changed runtime is rejected. There is no automatic paid restart or
mid-review handoff. The ordinary native comparator is still available through
the existing batch/pilot control runner on its separate fresh control state.

## Budget accounting

The scheduler connects original bundles whenever one workspace investigation
spans them. Every connected component receives only the sum of those original
bundle allowances. Native fragments, shared workspace groups and their remaining
peers all spend from that component and the global ledger. Each unit also keeps
the original per-bundle ceiling; grouping does not create additional credit.

With the six-call/24-query/512-KiB/900-second design, two connected originals
provide twelve calls/48 query units/1 MiB/1,800 seconds in total. Four routed units
within them do not receive twenty-four calls. Workspace runs first, then native
fragments, with each component contiguous. The remaining allowance reserves at
least one final call for every unfinished unit. A final-only offer has zero
lookup units. This is an allocation policy to evaluate, not a quality guarantee.

Model reservations persist before dispatch. Returned query batches are charged
before validation/execution; rejected batches remain charged. Native research
sees the smaller worker-local/outer remainder. Workspace lookups are checked
against the same ledger before execution. Every received JSON-result byte is
observed, including feedback and partial failures; observed overspend is retained.
Input/output/cached input and model time come from bound provider receipts.
Missing counters or unobserved calls block further paid work on either path.
Unit, component and global deadlines remain active across continuations.

The ledger's `usage` is the combined execution accounting. `workspace_usage`
describes only the workspace registry's own calls/source accounting; do not add
its model counters to the combined ledger or treat it as the whole hybrid cost.
Preparation and final report/source checks remain additional to model time.

## Native validation and original-result assembly

The ordinary worker now supports `--validate-only` with `--phase native`, without
supersession. It performs ordinary review, finalization and report/source checks,
then returns `source_validated` without recording decisions or pending questions.
Default admission behavior is unchanged. The hybrid native path uses this mode
against a source-bound subset work package; the original ownership package stays
current for the workspace/controller.

Exact validated native drafts are captured in the registry with their original
checks/blockers and source citations. No shared proposition or caller applicability
is invented for native results. Native import receipts retain the source worker
drafts and findings hash. Workspace drafts keep their exact proposition revisions,
conditions/exclusions, applicability and deciding questions.

Only after every selected unit completes with known usage does the dispatcher
finalize **every complete original bundle**, revalidate the native report and
export `treatment/review-package.json`/`.md`. Missing claims, stale dependencies
or unresolved required closure prevent complete assembly. Partial native/workspace
artifacts and all spend remain available on failure. Neither path admits decisions
in this treatment. A source-validated report is not semantic adjudication.

The [offline implementation check](experiments/review-hybrid-dispatch-results.md)
establishes this integration and the connected budgets. A fresh live comparison
still needs frozen actual per-unit source packets, evaluator proof/qualification
criteria and a suitable uncertainty control before paid dispatch. No savings or
full-app acceptance follows from deterministic-provider tests.
