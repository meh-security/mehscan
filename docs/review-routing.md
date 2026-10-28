# Inspect selective review routes

`scripts/review_routing.py` implements the first slice of the
[routing plan](review-routing-plan.md). It creates a JSON/Markdown proposal from
an existing inventory and ordinary maximum-20 native bundle manifest. It invokes
neither a model nor the native executable. It creates no workspace or verdict and
does not dispatch either path. Existing worker and workspace behavior is unchanged.

## Generate and check

```powershell
python scripts/review_routing.py `
  --source-root C:/authorized/application `
  --inventory C:/scan-runs/inventory `
  --manifest C:/scan-runs/bundles/manifest.json `
  --output C:/scan-runs/routes
```

The new directory contains `routing.json`, `routing.md` and `preparation.json`.
Every selected claim appears once, retaining its original bundle ID, source
anchor/hash, proposed path, strategy, deciding question and selection reason.
Native packet memberships preserve the original grouping of their native members;
they do not assert shared caller policy. Limits and upstream planner abstentions
remain visible. The proposal accepts 1–128 claims, at most 20 per original bundle.

Without other inputs, claims stay native. Known SQL, cookie, parser and NoSQL
families receive a local investigation question; fallback does not assert that
the claim is locally complete. A rule name does not certify a verdict.

Optionally add `--planner-plan C:/scan-runs/work-plan.json --scanner PATH` to use
an existing [work planner](review-workspace-planner.md) proposal. The scanner is
hashed, never executed. Planner content, current code, inventory, engine, selected
claims and recorded physical source must validate. A shared-operation proposal
can select workspace; a `local_sql` group stays native. Unsupported/isolated
authorization remains native unless explicitly selected. Generating the upstream
planner can make native queries; its recorded cost is retained separately from
the router's zero native/model calls. Do not count that preparation as free.

```powershell
python scripts/review_routing.py `
  --source-root C:/authorized/application `
  --inventory C:/scan-runs/inventory `
  --manifest C:/scan-runs/bundles/manifest.json `
  --check C:/scan-runs/routes
```

Supply the same optional planner/scanner/selections inputs when checking. This
reconstructs the proposal and rejects changed routes, inputs, runtime or captured
source. It writes nothing. Output must be outside application source and must not
already exist. Native's display root `.` is accepted; the explicitly supplied
physical root and selected file hashes are bound in the proposal. This checks
captured-file freshness, not the entire inventory snapshot or native ownership.

## Explicit relationship selections

`--selections PATH` accepts a JSON document with these fields:

- `schema_version`: `mehscanReviewRoutingSelections/experimental-v1`.
- `binding`: the three `source_fingerprint`, `inventory_sha256` and
  `manifest_sha256` fields from the initial proposal's binding.
- `selections`: a list of source-bound selection objects.

Each selection contains `review_ids`, `route`, `kind`, `deciding_question`,
`reason`, `caller_checks`, `evidence_windows` and `limits`. Workspace kinds are
`shared_operation`, `shared_dependency` and single-claim `relationship`.
Shared kinds need at least two claims. Every workspace member needs its own
caller/check question, keyed by claim ID. These are questions, not inherited facts
or verdicts. Windows contain `path`, `start_line`, `end_line`, `file_sha256`;
current bytes must match. Keep nonempty limitations and state why sharing or
persistent relational work helps. Native exceptions use `kind: native_local`,
with empty caller checks/windows; they make no applicability assertion.

Selections may not overlap, name unknown claims or contain more than 20 members.
Source windows allow at most eight, 400 lines/16 KiB each and 64 KiB per selection.
The whole inspection reads at most 16 MiB of source. An oversized automatic
operation proposal stays native with a visible limit. Explicit exceptions split
automatic groups; remaining compatible peers can still share. Invalid explicit
source is rejected rather than silently broadening its scope.

Explicit selection labor is reported as unmetered, not zero. Content hashes
provide integrity, not authentication or semantic certification of the proposal.

## Inspect the dispatch cost before execution

`dispatch_effects` lists the original packet count, proposed native/workspace
units, original bundles split across destinations and workspace groups whose
members already fit one native packet. JSON, Markdown and the receipt expose this
information. These are proposed context units, not model calls or saved work.
Routing can add conversations even when its grouping is source-correct.

The [22-claim offline check](experiments/review-routing-inspection-results.md)
proposes 15 native claims and seven workspace claims, but twelve units versus ten
original packets. Keep the candidate routes; measure whether their state/sharing
value offsets this cost rather than declaring a hybrid saving from group counts.

`dispatch_ready` stays false. Mixed original bundles need subset task formation
and complete original-result assembly before native validation. Future dispatch
must retain a combined allowance for fragments of the same original bundle;
cross-bundle workspace groups need a shared ledger for the connected original
bundles. Splitting a bundle must not grant each fragment a fresh six-call budget.
The [hybrid dispatcher](review-hybrid.md) now implements that separate execution
boundary. The inspector artifact itself remains a proposal with
`dispatch_ready: false`; dispatch requires a fresh bound hybrid preparation.
