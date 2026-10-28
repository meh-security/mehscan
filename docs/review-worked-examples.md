# Worked review examples: what native and workspace give the reviewer

Use native for a question the supplied local construction can settle. Use
workspace where a qualified implementation fact helps several callers, or where
some claims can close while a different dependency remains unresolved. Native
also shares source within its ordinary maximum-20 packets. Workspace is useful
state and presentation infrastructure, not an automatic improvement for a category.

These six examples are **saved outcomes**, projected through the current CLI onto
database copies. They introduce no model calls, new findings, native admission or
accuracy/speed measurement. They come from [AL](experiments/review-hybrid-packet-results.md)
and [AX](experiments/review-comments-comparison-results.md); source, model, contracts
and proof depth differ. Do not combine their timings into an engine ranking.

## Six concrete outcomes

| Example | Actual outcome | What the reviewer learns | Useful workflow behavior |
| --- | --- | --- | --- |
| Product search SQL | `issue`, high | Request `q` enters quoted SQL grammar directly; truncation does not bind it as a value | Ordinary native review settles a local construction and supplies a concrete parameter-binding fix |
| Local HTML policy, no hook | `not_issue` | This fresh policy instance escapes input for an ordinary element body and registers no later hook | A shared implementation fact is applied to this caller's actual configuration |
| Same factory, unsafe later hook | `issue`, medium in Sol workspace | The hook inserts URL-controlled event-handler code after escaping | Shared source produces a different verdict when the caller changes the check-to-effect relationship |
| External HTML policy | `needs_review` | The import map identifies an asset, but its implementation/output contract is unavailable | Local claims stay closed while only the external question continues |
| Wallet card ownership | `not_issue`, with a separate payment lead | The selected card and credited wallet are tied to the accepted caller identity; credit amount/payment settlement remains a different question | A narrow negative does not erase an actionable workflow lead or certify the whole operation |
| Bulk comment deletion | `not_issue`, qualified | The caller reaches the override, and post-hook keys checked for delete access are the keys deleted | Shared inherited implementation is explained with separate single/bulk applicability and retained exclusions |

## 1. Local SQL: stop when the selected mechanism is established

Saved claim `review-8efee4242f8a9275`, `routes/search.ts:23`, was handled by the
**native engine** inside AL's hybrid package. Its recorded result says the request
search value is interpolated inside quoted `LIKE` expressions without escaping
or binding. The 200-character limit does not prevent SQL grammar changes, and
query results return to the requester. The proposed fix is fixed SQL with bound
values for both operands.

This finding does not need every caller of the database library or a new learned
fact store. Search and login can share a native packet while keeping their own
mechanisms and impact conditions. Login's second-factor qualification does not
transfer to product search. The saved inventory does not contain an admitted safe
parameterized SQL control; these positives do not prove balanced SQL accuracy.

AL also had a known caller-proof limitation: its supplied custom-wrapper window
omitted `asyncHandler`. The evaluator later inspected the transparent wrapper,
but that read is not retroactive reviewer evidence. Preserve this source-delivery
qualification rather than describe the historical package as complete proof.

## 2. Shared HTML implementation: one fact, three different decisions

This is a constructed source contrast, not a held-out production application.
The relevant shared fact is conditional:

```text
createPolicy escapes the input, then runs that instance's hooks.
applyPolicy delegates to the supplied policy's sanitize method.
Escaping protects ordinary HTML element content only if later hooks
do not introduce unsafe markup. External policy behavior is not established.
```

The exact caller configurations produce separate outcomes:

```text
page-one:   local fresh instance → no hooks → escaped text → innerHTML
            not_issue for the selected ordinary HTML-content boundary

page-two:   local instance → escape → hook adds URL-controlled onerror
            → innerHTML → issue: the later insertion defeats earlier escaping

page-three: external policy → unknown sanitize implementation → innerHTML
            needs_review: inspect what /runtime/output-policy.js serves
```

The saved Sol workspace closes the first two claims in turn 1. Subsequent contexts
retain only the external claim as active:

| Turn | Offered active claims | Committed decisions | Deciding evidence requested |
| --- | --- | --- | --- |
| 1 | All three | Local safe + local unsafe | Read the actual import-map target; the file lookup returns not found |
| 2 | External only | None | Locate policy/runtime paths; only the known local policy is found |
| 3 | External only | None | Inspect the package manifest; a dependency declaration does not supply the served implementation |
| 4 | External only | External `needs_review` | Preserve the exact missing asset/output-contract question |

The package makes a useful stopping point reviewable. Missing local files do not
prove a runtime asset cannot load, and a similarly named local sanitizer does not
establish the external policy's behavior. The local successes need not become
fresh investigations while that question remains open. This AL four-turn sequence
is not AS's later settled-consumer reconfirmation scenario, and it is not a new
memory-savings result. Sol native also reaches the same three outcome categories
in three calls; Sol workspace takes four in this historical comparison.

The hook's original severities differ: **Sol native high, Sol workspace medium,
Terra workspace high**. AY found and corrected AL's documentation claim of
severity agreement; no original diagnosis is changed. Agreement on the mechanism
and verdict does not mean equivalent risk classification.

## 3. Ownership: preserve the useful lead after local closure

Saved claim `observation-review-30694846a0f13032`, `routes/wallet.ts:24`, asks about
cross-owner resource selection. The result binds the inspected registration's
overwritten `UserId` to both the selected payment card and credited wallet. A
foreign card cannot pass that conjunction. Its `not_issue` applies to this
ownership question under the accepted authentication identity, with AL's wrapper
source qualification noted above.

The same result retains a separate lead:

> What validates or settles the client-requested balance amount before wallet credit?

That lead is not an additional classified finding. It explains why closing the
ownership claim does not certify payment amount, settlement, ordering or
concurrency. Workspace's shared ownership note also explicitly excludes those
guarantees. A reviewer can retain the useful concern without reopening unrelated
owner selectors or losing it behind a safe-looking label.

## 4. Inherited comment deletion: distinguish scoped closure from deeper assurance

Saved claim `observation-review-940a94509d1dcf63`, `comments.ts:161`, reaches
`CommentsService` with request accountability. Its update/delete overrides and
inherited methods preserve the selected action and effective keys. The workspace
result closes deletion because rejection precedes the effect on those same keys.
Its shared note excludes arbitrary extensions, permission configurations and
other callers; administrators are explicitly exempted by the access check.

Sol native retains that local chain but asks whether deeper permission helpers
correctly handle deletion's empty field list, and whether credential helpers
establish the authority. It exhausts its allowance with `needs_review`. Terra
native inspects more accountability/permission code and closes the claims. These
are different stopping boundaries. Do not turn workspace's first-response result
into a claim that it performed native's deeper audit more efficiently.

## Use the CLI without another model call

The example directory is
`C:/dmitry/scan-runs/workspace-review-examples-20261028-ay`. Each case contains a
copied `workspace.sqlite`, binding-only `seed.json`, exact `claim.json` and a
generated `focused.md`. From the repository root, these commands inspect the
prepared **copies**, rather than operating on a historical live workspace:

```powershell
$example = 'C:/dmitry/scan-runs/workspace-review-examples-20261028-ay/html-external'

python scripts/review_workspace.py review-package --workspace "$example/workspace.sqlite" --seed "$example/seed.json" --format markdown --review-id observation-review-a2cbd2fbdc1fdeeb

python scripts/review_workspace.py knowledge --workspace "$example/workspace.sqlite" --seed "$example/seed.json" --proposition-id local-policy-escaping-before-hooks
```

The first command shows the selected native question, unchanged verdict/reason,
linked conditions and applicability, outstanding question and captured source.
The second shows the qualified fact; it does not turn that interpretation into
a certified or universally applicable fact. Focused Markdown retains the package's
full source catalog and does not reduce a model prompt.

For why the historical work progressed or stopped, use the saved read-only
`policy-turn-audit.md` in the example root. It joins each requested question to
returned evidence and observed remaining work. The package is the result view;
the turn audit is the investigation view. The existing CLI offers explicit
inspection commands, not a released interactive scheduling UI. These examples do
not require another UI, summarizer or state schema.

## Verification and next boundary

AY regenerates all three source packages exactly on copies and checks six focused
CLI outputs against the existing renderer. All six selected results and their
original questions/reasons remain literal; copied databases remain unchanged.
All captured source-file hashes are current. The original 1,527 AL files and 433
AW files remain byte-identical; AP and AX closed manifests and the 68 frozen
candidate files still verify. Full provenance is in AY's `verification.json`.

An offline byte-boundary check also reproduces AX's 48,178 canonical UTF-8 bytes
versus 48,203 under the frozen Windows default-decoding path. A hypothetical limit
between them would stop prematurely; the actual 512 KiB allowance was unaffected.
The runtime remains frozen. This concrete accounting defect can receive a later
explicit-UTF-8 correction with an offline boundary test, without reopening AX or
buying another model run.

The decision remains native local closure plus selected qualified workspace
relationships and partial closure. No new comparative accuracy, human-review time
or persistent-memory saving is established. Before default promotion, validate
an independently adjudicated mixed package and realistic source-preparation cost.
No unchanged paid repeat, full-app run or automatic feature expansion follows.
