# Bounded dependency-chain delivery — 2026-10-30

The previous review-flow work is committed as `bce0a4c`. This continuation fixes
one demonstrated source-delivery defect without another paid model run. It does
not establish better verdicts or solve closure scope.

## Implementation

The opt-in source-profile builder now accepts `--dependency-chains`, implying
`--dependencies`. Discovered source candidates are allocated as chains under
the existing eight-window / 64-KiB bundle bounds. A known chain either fits as a
unit or receives an explicit omission reason. An oversized ambiguous strategy
set does not silently select the first candidate. Independent source preparation
continues when another chain cannot fit.

The allocator first reserves one same-named delegated operation per caller when
the native anchor and invoked member identify one. It then allocates shared
credential-registration source, remaining declared receivers and other imports,
round-robin within each stage. This structural priority is not proof that the
method is the final effect or the only relevant dependency. Source is reused by
hash/range; each caller retains its own question, requested/delivered windows,
source scope and trace. Verdicts and active provider identity are not inferred.

The profile schema, source bounds, stale-source guards, native bundling, worker,
prompt and default preparation remain unchanged. `--dependencies` retains its
previous flat behavior. The builder still does not follow re-export chains or
select source from a reviewer-authored deciding question. Those remain explicit
next work rather than implied capabilities of the new flag.

## Offline experiment and surgical correction

Both replays use the exact CU selection: **72 claims / 29 bundles / five pinned
applications**. Each rebuilds the flat profiles and the new chain profiles with
the frozen optimized native executable, validates bundle membership and every
prepared source range/hash, and verifies all 4,796 source files before and after.
No model decisions, audit answers or manually selected app-specific source paths
enter preparation. Native requests and responses are traced; no provider runs.

The first replay, **CV**, gave credential chains first priority. It delivered
all eight caller-scoped credential chains but displaced the import service that
supported a useful local task-creation closure in CU. Preserve this result as
evidence of the tradeoff; do not promote it merely because strategy delivery rose.

The corrected replay, **CW**, reserves a same-named operation delegate for each
caller first. It retains both the import implementation and the credential
strategy in the affected bundle. A generic four-caller fixture with many service
imports verifies this behavior without embedding application names or claim IDs.

| Offline measurement | CV: credential first | CW: caller delegate first |
| --- | ---: | ---: |
| Claims / native bundles | 72 / 29 | 72 / 29 |
| Legacy flat profiles reproduced exactly | all | all |
| Delivered caller-scoped candidate chains | 39 | 41 |
| Omitted candidate chains | 90 | 88 |
| Delivered credential chains | 8 | 8 |
| Physical window-set changes versus flat | 3 bundles / 13 claims | 3 bundles / 13 claims |
| Source files verified before/after | 4,796 | 4,796 |
| Replay wall, including both preparation modes | 62.985 s | 63.622 s |
| Model calls / provider spend | 0 / $0 | 0 / $0 |

Eight credential chains are eight caller-scoped deliveries of shared source,
not eight independent implementations or security findings. All recorded chain
omissions in these app replays hit the window count bound. Generic tests also
cover byte exhaustion and missing required source.

The original `comparison.json` counts seven changed profiles covering 35 claims.
That comparison also counts ordering. `source-delivery-comparison.json` compares
actual path/range/hash sets and identifies three physically changed bundles
covering 13 claims. Profile digests and evidence IDs may change even when physical
source sets match; do not label these as identical model-packet controls.

CW adds the JWT strategy/module context to two Docmost authorization bundles and
more called implementation ranges to a HedgeDoc bundle. It still displaces some
source, including workspace-ability/repository context in one Docmost bundle and
session/type/decorator source in HedgeDoc. Delivery is improved for the targeted
chains, not globally complete. The remaining 88 omissions are not 88 security
gaps; many are passive imports or repeated caller references.

## Validation and scope corpus

**18 focused tests pass:** nine native-backed dependency tests, four existing
profile tests and five source-builder tests. They exercise aliases, duplicate
registrations, dynamic keys, decorator anchors, independent caller scope,
shared-source reuse, stale bytes, atomic count/byte limits, missing source and
continued independent preparation. The unchanged worker consumes the resulting
profiles through its normal `prepare` and bundle validation paths in the replay.
The previous commit's full controller suite remains historical validation; it
was not rerun for this isolated optional allocator change.

CW also contains `scope-corpus.json`: all **13 CU disagreement cases**, their
original paired outputs, source-audit assessments and **26 verified source-file
bindings**. It is evaluation-only and must never enter reviewer prompts as
expected answers. Cases include local versus downstream closure, optional
credential branches, package binding, generated HTML and the Python reply-target
mismatch at two claim sites. Creating this corpus does not validate or implement
a scope-aware finalizer.

## Decision and next gates

Keep the chain allocator opt-in and retain the flat mode. Stop changing global
source priorities to accommodate individual apps. No paid rerun follows merely
from better physical delivery.

1. Add bounded, explicit re-export navigation using native module identity and
   only the files actually traversed. Cover named/star exports, ambiguity,
   cycles, conditional exports and missing build outputs. Do not guess a runtime
   package binding from a convenient source file.
2. Connect chain selection to an actual deciding question through selective
   lookups. The current automatic navigation questions describe source retrieval;
   they do not establish what fact will change a verdict. Preserve successful
   local facts with source, caller and predicate scope while tracking separate
   downstream obligations. Use the saved scope corpus and generic counterexamples
   before changing reviewer guidance or finalization behavior.
3. Diagnose the recurring provider 403 failures through supported diagnostics
   with the CT/CU attempt lineage intact. Missing usage remains unknown. Wider
   paid comparisons remain on hold until the delivery/scope gates and provider
   operation justify them; no arbitrary global run cutoff is introduced.

Artifacts: `C:/dmitry/scan-runs/dependency-chain-delivery-20261030-cv` and `...-cw`.
Both retain the frozen builder, bindings, sweeps, profiles, native lookup journals,
bundle comparisons and normalized physical-source comparison. CW additionally
contains the evaluation-only scope corpus. Nothing is admitted or published.
