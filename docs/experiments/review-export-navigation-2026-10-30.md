# Bounded export navigation — 2026-10-30, CX

This continues the [CW chain-delivery study](review-dependency-chain-delivery-2026-10-30.md).
The new native query answers one named export-navigation question. It does not
preload another application-wide context graph, change model guidance, or spend
provider calls. Native and selective workspace remain the operating direction.

## Implementation and correctness

`mehscan investigate export-target ROOT --path FILE --name EXPORT` follows static
named/default aliases and star exports through the existing module resolver.
It returns visited nodes, a unique source candidate when established, ambiguity,
missing/unsupported branches, and explicit traversal limits. Normal native query
journaling records the request and result. The graph summarizes only traversed
modules, although ordinary repository discovery and source loading still occur.

Bounds are eight levels, 128 nodes/edges, 32 summarized files, 256 KiB per file
and 1 MiB of parsed source. A partial graph cannot select a unique candidate.
Explicit exports take precedence over stars; stars exclude `default`. Diamond
paths to the same implementation are allowed. Namespace imports, type-only
imports, reassigned bindings, parser failures, cycles and missing package build
outputs retain gaps. No package `source`/`module` field is guessed as the active
runtime entry. Existing graph nodes remain useful leads even without a final
unique target.

The work exposed a shared resolver bug: an ambiguous inner star returned no
target, which a parent could discard before accepting another sibling as unique.
Ambiguity now propagates through the resolution walk. The old CU executable
produces process-execution paths through both an ambiguous barrel and a valid
direct import in the generic counterexample; the corrected executable retains
only the direct-import path. This is a deliberate scanner correction, not just
a new review API. It does not mark the unresolved caller safe.

Fourteen focused Rust tests pass: seven export-navigation/scanner controls,
six existing import/module/ownership/type/object regressions and one CLI journal
test. They cover unrelated malformed files, alias identity, import conditions,
explicit precedence, diamond paths, nested ambiguity, cycles, absent branches,
reassignment, namespace/type erasure, and depth/file/byte limits.

## Frozen replay

All 72 selected claims / 29 bundles across NodeGoat, Docmost, HedgeDoc, FlaskBB
and PyGoat replay successfully. Legacy flat profiles exactly match CU and chain
profiles exactly match CW, including ordering and hash bindings. The replay takes
63.339 seconds; the existing allocator still delivers 41 chains, omits 88 at its
window limit, and retains all eight credential chains. No new source windows are
automatically added by CX. `compatibility.json` records the exact comparisons.
The inherited `comparison.json` fields comparing flat against chains repeat the
CW experiment; they are not changes caused by this implementation. This is saved
preparation compatibility, not a fresh full-inventory or live review result.

Seven saved navigation questions ran through the optimized CLI with native
journals. They took 2.700 seconds of replay wall time, with 17 native queries;
the sum of query durations is 6.384 seconds because up to three questions ran
concurrently. These are local navigation measurements under concurrent replay,
not model latency or an end-to-end review benchmark.

| Question / control | Result | Files summarized |
| --- | --- | ---: |
| Export service's actual `getPageTitle` import | `integrations/export/utils.ts` | 1 |
| `sanitizeFileName` through the common helper barrel | `common/helpers/utils.ts` | 8 |
| Same-name `getPageTitle` through a different explicit entry | `common/helpers/constants.ts`, kept separate | 8 |
| Link view's `@docmost/editor-ext` import | Unresolved package/build entry | 0 |
| Kanban card's independent import of the same package | Unresolved package/build entry | 0 |
| Explicit editor source barrel and `sanitizeUrl` | Incomplete at the file bound; no unique candidate | 32 |
| Explicit sanitizer source leaf from the saved audit | `packages/editor-ext/src/lib/utils.ts` inspectable | 1 |

The first three paths are under `apps/server/src/`. The exact export caller uses
`./utils`, not the common helper with the same name. Declaration-name similarity
must not substitute one implementation for the other. Four unique candidates in
this table are navigation outcomes, not four security closures.

The two package-import gaps remain independent of the broad source barrel's
traversal limit. The latter reads 79,481 parsed source bytes before reaching the
32-file bound. Inspecting the saved leaf is useful local evidence, but does not
establish the missing package/build relationship. Neither gap is a safety verdict.

Source hashes for all 4,796 pinned files verify before and after the replay.
Artifacts live in `C:/dmitry/scan-runs/export-navigation-20261030-cx`, including
`question-results.json`, per-question native journals/source reads, the generic
old/new ambiguity counterexample, frozen implementation files and runtime patch.
The scanner SHA-256 is
`faae7133546302ed884558490aa7479852e939736a2c8621298498753059e8c0`.
The optimized build took 7m08s including its initial build-lock wait; build and
coordination time are outside the navigation replay wall time.

## Direction and stop rules

Keep this as a native navigation primitive. The typed model research API and
automatic source-profile builder do not use it yet. Existing flat and chain
preparation modes stay opt-in. Do not add another global source-priority rule or
raise graph limits simply to make one application's barrel appear resolved.

The next implementation gate is a reviewer-directed lookup attached to an exact
claim and deciding question. Preserve the import path, requested fact, source/hash
binding, returned evidence, remaining applicability question and later decision.
Reuse identical lookup results within pinned source while retaining each caller's
scope. A useful local implementation can be inspected even while package/build
applicability remains unresolved; those are separate review obligations.

Use the saved 13-case scope corpus to distinguish a valid local closure from an
unproven downstream effect. Do not feed prior answers into new review packets.
Stop before paid expansion until the normal lookup/finalization route is tested
offline and the recurrent provider-403 failure gate is addressed. Previous failed
attempts and unknown charges remain recorded; this experiment adds no provider
spend. Neither this navigation test nor profile compatibility establishes a model
quality or price improvement.
