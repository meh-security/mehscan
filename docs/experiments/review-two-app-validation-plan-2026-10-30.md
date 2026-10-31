# Frozen workflow validation on two applications — 2026-10-30

The user requested two live application runs after the normal controller replay
passed offline. This tests bug-finding quality and actual runtime behavior,
rather than further tuning OrchardCore or reducing sub-dollar differences.

## Fixed sources and coverage

| Application | Source commit | Full inventory | Rules | Claim-bearing files |
| --- | --- | ---: | ---: | ---: |
| FlaskBB, production Flask forum | `737d76f14e8f8fa4a493f1424ab184c87aecc516` | 205 | 16 | 24 |
| crAPI, deliberate API-security benchmark | `b5fc307f3e5f875809b095b771108ef342a33724` | 155 | 59 | 43 |

Official sources: [FlaskBB](https://github.com/flaskbb/flaskbb) and
[OWASP crAPI](https://github.com/OWASP/crAPI). Fresh shallow checkouts, no app
execution, builds or target dependency installation. Freeze all 506 FlaskBB and
1,062 crAPI source files outside `.git`. Prior crAPI native benchmark work exists;
this is a fresh run of the current review workflow, not a claim that the project
has never been inspected by Mehscan. Previous verdicts/benchmark labels are not
supplied as expected answers.

Review all 360 inventory claims, including any marker continuation pages. No
outcome-based candidate selection, hand-seeded final context, saved model answer
or app-specific initial source profile. Ordinary native application preparation
and deciding lookups remain available. Value is recorded as a priority hint;
the selected coverage is explicitly all, not a filtered Value result.

FlaskBB is heavily HTML/redirect oriented (95 / 82 claims). crAPI adds Java,
Python and Go API relationships, SQL, resource access, tokens, uploads and TLS.
Inventory coverage is not complete security coverage: absence of a candidate
for an endpoint or rule is not a negative verdict. Record scanner/coverage gaps
separately from wrong AI dismissals. Teaching comments and benchmark examples
are source data, not independent truth labels.

## Frozen execution

Implementation/report baseline `c28735a` / implementation `cc4fe2b`. Same optimized
scanner, Terra 6.1 medium, stable schema, line-addressed source and category
guidance. Freeze and preflight every initial source packet, contract, inventory,
provider and source hash before inference. No prompt/model/mode tournament.

Run both applications in parallel, three native workers each: six simultaneous
provider calls maximum. If an app needs marker streams, process its streams
sequentially with those same three slots. Keep native bundle defaults of 20.
Use the existing five continuation rounds, 24 query units, 524,288 source bytes
and 900-second investigation deadline. No aggregate three-minute cutoff.

Retain all paid calls, failed replies, cache counters and unknown usage. A local
bundle failure does not cancel unrelated bundles or the other app. No automatic
fresh retry or budget reset for a failed/unknown attempt. Respect provider blocks.
Keep the execution request through final validation and completion publication;
record stage walls, all attempted provider price and manual recovery separately.
No native admission.

## Selective follow-up and source audit

Keep native first-pass outputs as the comparison baseline. Use workspace for
specific consequential uncertainty, a risky confident negative, unsupported
promotion or an actual shared implementation/authority-to-effect relationship.
Preserve per-claim questions/verdicts; share source only where applicable. Local
SQL binding and complete transformations need no compulsory caller inventory.

Bound follow-up to at most eight investigations / 24 claims per app with the
existing six-call, 24-query, 512-KiB and 900-second workspace limits. This is a
study boundary, not permission to label unfinished claims safe. Do not seed the
final answer or benchmark label into a follow-up. Newly learned facts may be
reused only with current source and compatible caller applicability.

Audit all issue promotions against their actual mechanism, guards, actor and
effect. Screen negative summaries and inspect a reproducible stratified source
sample, including consequential controls. Inspect uncertainty for available
local evidence versus real deployment gaps. Check known benchmark mechanisms
against the pinned source after review; distinguish missed inventory coverage,
missed findings and wrong dismissals. Do not calculate whole-app precision or
recall from incomplete labels or selected source audits.

Report retained supported mechanisms, rejected promotions, wrong dismissals,
useful uncertainty, execution failures, manual intervention and incremental
workspace value. Measure actual input/cached/uncached/output/cache-write tokens,
all-attempt API-equivalent price and time. Cache percentage and closure count
alone are not quality.

Stop after both native runs, bounded follow-ups and the source/flow audit, or
explicit original-limit/failed-ID accounting. Preserve mixed useful modes. Fix
only consequential demonstrated bugs, retain the original results and replay
each correction against prior cases. Do not tune the prompt mid-run or silently
turn assisted completion into unattended success.

Artifacts: `C:/dmitry/scan-runs/two-app-validation-20261030-cj`.
