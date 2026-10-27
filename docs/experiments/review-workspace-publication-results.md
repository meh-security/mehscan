# Atomic lookup publication — offline overhead check

Status: implemented at `c08a300`; native freshness and accounting tests pass.
The fresh paired benchmark uses real Directus source/native CLI checks and
deterministic model responses. It invokes **zero real provider calls** and makes
no security adjudication, live speedup or broader package-quality claim.

## Change

Previously a new native lookup checked the complete work binding, captured source
in a separate committed action, checked the binding again, then committed its
result receipt. The new controller stages source and receipt in one SQLite
transaction and performs the full native check immediately before publication.
Other readers see neither staged object until that transaction succeeds. Receipt
replay also runs the freshness callback; it cannot skip validation by reusing an
operation key.

This removes one full check for each newly fetched native result. Reused evidence,
guidance and knowledge still receive their publication check. Preparation, paid
inference and outer guard checks remain unchanged. The callback reads committed
workspace state without writing that workspace. No cross-turn freshness cache,
model prompt/schema change, special SDK rule or native admission was introduced.

Query reservation and observed returned-JSON bytes commit before publication.
Stale/invalid capture rolls back the new source and receipt, while those costs and
paid-call usage remain recorded. Successful receipt publication does not charge
observed bytes a second time. Unobserved paid usage still prevents more lookups
or paid dispatch. The captured text expectation is hashed, avoiding a second copy
of source text in the bounded controller action.

## Verification

All **109 workspace tests pass** in 84.389 seconds. The adapter suite runs
46 tests successfully with one existing platform skip. New tests cover:

- Source changes after native lookup and during transactional capture, including
  changes outside the returned source window.
- Superseding owner/generation and a changed native plan before publication.
- Changed provider descriptor or trusted skill during lookup/capture.
- Unknown paid usage preventing lookup dispatch; existing stale-paid-answer and
  prepared-packet/runtime tests remain passing.
- No new evidence/completed receipt visible to another reader before the fence;
  rollback retains query units/received bytes, and replay revalidates.
- Source-text mismatch/truncation, observed-byte mismatch, successful accounting
  exactly once, and exact-source reuse with original query attribution.

An initial full-suite run exposed a rejected empty evidence list for guidance;
that implementation error was corrected before the final suite and benchmark.
No paid repair or model inference occurred. No Rust code changed.

## Benchmark design

Run: `C:/dmitry/scan-runs/workspace-publication-20261027-t`, with matching private
fixture state under `C:/dmitry/scan-private`. `benchmark.py` is the reproducible
driver. `study-freeze.json` binds the driver, implementation hashes and serial order:
old workspace, staged workspace, staged workspace, old workspace. Each run prepares
fresh private native stores/workspaces; the closed R/S studies are untouched.

Old workspace comes from S's frozen package (`8699e5b`); staged workspace uses
`c08a300`. The source is the same pinned Directus export, fingerprint
`review-sources-v1-dd8e919b18edb6952d521d6aad95b439faac593534362545ab6ab28178ef619a`.
The selected SDK claim supplies a native binding, but the responses are a fixed
four-window lookup batch followed by exact reuse of that batch. No finding is
produced; the claim remains open. This is not another SDK review/quality retry.

Every run has two simulated turns, four actual native source reads, four reused
results and eight query units. Dummy provider configuration and an explicitly
mocked provider preflight prevent any live provider invocation; actual adapter
`--contract` processes and all native freshness checks still execute. Simulated
workspace call reservations/zero-token metrics are fixture data, not paid calls or
measured provider performance. Unused ordinary-arm preparations are not executed.

The final comparison verifies exact equality of captured source windows/file hashes,
lookup queries/results/reuse attribution, received JSON bytes, unique source bytes
and query units. Each run retains frozen packages, raw native trace and result.
Preparation is measured separately from the two-turn execution.

## Observed measurements

| Run | State/work checks | Check time | Two-turn execution | Preparation |
| --- | ---: | ---: | ---: | ---: |
| Old workspace 1 | 22 | 11.073 s | 13.236 s | 28.667 s |
| Staged workspace 1 | 18 | 8.995 s | 11.096 s | 26.845 s |
| Staged workspace 2 | 18 | 9.090 s | 11.308 s | 27.068 s |
| Old workspace 2 | 22 | 11.010 s | 13.382 s | 26.921 s |

Mean execution falls **13.309 to 11.202 seconds**, saving 2.107 seconds (15.8%)
in this fixed offline pattern. Checks fall 22 to 18 (18.2%); their mean measured
time falls 11.042 to 9.043 seconds. All four runs retain exactly eight query units,
12,342 received JSON bytes and 4,114 unique captured-source bytes, with identical
semantic source/lookup results and reuse attribution. This is old workspace versus
new workspace, not ordinary native review versus workspace.

Preparation totals 109.501 seconds and two-turn execution totals 49.022 seconds
across the four fresh runs. Preparation differences are not attributed to this
publication change. These measured intervals exclude evaluator/implementation labor
and are not a complete end-to-end wall-time claim. `comparison.json` records the
completed comparison and parity assertions. No benchmark rerun or repair was needed.

## Interpretation and next work

This is a targeted controller improvement with a stronger atomic publication
boundary, not evidence that the full workspace package now outperforms native
review. Many preparation/inference/guard checks remain. A two-turn fixed lookup
pattern cannot establish a live latency distribution or whole-app savings.

The source-quality gap from S is independent: a local implementation mechanism
and its required authority/caller binding still need distinct support in review
state. Resume that milestone with compatible/incompatible bindings and local
controls that need no wider caller discovery. Do not replace it with a new generic
prompt patch, larger budget or unmodified paid SDK retry. Only a genuinely changed,
source-audited package should reach a fresh mixed-batch comparison. Native defaults
remain unchanged, and the sixteen main/eight reserved claims remain unreviewed.
