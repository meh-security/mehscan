# Rejected workspace decision preview — 2026-10-30

The bounded candidate-export implementation passes its offline gate. The exact
saved OrchardCore owner reply now produces a separately source-validated issue
candidate without accepting its invalid `source132` action, closing its question,
changing a draft or admitting a finding. **No inference or new provider spend.**
This improves recovery of useful paid output; it does not establish better live
precision, reduced model investigation or clean unattended acceptance.

## Problem and implementation

The [30-claim acceptance package](review-orchard-acceptance-results-2026-10-30.md)
ended the owner's six-call workspace allowance with an invalid auxiliary
reference. Its decision had valid source citations and conditional reasoning.
Accepting the whole reply would conceal a failure; buying another conversation
would repeat already-paid work. The existing `export-completed` interface only
handles judgments accepted into workspace state, so it cannot expose this reply.

The new bridge command is `export-candidates --session-id <id> --config <path>`,
with the same bound arguments as other bridge commands. It:

1. Requires a newly recorded stable-schema auxiliary proof-reference rejection
   with a nonempty, independently valid decision component. The adapter saves
   the exact dispatched task and reply privately, and a public hash manifest.
   The workspace binds the manifest digest atomically to the observed call usage.
2. Checks the latest dispatched turn, prepared context, source/runtime binding,
   exact private reply/task, diagnostic, provider and observed receipt. It rejects
   missing/unknown usage, altered artifacts, duplicate/unassigned IDs and claims
   that also request deciding evidence. Every citation must fall inside an
   unclipped source window actually supplied to that turn.
3. Preserves model decisions in `model-decisions.json`, renders ordinary native
   drafts and runs the existing native source finalizer and reporter in a
   separate subset run. It rechecks bindings/state before publishing a preview.
4. Emits `candidate_only` with explicit source-validation, semantic-review and
   non-admission flags. It applies no auxiliary action, closes no question and
   changes no draft, budget, receipt or original failed state. An uncertainty
   candidate must retain meaningful questions already saved in workspace state.

The adapter's `--inspect-candidate` helper is read-only and instantiates no model
launcher. The latest correction round can be previewed after the original
allowance/deadline expires; earlier turns cannot override a later dispatch.
Repeated previews revalidate integrity and source. A crash during export does
not create a completed workspace judgment; retry uses the same bound candidate.
There is no automatic adoption path.

## Exact saved-reply regression

Artifacts: `C:/dmitry/scan-runs/orchard-candidate-preview-20261030-cd`.
The completed fixture lives under `completed/`; private fixture state uses a
separate directory and fake authentication. Development harness failures remain
in the parent scratch directory. None involved inference or changes to the
original live run.

The historical run predates the new task/reply binding and cannot be upgraded
in place. The offline fixture dispatches the **exact saved JSON reply** through
the current adapter using a deterministic launcher, fresh native/workspace
bindings, the original claim and all 19 saved source windows. Its synthetic
100-input/20-output receipt tests binding only; it is not experimental usage,
a new charge or a replacement for the original paid receipt.

| Check | Result |
| --- | --- |
| Exact reply bytes and decision text | Preserved; SHA-256 `496c63753174f5331f14e6b8085f5fc6daadf75d34e7e291d6eddb12fb548d9b` |
| Supplied source | All 19 original windows; all seven decision citations supplied and source-validated |
| Ordinary native report | Issue candidate; semantic/flow review still required |
| Invalid auxiliary reference | Still rejected; no substitution or deletion |
| Exhausted one-call fixture allowance | Preserved; no second launcher call |
| Workspace question/draft/usage/state | Unchanged; question open, draft absent |
| Original completion/native state | Still incomplete/unassessed; no admission |
| CLI versus API export | Identical preview; unchanged workspace |
| Historic artifacts/source | 469 public files unchanged across replay checks; 90 frozen runtime files, 15 frozen inputs and 12,872 source-file hashes independently verified |
| New live model calls/provider spend | Zero / $0 |

`completed/verification.json` records the exact-reply checks and current runtime
hashes. `final-checks.json` records CLI parity, frozen historical/source hashes
and regression-log digests. Replay/checker elapsed times describe offline local
validation and harness work; they are not live speed comparisons.

## Regression validation and one additional correction

Fifteen new candidate tests cover the exhausted allowance/deadline, invalid
auxiliary reference, real native finalization, explicit uncertainty, latest
correction round, changed reply/task/context/manifest/receipt/source, unseen
citations, wrong IDs, unresolved same-claim lookups, missing/unknown usage,
retired contexts, idempotence and interruption after native validation. The
adapter helper is also tested with model-launcher construction forbidden.

The first broader run exposed an existing lookup-reuse ordering defect:
persisted mappings sort by random session ID, so identical effective requests
could point to an intermediate reuse receipt rather than the original observed
lookup. Reuse now selects the earliest matching completed lookup by sequence.
It preserves request scopes, source checks and costs; it does not execute more
queries or infer additional authority. The existing directory-normalization
regression caught this failure and passes with the correction.

Final runs: **208 workspace tests passed; 69 adapter tests completed with one
optional skip; 12 hybrid tests passed** (288 passed, one skipped overall).
These use deterministic provider fixtures and the optimized native scanner.
No target application execution or paid inference occurs. The unchanged native
worker suite was not rerun for this bounded addition.

## Plan and stop decision

Keep cached native review plus selective, question-driven workspace. The live
package remains **$0.934469 / 58 receipted attempts**, with additional unmetered
coordination/source-audit cost. This offline change does not reprice that run,
erase its failed response or make its results unattended-ready.

Stop this implementation slice: the candidate path and state/integrity gates
pass. No larger run, blanket second reviewer or mode tournament is justified
by this result. The remaining bounded plan item is deciding-question framing:
carry local API guarantees versus caller authority and intentional query shaping
versus demonstrated injection into the selected prompt/question, using existing
category/state facilities. Inspect current delivery and saved decisions before
editing guidance; test the framing offline first. Further inference needs a
named unresolved rollout question, a fixed slice and quality/total-price gates.
