# Shared-answer consumers AS

The controller now offers affected same-work settled judgments alongside remaining
claims, so a reviewer can change a shared answer and explicitly confirm or revise
its consumers in one response. Active claims still determine completion. No
judgment is automatically accepted, and changed answers still invalidate drafts.

This implements the [correction after AR](../review-closure-and-evidence-plan.md#next-implementation-after-ar).
It is an offline implementation/verification slice, with **zero new paid model
calls**. It establishes action availability and guard behavior; it does not
establish live savings or repair AR's capped partial result.

Raw artifacts: `C:/dmitry/scan-runs/workspace-answer-consumers-20261028-as`.
The reconstructed state and packet are diagnostic derivatives, not an authenticated
session that can be resumed. AR remains closed at seven completed arms and one
partial arm; its 32 unused slots remain retired.

## What was wrong

AR's last raw Terra workspace prompt offered only profile and erasure. Its shared
cookie question also named two settled image judgments. Changing that answer
correctly reopened both image judgments, but the task and output-schema enum had
excluded those IDs. The sixth and final allowed call therefore could not confirm
all affected judgments even with the source already available.

The deciding boundary was controller eligibility, rather than a demonstrated
missing-memory or insufficient-investigation problem. Disabling invalidation,
copying old decisions automatically or buying another call would hide it.

## Implemented behavior

The working view keeps genuinely active claims in `claims`. Starting from them,
it closes over shared-question membership within the current work item. Settled
members appear separately in `answer_consumers`, with related question IDs and
their exact `previous_result`. Answered questions are included because revising
their answer can also invalidate consumers. Unrelated settled claims stay out.

The bridge includes those consumers' selected native questions, playbooks,
contracts and IDs in the provider task and schema. Their cited source,
proposition dependencies and applicability receive the existing freshness checks.
Previous results are explicitly described as reviewer interpretations requiring
confirmation where affected, rather than instructions or certified facts.

This grants no authority over another work item. A global shared-answer change
can still reopen foreign-work consumers under the existing guard; it does not
expose their drafts or permit decisions for their IDs in the current task. An
all-settled work item offers no consumers and terminates normally, including when
an intentionally partially resolved question remains open.

The packet assembly is extracted into a pure builder used by normal preparation
and the offline projection. It creates neither a session nor execution authority.
Session identity includes the previous judgments: changing one invalidates a
prepared view. Source/runtime/provider fences and native finalization remain.

Fresh work can explicitly configure up to **144 KiB** for the compact view and
assembled packet. Existing configuration values do not change. The action limit
remains 128 KiB, and call/query/source credit is unchanged. Hybrid and comparison
loops now honor their configured context bound instead of imposing a separate
hardcoded 128 KiB check. Provider formatting adds bytes outside the packet limit;
this bound is not a total formatted-prompt or token ceiling.

## Actual historical projection

`reconstruct.py` opens AR's database read-only and replays 136 saved controller
receipts using AR's frozen old controller, stopping before the final answer.
Its working view matches the saved final-session view except usage/budget fields:
the historical call has already been observed at that replay point. Historical
usage is copied state, not additional spending. `project.py` passes that derived
state through the new view and actual packet builder, without binding or running
an old session.

| Measurement | Result |
| --- | ---: |
| Active selected claims | 2 |
| Additional same-work answer consumers | 2 |
| Offered native questions / schema-eligible IDs | 4 / 4 |
| Compact working view | 129,671 bytes |
| Compact assembled provider packet | 135,731 bytes |
| Explicit fresh packet ceiling | 147,456 bytes |
| Raw / addressed formatted prompt | 144,118 / 157,975 bytes |
| New provider calls / native queries | 0 / 0 |

The packet cannot fit the old 131,072-byte cap. It fits the explicit fresh 144 KiB
configuration without history compression. The actual implementation projection
differs slightly from AR's hypothetical 135,628-byte estimate; use **135,731** for
the implemented builder.

Both old image results are delivered exactly. Source windows, lookup receipts,
every question attempt in this state, qualified propositions and applicability
are identical to the historical packet. No condition or evidence is truncated.
All 1,630 files in AR's closed artifact manifest remain unchanged. The original
database and metadata also remain unchanged. These are projection checks, not
new validation of the historical source, judgments or final package.

## Fresh deterministic verification

A native-bound source fixture contains two selected callers linked by a helper
question and an unrelated settled local caller. Five synthetic observed calls
populate the original six-call budget; these are explicit test costs, not five
paid investigations. On the last allowed fake-adapter call, the task offers the
active caller plus the old consumer, omits the unrelated result, delivers the
exact qualified judgment and permits both IDs in the schema. The deterministic
reviewer changes the answer and explicitly confirms both decisions. Hybrid
assembly then stops at six calls, zero new queries and zero unknown usage, with
normal native finalization. No seventh call is available.

A companion test omits confirmation. The original consumer draft remains intact,
is flagged for reconsideration and prevents export. Further checks cover
connected questions, answered-question revision, all-settled termination,
consumer source/applicability dependencies, session freshness, cross-work schema
rejection and explicit context limits without additional paid credit. Existing
partial-closure tests still require an explicit later confirmation if the model
omits it in the answer-changing response.

Verification totals **160 passed and one platform-specific skip**, recorded by
command in `test-verification.json` in the artifact directory:

| Check | Passed | Skipped |
| --- | ---: | ---: |
| Core workspace | 35 | 0 |
| Answer-consumer core / native-bound bridge | 8 / 4 | 0 |
| Workspace actions | 21 | 0 |
| Provider adapters | 56 | 1 |
| Review package / deciding evidence | 10 / 13 | 0 |
| Hybrid dispatcher | 12 | 0 |
| Existing checkpoint bootstrap/finalization | 1 | 0 |

The skip is the existing POSIX shebang case on Windows. Python compilation and
`git diff --check` also pass. Tests use local source fixtures and fake reviewer
responses; they do not execute a target application.

## What follows

Keep native local SQL/API/redirect closure, the addressed-source option and useful
qualified workspace state. AS does not justify a universal workspace route or
wider speed tournament. It fixes one demonstrable obstacle to balanced reuse.

The next useful live observation, if undertaken, is one fresh Terra 6.1 medium
raw six-claim relationship workspace with the same source and original paid
limits, plus an explicit 144 KiB configuration. Audit whether the reviewer uses
the consumer authority and preserves conditions. Do not resume AR, force a partial
transition, repeat all eight arms or infer efficiency against its censored raw
Terra result. See the [next evidence and stopping rules](../review-closure-and-evidence-plan.md#next-evidence-after-as).
