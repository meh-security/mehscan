# Notebook consumer comparison — 2026-10-26

**Stop expansion of eager case-notebook delivery.** In this slice it avoided
helper lookups, but saved no model turns and increased input/output. Both arms
retained the same unresolved basket effect. This is a completed bounded
comparison with incomplete mechanism closure, not a successful efficiency gate.

## Frozen conditions

Artifacts: `C:/dmitry/scan-runs/workspace-consumers-v2-20261026-j`, including
`consumer-binding.json`, `consumer-source-parity.json`, `notebook.json`, import
receipts, both `consumer-result.json` files, `comparison-result.json` and
`closed.json`.

Both arms reviewed the deluxe customer lookup followed by the basket item
lookup, using the same source snapshot, native questions, protocol v2, model
`gpt-6.1-sol`, medium effort, CLI `0.164.0-alpha.11.1`, source-preparation policy
and fresh-session policy. Canonical initial source matched for both claims.
Cross-work knowledge search was disabled in both arms. Only treatment received
the unchanged 3,503-byte wallet notebook before review. No applicability or
verdict was imported. Arms ran serially: control, then treatment.

Each arm had four pooled model calls, 50,000 observed input tokens, 4,000 output
tokens, 14 query units including two preparation locators, 128 KiB received query
JSON and at most 240 seconds of execution. The whole phase had a 600-second
absolute preparation/execution deadline. The native per-claim ceiling remained
four calls. Shared preparation, including notebook import, took 18,776 ms.

## Actual measurements

| Measurement | Without notebook | With notebook |
| --- | ---: | ---: |
| Model calls | 4 | 4 |
| Input tokens | 48,652 | 54,344 |
| Cached input tokens | 0 | 0 |
| Output tokens | 1,855 | 2,175 |
| Reported call time | 64,809 ms | 68,039 ms |
| Arm execution wall time | 75,596 ms | 78,107 ms |
| Query units including preparation | 9 | 6 |
| Received query JSON | 11,330 bytes | 21,258 bytes |
| Unobserved calls / native admissions | 0 / 0 | 0 / 0 |

Consumer input increased **11.70%**, output **17.25%**, and execution wall time
about **3.32%**. Treatment exceeded its observed 50,000-input gate by **4,344
tokens** on the final call: the pre-dispatch total was below the threshold, and
the returned counters crossed it. The overspend is retained, not counted as
within budget. No further call followed it. Combined consumer input was 102,996
and output 4,030.

Charging the same measured producer cost to both comparison alternatives gives
73,792 input / 2,834 output without the notebook versus 79,484 input / 3,154 output
with it. The input regression is about 7.71% under that shared allocation. This
is a paired consumption experiment after one common producer, not independently
repeated fact production or comparison with the ordinary worker. Actual spend
counts that producer once, not twice. A small serial trial cannot establish a
general latency distribution or the causal contribution of every trace choice.

## Quality and scope audit

Both arms returned `not_issue` for the selected deluxe ownership relationship.
They read the handler, bound its selected user and effects to the body identity
supplied by the middleware, and preserved the separate payment-mode fallthrough
as a reviewer-origin lead. That lead is actionable source-backed uncertainty,
not an admitted payment finding. Its preservation must not be confused with
completion of a separate workflow review.

Both returned `needs_review` for basket. They correctly retained that overwriting
`body.UserId` does not constrain an item loaded by `req.params.id`; neither used
the wallet case as a basket ownership check. They required the downstream
generated update and its hooks before claiming a protected unauthorized effect.
Those are precise remaining gaps, not safe dismissals. The historically
source-audited basket mechanism nevertheless remains unclosed in this review
package, so the supported-mechanism closure gate is not passed.

The treatment's imported proposition remains scoped to GET wallet balance. It
created a separate deluxe proposition/applicability record and did not attach
the whole wallet proposition as applicable to either consumer. No imported
verdict or pending reconsideration is hidden. All four responses passed native
source finalization; that validates bindings and response shape, not completion
of the unresolved security relationship.

## Requested fact → evidence → remaining work → decision

| Arm/claim | Investigation | Outcome |
| --- | --- | --- |
| Control / deluxe | Read handler and `appendUserId` definition | Owner-bound local relationship; separate payment lead |
| Treatment / deluxe | Reuse supplied helper source; read handler | Same decision and lead; still two model calls |
| Control / basket | Read middleware/quantity helper, locate server references, reread `appendUserId` | No owner check locally; downstream effect unread; `needs_review` |
| Treatment / basket | Reuse helper; read basket code and server windows 380–525 and 700–950 | Generated resource identified, but intervening hooks/configuration still unread; `needs_review` |

The notebook did prevent both helper-definition requests. However, each claim
still needed another unique source read, so the avoided helper lookup had been
parallel work inside the same model turn rather than a whole deciding turn.
The treatment also retrieved more server source. In particular, its requested
windows skipped the interval immediately after line 525 while its final blocker
concerned that continuation. The extra read did not settle the deciding question.
This is a trace-level reason to improve evidence selection, not to add another
generic instruction to the reviewer.

The experiment does not show that all memory is uneconomic. It shows that this
eager case notebook, on these consumers, did not remove a model round or enough
payload to cover its own delivery. Fewer native queries were not a cost win.

## Historical stop decision and remaining direction

This was the stop decision after two consumers. The user's subsequent request
supersedes its restriction to offline next work: the [expanded four-arm
comparison](review-workspace-expanded-plan.md) tests source preparation,
rule-aware groups and fact delivery on twelve claims under a new frozen allowance.
The result here does not establish a general workflow winner, and a token
increase alone is no longer a rejection criterion.

Do not add a general retrieval index, expand automatic notebook delivery, repeat
these paid arms, or run a full application from this result. Keep the persistence,
provenance, explicit questions and safe handoff primitives as experimental tools.
The actual live reuse path works; its current economics do not pass.

The next work is **offline**, using these saved traces:

1. Map each unresolved question to the implementation/caller/effect source it
   actually needs. Distinguish shared helper work from the unique work that still
   forces a new model turn. Inspect the missing generated-resource continuation
   rather than filling an application-wide checklist.
2. Check bounded complete-operation packets for authorization/workflow cases:
   local handler, applicable registration and relevant effect/hook configuration.
   Apply the same policy to both compared arms; do not preload a verdict or
   require exhaustive caller traversal. SQL construction closure remains local.
3. Prepare a deterministic grouping diagnostic for the two native basket claims
   representing the same PUT operation (`server.ts:426` and
   `routes/basketItems.ts:68`). One shared investigation with separate verdicts
   tests actual common deciding work. This differs from grouping unrelated
   operations by file/category or imposing a whole-application assessment.

Any later paid diagnostic needs a separately frozen allowance and concrete
expected avoided work. Prefer a design that can eliminate an actual deciding
turn or substantial repeated source, not one whose only prediction is fewer
lookup executions. A richer CLI, semantic retrieval and AI grouping remain
deferred until the review behavior supports that investment.

## Cumulative accounting

The smoke, earlier producer, successful producer and this comparison used
**13 actual provider calls**, **164,788 known input** and **6,567 output tokens**.
Charged reservations total **14**, including the earlier proven local
pre-dispatch abort. The original proposed charged-call allowance is exhausted;
unused token allowance does not grant more calls. These are development costs,
not savings. The older pilot's genuinely unobserved turn remains separate and
unknown, and the earlier full control remains a descriptive reference.

No additional provider call, native admission or full-app rerun follows this
closed comparison automatically.
