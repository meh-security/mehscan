# BH partial results and cache accounting — 2026-10-29

**Execution interrupted across all four arms. One matched comparison completed:
Terra's 13-claim JWT package.** Preserve it; the complete Sol/MarsDB comparison
remains unanswered. Cache accounting is now explicit in the analysis and
[larger-run plan](../review-targeted-completion-plan-2026-10-29.md#cache-accounting--added-2026-10-29-at-user-request).

The [frozen BH plan](review-subagent-isolation-plan-2026-10-29.md) preserves three
original native bundles, 22 claims per arm. Fresh direct/helper comparisons use
the same model and medium effort, common diagnostic contract/source broker and
source access. They are not product-native admissions or a causal comparison to
BG. Helper production is charged to its own treatment. All four arms ran in
parallel; no target application or dependency code was executed.

## Completed Terra JWT pair

| Measurement | Direct | Helper plus both consumers |
| --- | ---: | ---: |
| Final claims | 13 | 13 |
| Calls | 15 | 16 |
| Input tokens | 550,104 | 567,808 |
| Cached input | 444,800 | 433,152 |
| Cached-input fraction | 80.86% | 76.28% |
| Output tokens | 8,130 | 9,055 |
| Standard credits | 4.204850 | 5.039715 |
| Standard API USD equivalent | $0.168194 | $0.201589 |
| Same receipts without cache-read discount | $0.590754 | $0.613083 |
| Observed provider time | 155.5 sec | 167.0 sec |
| Family elapsed time | 189.7 sec | 198.8 sec |
| Source queries | 75 | 71 |

The helper saves three consumer calls: routes 8 → 7 and lifecycle 7 → 5.
Producing the helper takes four calls, leaving **one extra call overall**.
Total input increases 3.22%, output 11.38%, family elapsed time 4.75% and observed
cache-adjusted price **19.85%**. Without the observed cache discount, repricing
the same receipts gives a **3.78%** price increase. This is not a measured cold run.

The consumer-only price falls from $0.168194 to $0.153929. Adding the producer's
$0.047660 changes the conclusion. Its cost must not be omitted or assumed
amortized across unobserved future consumers. The completed pair does not establish
lower whole-package cost for this helper design.

### Quality retained and differences

Both JWT helpers produced usable, source-backed, qualified notes: separate root
and middleware bindings; `expiresInMinutes` versus the application's `expiresIn`;
decode versus verify; header-selected algorithms; and unsigned-token behavior.
Neither pretends that the supplied vendor snapshots prove deployed resolution.
The root JWT manifest was absent from the available catalog, and both explicitly
preserve that gap. An archival lock backup does not resolve current installation.

Both Terra packages preserve the four lifecycle mechanisms: conditional forwarded
address bucket selection, unbounded cache-based authorization with correct expiry
semantics, decoded chat identity with a conditional order-tool effect, and optional
current-password confirmation. Both also preserve Product/Recycle denyAll bypass
conditions and the independent basket quantity ownership gap.

Five Terra route labels change from issue to needs_review: erasure-request creation,
card deletion, address deletion, 2FA disable, and quantity deletion. These are not
safe dismissals. Direct spells out more of the conditional forged-cache effects;
helper retains identity questions and local owner/password gates. Quantity has an
independent IP gate whose acceptance remains unestablished. The helper's explicit
uncertainty is useful; the direct issue label is not proof of a reachable deletion.

The broad generated-CRUD issue still identifies different mechanisms: Product PUT
in Terra direct, privileged registration in Terra helper, and basket/delete plus
a registration lead in completed Sol direct routes. Preserve the mechanism union;
do not treat identical issue labels as equivalent coverage. Native source validation
was not performed in this diagnostic; physical citations were checked separately.

Terra direct and Sol direct auth-route sessions reached their eighth/final call.
Terra helper's route consumer completed in seven. Retain remaining unread-edge
qualifications; do not claim identical uncensored research depth.

## Cache measurements across all recorded receipts

These rows cover known receipts only, at different completion depths. **They are
not a ranking of completed alternatives.** Each arm additionally has one actual
invocation without a receipt.

| Arm | Known receipts / actual calls | Final claims / selected | Recorded input | Cached input | Cache share | Known API equivalent | Same known receipts without cache discount |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Terra direct | 20 / 21 | 13 / 22 | 701,929 | 559,360 | 79.69% | $0.217367 | $0.748759 |
| Terra helper | 22 / 23 | 13 / 22 | 775,075 | 581,760 | 75.06% | $0.274008 | $0.826680 |
| Sol direct | 14 / 15 | 9 / 22 | 573,548 | 456,192 | 79.54% | $0.361781 | $1.228546 |
| Sol helper | 10 / 11 | 0 / 22 | 421,879 | 322,432 | 76.43% | $0.275517 | $0.888138 |

Known total: 2,472,431 input, 1,919,744 cached input and 32,270 output tokens.
The 66 recorded receipts cost $1.1286734 at the frozen Standard API equivalents;
repricing those same receipts without cache-read discounts gives $3.6921230.
The resulting $2.5634496 discount excludes all four unknown invocations. Cache
writes are explicitly reported zero on every known receipt; no missing counter
was silently assigned zero. These equivalents are not account invoices.

Cached-input fractions are token-weighted. Cache lowers total recorded price by
about 67–71% in the per-arm rows. That is economically material despite continuing
source/history repetition. Analysis now breaks this out by arm, family and session,
including producer cost. No latency improvement is attributed causally to cache.

BG observed almost no caching; BH's large cache share is a new observation, not
proof that isolation caused it. Models, source availability, diagnostic prompt/
schema, execution timing and potential cross-arm cache overlap limit comparisons.
A fresh conversation is not necessarily cold. Do not buy warm-up calls or assume
these hit rates transfer unchanged to a larger deployment. A useful next offline
check is prefix/schema/source stability in saved BG versus BH receipts and prompts.

## Interruption and accounting

All four study Python processes and their terminal sessions disappeared. Private
provider traces stop around 16:53–16:54 UTC with no current-turn completion or
answer artifact. New Codex runtime processes started around 16:54 UTC. The pinned
executable under `bin/2993767bd1dfb009/codex.exe` is now missing; the current runtime
is under `bin/0ab0e7a8f3779036`. This is consistent with an application/runtime
replacement interrupting the work. The exact trigger is unconfirmed; it is not
established as PC sleep or a model failure.

All source and remaining frozen files are unchanged. The runtime guard correctly
fails because its executable is absent. No runtime was silently substituted, no
unknown call was repurchased, and original ledgers remain untouched. An offline
sidecar marks their former running states as interrupted. All 66 known receipts
were recomputed from raw provider events and exact cumulative-counter deltas.

- Terra direct: interrupted in database turn 6; both JWT consumers complete.
- Terra helper: interrupted in MarsDB researcher turn 7; JWT helper and both
  consumers complete.
- Sol direct: interrupted in lifecycle turn 7; route consumer complete.
- Sol helper: interrupted in route consumer turn 8; JWT helper complete.

There is no final MarsDB consumer result and no completed Sol helper consumer.
Do not infer selector-error correction, SQL-peer preservation, or whole-arm price
savings from their partial progress. Full end-to-end completion times are unknown.

## Next boundary

Keep direct review as the economical observed Terra JWT option; retain the helper's
useful source handoff and scoped uncertainty. This single pair does not justify
discarding helpers for other relationships or declaring a general winner.

Cache-adjusted complete-package price is now mandatory alongside quality, raw input,
source repetition and timing. The dated targeted-completion plan remains the next
main direction. The requested BH test is only partially answered: any completion
of its remaining work needs a fresh recovery contract/runtime binding that retains
all spent calls and unknown usage. Never repurchase the completed Terra JWT pair.

Artifacts: `C:/dmitry/scan-runs/subagent-isolation-20261029-bh`:
`comparison.json`, `source-quality-audit.json`, `receipt-source-audit.json`,
`interruption-audit.json`, `remaining-work.json`, raw prompts, lookups and outputs.
Preparation-script time is recorded, but harness authoring, historical vendor
acquisition and human adjudication are not fully timed/priced. This is development
evidence on familiar source, not independent accuracy or production total cost.
