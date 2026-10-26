# Wallet producer with prepared route source — 2026-10-26

**The producer completed in two calls and exported a bounded notebook.** Native
source validation and the subsequent source audit support the narrow wallet
selector decision. No consumer ran; useful cross-claim reuse remains unproven.

## Frozen test

Artifacts: `C:/dmitry/scan-runs/workspace-producer-v2-20261026-i`, including
`producer-binding.json`, `route-locator.json`, `route-preparation.json`,
`producer/result.json`, `producer/notebook.json`, `source-audit.json` and
`budget-ledger.json`. Historical attempts were not reopened.

One selected native claim, `observation-review-d3ddaeb3c0f97e31`, used the same
pinned Juice Shop source, `gpt-6.1-sol`, medium effort and CLI
`0.164.0-alpha.11.1`. The experiment froze protocol v2, at most three model calls,
45,000 observed input tokens, 4,000 output tokens, 12 query units including
preparation, 128 KiB of received query JSON and a 300-second absolute
preparation/execution deadline. Unknown usage would stop dispatch. No correction
or consumer call allowance was added.

The initial packet contains the selected wallet handler and 382 bytes of actual
route source from the native `getWalletBalance` reference. The guard body was
not preloaded. Cross-work knowledge lookup was disabled, and no evaluator answer
or manually authored proposition entered the packet.

## Result and deciding evidence

| Measurement | Actual result |
| --- | ---: |
| Model calls / unobserved calls | 2 / 0 |
| Input / cached input tokens | 25,140 / 0 |
| Output tokens | 979 |
| Reported call time | 31,507 ms |
| Review execution wall time | 36,003 ms |
| Preparation through result wall time | 177,825 ms |
| Query units, including preparation | 4 |
| Received query JSON | 10,238 bytes |
| Exported notebook | 1 proposition, 3,503 bytes |
| Consumer calls / native admissions | 0 / 0 |

The first model turn asked whether `appendUserId` binds the selector and what
happens on failed identity lookup. It requested the guard definition and a
server prefix for import/earlier middleware context. The controller retrieved the
definition and bounded body. The second turn used the supplied registration,
guard body and wallet read to answer the question and return `not_issue`.

The decisive chain is concrete: the GET route runs `appendUserId` first; that
middleware assigns the token-map entry's `data.id` to `body.UserId` and advances
only after that access succeeds; the read filters the wallet by that value.
The error branch sends 401 without advancing. The server-prefix lookup supplied
namespace context but was not part of the exported decisive evidence; it remains
an opportunity to reduce broad supporting reads rather than a reason to rerun
this completed producer.

The source audit verified all three exported windows against actual file hashes
and bytes. Native finalization also validated the scoped response. The initial
question is answered, and native outstanding checks/blockers are empty without
the model writing those fields.

One initial launch failed before reservation because the producer output parent
directory had not been created. Creating it allowed the unchanged frozen runner
to start; no provider call, reservation refund or deadline extension occurred.
That setup time is included above. The project execution helper now creates its
arm directory, with a regression test. Writing/freezing the runner also falls
inside the reported preparation interval; 36 seconds is not the complete
experiment wall time.

## What the notebook can and cannot establish

The saved proposition is scoped to **GET `/rest/wallet/balance`**. Its conditions
require the shown middleware order and a token map supplying caller identity.
Its exclusions explicitly retain token issuance, token-map integrity, other
wallet operations and other routes outside its assessment. The producer did not
prove JWT verification or make an application-wide authentication assertion.

This is a remembered, source-backed case with useful helper implementation
evidence. It is not a universal authorization rule. In a consumer experiment,
the model may reuse the supplied `appendUserId` source while establishing its own
registration, arguments and effect. The wallet proposition itself must not be
declared applicable wholesale to deluxe or basket. In particular, replacing
`body.UserId` does not constrain `req.params.id`. Do not manually broaden or
rewrite the paid proposition before testing its consumption.

## Reference comparison and limits

The fresh ordinary control from attempt `d` used four calls, 110,846 input,
2,051 output and 59,269 ms of reported call time for this exact native claim.
Those are descriptive reference measurements. This producer changed source
preparation, review contract, guidance/session handling and retained state; it
does not isolate any one cause. Its whole preparation interval is substantial,
and one negative claim cannot establish mixed-package quality or economics.
No percentage saving or memory benefit is claimed.

## Next gate and cumulative accounting

The producer-only attempt is closed. A separate comparison may now give the
**unchanged** notebook to deluxe and basket consumers versus no supplied notebook,
with matching native route preparation, independent decisions and source audit.
Keep knowledge search disabled in both arms and count every payload, lookup,
split and deferred claim. Preserve the deluxe payment prerequisite mechanism and
the basket route-ID exception; fewer findings alone cannot satisfy the gate.

The known development total for the smoke, previous producer and this producer
is five actual provider calls, 61,792 input and 2,537 output tokens. Charged
reservations total six because the earlier proven local pre-dispatch abort
retains its slot. Eight charged calls, 138,208 observed input and 11,463 output
tokens remain under the original proposed cumulative ceilings. The older pilot's
genuinely unobserved provider turn remains separate and unknown.

A proposed consumer-only phase can fit within those remaining ceilings with
four pooled calls per arm, 50,000 observed input and 4,000 output tokens per arm,
and a separately declared absolute wall deadline. The same native per-claim
ceiling still applies. If either arm cannot complete the deciding relationships
within the limit, report the comparison incomplete rather than treating the
cheaper partial result as a saving. Charge this producer's measured cost to each
comparison alternative, but count it once in actual experimental spend.
