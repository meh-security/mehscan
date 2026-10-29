# Sol hybrid rerun after provider capacity failure

The user requested a rerun of Sol hybrid only. Leave Sol native, Terra native
and Terra hybrid unchanged. Preserve the stopped Sol hybrid attempt and account
for its 34 known calls, 82.75215 published Standard credit equivalents and one
invocation without a usage receipt separately from the fresh attempt.

The failed invocation's private provider rollout records `server_overloaded`:
"Selected model is at capacity. Please try a different model." The terminal
event is at 2026-10-29 02:08:34.836 UTC (October 28, 22:08:34 Toronto). It has no
assistant answer and no token-usage receipt. This establishes the reported
failure cause; it does not establish zero charge.

The Windows System log inspected for the surrounding two hours shows Modern
Standby exit at 02:14:40 UTC and entry at 02:15:20 UTC, after the failure. No
standby entry at the failure was observed. The evidence supports a provider
capacity failure; it does not support attributing that error to sleep.

Prepare a fresh, isolated Sol hybrid run under
`C:/dmitry/scan-runs/workspace-sol-hybrid-rerun-20261028-be`, with separate private
state. Reuse only frozen code, native questions, source selection and routing;
import no earlier verdicts, progress, research or provider sessions. The same
116 claims use 108 native reviews and one eight-claim workspace, for 24 units.
The prepared control state is for offline source/question parity only and is
not authorized for live review.

Keep `gpt-6.1-sol` at medium effort, addressed source, 144 KiB workspace context,
six calls/24 queries/512 KiB/900 seconds per investigation and original connected
bundle accounting. Keep aggregate call/query/byte ceilings, complete usage
accounting and source/provider fences. Apply the existing removal of aggregate
token/time cutoffs. No prompt, routing, memory or model tuning accompanies this
rerun. No additional study retry or model fallback is authorized; any original
controller retry remains within its frozen investigation allowance and is
included in usage.

Before payment, verify byte-identical reviewer/native code, fresh empty state,
all 49 actual offline packets, physical source coverage and initial source and
question parity with BC. Freeze the new runtime and bindings. Request Windows
idle-sleep prevention for the running process using `SetThreadExecutionState`;
release it on exit without changing global power settings. This does not
override an explicit user sleep action. Capture bounded failure diagnostics and
terminal provider error events without copying credentials or model/source text.

Judge quality using the original BD evaluator criteria, including conditions,
scoped negatives, useful uncertainty and distinct leads. Report new-run price
and cumulative development spending separately. A successful fresh run does
not erase the earlier failure, and partial hybrid packages are not complete-app
price comparisons.
