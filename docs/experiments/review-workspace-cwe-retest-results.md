# BF: CWE correction and completed Sol/Terra workspace retests

Both fresh eight-claim workspace retests completed. All sixteen outputs pass
native subset validation, all 48 exported source excerpts match their physical
UTF-8 byte ranges, and every new provider call has a usage receipt. No native
peer inference or full-app rerun was performed. The earlier incomplete hybrid
packages remain incomplete.

The correction is committed as `27b0846`; the
[precommitted plan](review-workspace-cwe-retest-plan.md) and artifacts are under
`C:/dmitry/scan-runs/workspace-cwe-repair-retest-20261029-bf`.

## What was corrected

The shared ordinary/workspace output schema now constrains CWE spelling and
count. The native validator still enforces distinctness and result semantics.
The ordinary worker can correct its exact CWE-format rejection using one
original remaining turn. Recovery validates a retained candidate before marking
it complete. There is no automatic CWE assignment, verdict conversion, extra
turn allowance, general native-error retry or model substitution.

Real native-validator tests pass for repair, interrupted-candidate recovery,
repeated-invalid-output rejection, unchanged citation repair, admission recovery
without provider replay, exhausted-budget recovery and the exact diagnostic
allowlist. Adapter and workspace schema suites pass, with one optional adapter
integration test skipped. No inference was used for these checks. The live
workspace runs did not emit malformed CWEs, so they do not independently exercise
the new repair path or establish its savings.

## Matched scope and observed price

Both models use medium effort, addressed source and the same original eight
claims. Fresh full-population preparation preserves the original available
context. Before payment, both actual workspace packets match BC's physical source
and exact native questions. Only the selected workspace is dispatched. The same
six-call, 24-query, 512 KiB, 900-second investigation allowance and 144 KiB context
apply. No aggregate token/time censor is present. No old judgments or sessions
are imported. The native executable and review prompt text are unchanged.

| Measurement | Sol workspace | Terra workspace |
| --- | ---: | ---: |
| Native-validated selected outcomes | 8/8 | 8/8 |
| Provider calls | 6 | 4 |
| Input tokens | 261,817 | 166,450 |
| Output tokens | 4,801 | 3,859 |
| Cached input / cache writes | 0 / 0 | 0 / 0 |
| Charged query units | 15 | 15 |
| Received lookup JSON bytes | 73,324 | 65,603 |
| Published Standard Codex credit equivalent | 14.291100 | 4.643625 |
| Published Standard API USD equivalent | $0.571644 | $0.185745 |
| Provider time | 128.233 s | 62.331 s |
| Active run time, including assembly | 158.013 s | 84.157 s |

Terra's observed inference-price equivalent is 67.5% lower on this slice. This
includes input and output; reasoning is not added again. All per-call input is
below the frozen long-context threshold. Prices use the October 28 Standard
rate basis, not an account invoice, subscription allocation or total operational
cost. Each fresh source-only preparation took about 95 seconds; preparation,
tests and adjudication are additional operational work. Concurrent timing is
secondary and is not a controlled serial speed benchmark.

The new pair totals 18.934725 Standard credits / $0.757389 API-rate equivalent.
The earlier stopped Sol hybrid attempts retain at least 112.999200 known Standard
credits plus one invocation without usage; they are additional spending. BB's
separate failed preparation/run cost also remains recorded. Do not subtract any
of that spending or price an incomplete hybrid as a completed full-app package.

## Quality and investigation audit

| Selected mechanism/control | Sol | Terra | Source audit |
| --- | --- | --- | --- |
| Request image URL reaches server fetch | High-severity issue | High-severity issue | Both retain unrestricted destination selection, post-request response checks and deployment-dependent internal reachability |
| Three fixed profile redirects | Three not-issues | Three not-issues | Each redirect uses trusted deployment `BASE_PATH` plus `/profile`; uploaded content, image URL and username do not select these destinations |
| Successful image update, fallback image update, username update and privacy-request creation | Four needs-review results | Four medium-severity conditional issues | Both preserve cookie authority, actual state writes, missing request-token/origin gating and cookie-delivery qualifications |

All eight selected results, including all four consequential disagreements and
the three local negative controls, were inspected. This is implementation-agent
source adjudication on a familiar development corpus, not independent gold.

Terra's package is more actionable for conditional source findings here. Its CSRF
reasons and impacts require delivery of an accepted cookie; one explicitly names
a suitably positioned same-site cross-origin attacker. It does not establish an
untrusted sibling origin or an exploitable deployed instance. SameSite governs
site relationships rather than origin equality, so the remaining browser/default
questions qualify applicability without disproving the shown server-side
mechanism. This inference agrees with
[MDN's SameSite definition](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Set-Cookie#samesitesamesite-value)
and [OWASP's SameSite limitations](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html#limitations-of-samesite).
Those evaluator-only references were not supplied to either model.

Sol retains useful uncertainty and makes no wrong safe dismissal of these
mechanisms. It traces the client cookie writer, default provider configuration
and a failed dependency-source lookup, then requires effective library/browser
delivery behavior to close all four claims. Its extra investigation did not
produce stronger conditional closure in this run. Preserve the four checks and
blockers; do not silently convert their original labels.

Both models reuse one cookie question across the four CSRF claims and record a
separate shared redirect proposition with deployment conditions. State sharing
works concretely here. The principal difference is the stopping/qualification
decision, not missing persistent state. Terra retains one adjacent SSRF lead
already represented by the selected fetch claim; count it as duplicate package
context, not another vulnerability. The two image-update branches also remain
separate scanner outcomes, not automatically distinct vulnerabilities.

## Practical direction

Keep Terra workspace as a promising option for these related conditional
relationships, with its applicability conditions visible. Keep Sol's conservative
mode and the native modes; this result does not rank all models or rule families.
SQL and other locally closed constructions retain the native direction.

Freeze further grouping/memory/prompt changes while auditing the saved full-app
native results and incomplete hybrid packages. A full-package completion needs
an explicit, source-bound handoff for corrected code and conserved prior budgets;
the existing recovery binding correctly rejects arbitrary controller/runtime
changes. Do not bypass that fence or repeat all completed native work. The BF
subset validation proves neither completion of those packages nor their total
price. No further paid run is scheduled by this result.
