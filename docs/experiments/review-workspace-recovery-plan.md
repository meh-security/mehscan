# Shared API policy recovery check

Status: planned; fresh study S, separate from the closed failed study R. This is
a targeted regression check, not confirmation of whole-app efficiency.

The compact workspace prompt now receives the same established-API semantics as
the ordinary reviewer. Test that correction before changing validation, navigation,
budgets, grouping or model settings. The existing offline delivery tests passed;
they do not establish security-quality recovery.

## Cases and comparison

Use two source-pinned datasets, independently prepared native control and workspace
arms, and actual native default bundle membership (maximum 20). Match initial
source, source lookup availability and per-bundle limits: six model calls,
24 query units, 512 KiB received JSON and 900 seconds. Use the existing capable
model/settings, serial execution and fresh state, without prior judgments or facts.

| Dataset | Native claim | Evaluator expectation, withheld from reviewers |
| --- | --- | --- |
| Directus | `observation-review-febb44a92647e30b` | Conditional sandbox URL-scope bypass through redirects; establish SDK binding, initial URL check, Axios options and separate IP policy. Requires a usable permitted redirector; no unrestricted private-IP SSRF claim. |
| Directus | `observation-review-4d2d5dd2bbe9cd3c` | Scoped negative for default YAML load; verify actual parser/version/options, without certifying resource bounds or unrelated operations. |
| Existing contract controls | `review-aa6c9a45c0a1d4d1` | Finding: custom DOMPurify hook reintroduces attacker-controlled event attribute. |
| Existing contract controls | `review-8fef704cceae843f` | Finding: relative local helper named sanitize returns input unchanged. |
| Existing contract controls | `review-7ce493fa6ca24734` | Actionable uncertainty: external custom output policy has no available implementation contract. |

Controls use the unchanged source fixture from the earlier dependency-contract
trial, through current native candidate admission. These are known development
regressions, not unseen accuracy data. Do not fabricate a candidate for the custom
YAML loader's previous admission gap. No evaluator expectation or source-audit
answer is included in model tasks.

Run Directus treatment then control; run contract controls control then treatment.
Bind exact source, packages, provider configuration, execution order and evaluator
expectations before inference. Record effective bundle count/call ceiling after
native preparation. No automatic retry, repair, effort sweep or use of R's unused
allowance. Stop on controller failure, unknown usage or changed frozen inputs;
preserve all paid work. Close the study after both paired datasets and source audit.

## Decision

Pass only if both arms preserve the supported mechanisms and scope above, reject
neither unsafe control as safe, retain the genuinely unknown contract, and finish
with accounted usage and native source validation. A conditional issue must retain
its conditions. An unresolved answer is useful but does not recover a supported
classified finding. Source validation alone is not security correctness.

If the workspace still fails to follow the available SDK consumer edge, retain the
failure and inspect its question/lookup history; do not add another generic prompt
instruction or preload that edge as a paid repair. If it passes, this permits a
separate freeze of the unreviewed mixed batches after validation-overhead work. It
does not permit a full-app run or establish repeatability from one recovery.

Measure actual calls, input/output/cache, provider time, active execution and native
validation overhead; lower input is not an acceptance gate. Do not optimize the
255-check overhead inside this recovery experiment. Any later optimization needs
source/owner/runtime freshness and stale-paid-answer regression checks before its
own timing comparison.
