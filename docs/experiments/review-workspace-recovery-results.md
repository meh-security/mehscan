# Shared API policy recovery — partial recovery

Status: **closed; verdict recovery, incomplete evidence recovery**. Five claims
were reviewed in both arms, using 26 accounted provider calls. All ten dispositions
passed native source validation. Both arms returned three findings, one scoped
negative and one actionable unresolved contract. Unsafe controls were not dismissed.
The stricter source-quality gate in the [frozen plan](review-workspace-recovery-plan.md)
does **not** pass: the workspace's SDK finding does not establish the caller binding
required by that plan. No mixed main wave or full application was dispatched.

## What ran

Fresh study: `C:/dmitry/scan-runs/workspace-recovery-20261026-s`, with independent
private state/configuration under the corresponding `scan-private` directory.
Code/skill at `8699e5b` includes the shared-policy fix from `2a20b28`; study R stays
unchanged and closed. Source, scanner, complete package, provider configuration,
selection, evaluator expectations and execution order were bound before inference.

The provider remained `gpt-6.1-sol`, medium, CLI `0.164.0-alpha.11.1`. Actual native
default batching (maximum 20) formed two singleton Directus bundles and one
three-claim sanitizer-control bundle. Workspace matched those memberships. Each
bundle retained six calls, 24 query units, 512 KiB received JSON and 900 seconds;
each dataset/arm had 1,800 seconds. The effective study ceiling was 36 calls.
Execution was serial: Directus workspace/native, then controls native/workspace.

Both Directus cases received exactly the same canonical initial source as study R.
No prior answer, finding, learned proposition or evaluator expectation entered a
reviewer packet. The shared semantic paragraph was restored; validation/navigation
code was unchanged. Aggregate limits and selected package population differ from R,
and this is one stochastic development regression, not isolated causal proof.

The controls are unchanged fixtures from the earlier dependency-contract trial,
admitted through current native IDs. They are known regressions, not unseen accuracy
data. Native completion records only into fresh private study stores; workspace
finalizes/reports without admission. No application/shared production state changed.

## Measured result

| Measurement | Native | Workspace |
| --- | ---: | ---: |
| Calls | 14 | 12 |
| Input tokens | 367,672 | 172,959 |
| Cached input | 0 | 0 |
| Output tokens | 6,300 | 6,246 |
| Measured review-call time | 212.690 s | 208.290 s |
| Active execution | 237.113 s | 270.133 s |
| Outside measured review calls | 24.423 s | 61.843 s |

Input falls 53.0%, but output is nearly unchanged and neither is the acceptance
criterion. Two fewer calls save only 4.400 seconds of measured review-call time;
active execution is **33.020 seconds slower** (13.9%). The three-claim controls
favor workspace (70.495 versus 85.335 seconds), while Directus favors native
(151.778 versus 199.638 seconds). This is not a timing distribution or whole-app
estimate.

Total paid work: **26 calls, 540,631 input, 12,546 output, zero cached input and
420.980 seconds measured review-call time**. Active execution totals 507.246 seconds.
Preparation measured around complete dataset preparation totals 32.014 seconds;
it excludes evaluator/implementation labor. No paid retry, repair, unknown usage,
controller failure or ceiling increase occurred.

Workspace again spends much of its overhead in full native freshness validation:

| Dataset | State/work calls | Measured validation |
| --- | ---: | ---: |
| Directus / nine reviewer turns | 77 | 46.038 s |
| Controls / three reviewer turns | 30 | 1.849 s |
| Total | 107 | 47.887 s |

These are non-overlapping native trace events after execution began, excluding
preparation. They explain much of the 61.843 seconds outside model calls. This
reproduces R's overhead diagnosis without changing the validation contract.

## Source audit

| Relationship | Native | Workspace | Assessment |
| --- | --- | --- | --- |
| Default YAML load | Scoped negative / four calls | Scoped negative / four calls | Actual import, default options and root catalog version retained; no executable constructors inferred, no resource/whole-operation certification. |
| SDK redirect scope | Finding / six calls | Finding / five calls | Conditional mechanism recovered, but workspace did not read SDK wiring or the catalog binding. |
| Unsafe DOMPurify hook | Finding | Finding | Actual after-sanitization addition of attacker-controlled onerror preserved; browser-policy conditions retained. |
| Local identity sanitizer | Finding | Finding | Actual relative helper returns input unchanged; not inferred from its name. |
| Unknown external sanitizer | Unresolved | Unresolved | External package resolution/implementation remains unknown; neither neighboring implementation is transferred to it. |

The final three rows share four native calls or three workspace calls. Do not
allocate the shared bundle's cost independently to each claim or treat partial
closure as additional saved investigations.

### The important remaining gap

Workspace reads the complete request generator, Axios factory, IP-validation agent,
IP policy and requested-scope schema. Its saved answer explicitly identifies
standard Node Axios redirects as reviewer inference. It correctly retains the
permitted-redirector precondition and separate IP denial. This is a real improvement
over R's unresolved contract demand; no exact vendored Axios implementation was
needed, and no unrestricted private-IP SSRF is asserted.

However, it closes its authority question without following the registration chain
from `requestGenerator` through `getSdk` to `instantiateSandboxSdk`. Its Axios
manifest read also stops at `catalog:` rather than the root catalog binding. The
final high-confidence finding asserts an extension capability without displaying
that application wiring. Native reads the registry, follows the returned consumer,
verifies requested-scope propagation into the isolate, and reads Axios 1.20.0 from
the root catalog before making the same conditional finding.

The missing version read is a delivery limitation, not a universal requirement for
exact-version implementation proof: investigate a version only where it matters to
the selected semantics. The missing SDK authority binding is the material gap in
this study's frozen source gate. A supported local conditional mechanism and a
verified application boundary should remain distinguishable. This audit does not
claim that the finding is false; the actual application wiring supports it. It
does show that matching verdicts alone would overstate recovery.

Workspace used nine query units for the SDK claim, below its 24-unit ceiling, and
closed on call five of six. Thus this is **not budget exhaustion**. Its saved
question becomes answered without resolving that relationship. Persistent answered
state is reviewer interpretation, not automatic evidence of completeness. Increasing
turn/query allowances is not the indicated correction.

## Accounting and validation

`study-freeze.json`, `execution.json`, `collected-results.json`, per-dataset
`workspace-question-trace.json`, raw provider metrics/answers and native finalizations
retain the evidence. `source-audit.json`, `quality-gate.json` and `study-closed.json`
record the evaluator decision separately from native validation. Original bindings,
packages and study R remain byte-identical; all attempted calls have observed usage.

An evaluator-only expected-label typo (`not_an_issue` instead of native `not_issue`)
was recorded in `evaluator-annotation-erratum.json` after dispatch began and before
source audit. The frozen text and committed plan clearly specify a scoped negative;
only that label is normalized during collection. Original expectations remain
unchanged. No reviewer input or runtime repair resulted.

No runtime code changed in this milestone. The previous 99 workspace tests and
adapter suite remain the offline implementation evidence, not newly rerun tests or
proof of recovery. New verification checks frozen hashes, source parity, metric
reconciliation and all ten native-validated dispositions.
`verification.json` also checks all 26 actual provider prompt artifacts: the shared
API policy appears in every fresh workspace prompt and each native conversation's
initial prompt. Native continuation prompts are deltas relying on preserved
history; they do not repeat the paragraph. Initial Directus source matches R.

## Correction to the next work

1. **Do not keep tuning the compact prompt on this SDK example.** API-policy delivery
   recovered a mechanism but did not recover the complete package. Retain ordinary
   native review as the operational reference. Distinguish a local implementation
   result from its required authority/caller applicability in review state; an
   answered question or finding label cannot silently stand for both. Test any
   correction with compatible and incompatible bindings, rather than another
   unmodified paid SDK retry or exhaustive caller discovery.
2. **Make controller execution cheaper before another broad workspace comparison.**
   Inspect checks around preparation, paid inference and lookup receipt capture.
   Consolidate only through a boundary that still validates source/owner/runtime
   before paid work and rejects stale paid answers with their usage retained. A
   native lookup currently checks work before source capture and the caller checks
   it again before recording the receipt. Removing either check blindly can change
   when stale evidence becomes persistent. Prove an equivalent staging/publication
   boundary and measure it offline before a fresh live freeze.

These are independent quality and execution tasks; finish each with explicit tests
and stop if its proposed change does not address the measured gap. More generic
memory, an AI planner, a CLI interface, greater budgets or another full-app run do
not answer either issue. The unreviewed sixteen mixed claims remain useful for the
next genuinely changed package comparison, with a fresh freeze after these tasks.
The successful mixed positive/unknown control bundle is encouraging, but three
fixture claims do not establish broad batching superiority.
