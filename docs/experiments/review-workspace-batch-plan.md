# Native buckets versus persistent batches — frozen comparison

Status: [closed after the safety wave failed its source-quality gate](review-workspace-batch-results.md).
Eight paired claims completed in 62 observed provider calls. The sixteen main
claims and eight reserved claims received no model review. The original design
below is preserved; its unused allowance is not an automatic recovery budget.
This is the broader package test
following the [work-formation diagnostic](review-work-formation-results.md), not
another helper-only or singleton/group-count comparison.

Selection is in [review-workspace-batch-cases.json](review-workspace-batch-cases.json).
All 24 selected IDs and eight reserved IDs are outside both workspace development
slices. Some have appeared in earlier source/policy audits; they are not globally
unseen cases. The two source inventories do not supply a safe parameterized SQL
candidate, so this comparison makes no balanced-SQL or whole-app accuracy claim.

Artifacts: `C:/dmitry/scan-runs/workspace-batch-comparison-20261026-r`, with private
provider configs/ownership/stores under its matching `C:/dmitry/scan-private`
directory. Each application/wave has fresh, independent state for both arms and
a complete frozen package. Provider: `gpt-6.1-sol`, medium effort, the previously
bound CLI version. Source, scanner, skill, adapter/controller code, provider inputs,
exact selection and source parity are bound before dispatch.

## Arms and fairness

Control runs the supported ordinary native worker with native rule-bucket
generation and its default maximum of **20 reviews**. No `--max-reviews 1` is
passed. Treatment uses exactly the same generated bundle memberships as workspace
work items: independent verdicts, partial closure, fresh source-bound contexts,
questions/propositions and available lookups. Unsupported sharing remains batched;
there is no separate AI planner or imported proposition/answer/finding.

Both arms receive identical canonical initial source per bundle, including native
application-policy preparation. Preparation checks the source union, membership
and file hashes. Control also checks its actual initial provider packet before
dispatch. Formatting, response contract, history/context replacement and state
handling differ: this tests complete packages, not an isolated memory effect.

Each corresponding bundle has six paid-call slots including any repair, 24 query
units, 512 KiB received lookup JSON and 900 seconds. Each application/wave arm
has a 2,400-second ceiling plus generous 3M input/100K output safety ceilings.
Caps are ceilings, not targets; token reductions are not acceptance gates.
Execution/research concurrency is one. The native worker's usual continuation
policy is retained; treatment's partial closures do not regain slots. Unknown
usage or a controller failure stops the affected run without paid repairs.

Generated bundle sizes match in both arms:

| Dataset | Claims | Native bucket sizes |
| --- | ---: | --- |
| Safety wave / Juice Shop | 4 | 1, 1, 1, 1 |
| Safety wave / Directus | 4 | 1, 1, 1, 1 |
| Main / Juice Shop | 8 | 3, 2, 1, 2 |
| Main / Directus | 8 | 1, 2, 3, 2 |

Native defaults do not mean every selection becomes one 20-claim packet; rule
buckets split these populations. The first wave checks reliability and source
quality. It cannot demonstrate benefits of multi-claim batching. Only the main
wave contains the larger matched batches.

Run order is serial and counterbalanced: safety Juice control then treatment;
safety Directus treatment then control; if the gate passes, main Juice treatment
then control and main Directus control then treatment. At most 192 paid calls
exist across the sixteen matched bundles/two arms, before tighter global limits.
No context reset, retry, split or finalization repair creates a new allowance.

Ordinary worker completion records decisions into its **fresh private study
store**. Treatment uses the same native finalizer/reporter without state admission.
Those post-inference bookkeeping differences are explicit; no production/shared
store, application or remote service is modified or published.

## Safety wave and evaluator audit

Juice cases: embedded JWT signing key, filename allowlist/null-byte transformation,
substring redirect allowlist and conditionally unsafe NoSQL construction. Directus
cases: default YAML parsing, sanitized detached-DOM assignment, extension-request
redirect scope, and signed/scoped password-reset mutation. Private evaluator
expectations and source bases are frozen before dispatch and withheld from both
reviewers. They are provisional source judgments, not independent human truth.

Assess mechanisms and conditions, not verdict agreement alone. In particular:

- Filename extension bypass is not unrestricted filesystem traversal.
- Conditional query grammar manipulation is not automatically Node host execution.
- Redirect scope bypass does not remove IP-address policy.
- A scoped parser/HTML negative does not certify an operation or deployment.
- Privileged password mutation can be authorized by a verified scoped token;
  `admin: true` is not itself proof of missing authorization.

After all eight paired safety cases, stop expansion for wrong dismissal,
unsupported finding/unsafe applicability, lost supported mechanism, unknown usage
or controller failure. Preserve all costs and source-adjudicate disagreements.
Do not silently repair and pool the run as one fixed-controller result. Precise
configuration/contract uncertainty remains actionable work, not a forced negative.

The main wave adds related order/resource effects, cookie settings, genuine
generated-resource contract uncertainty, shared parser implementations, response
context controls, and distinct single/batch deletion policies. Retain local
verdicts separately from adjacent operation mechanisms: finding, scoped negative,
unresolved question and unvalidated lead are different statuses.

## Accounting and readiness

Measure provider input/cached input/output, model time, active elapsed time,
lookups, repeated source, partial closures and complete ID/status coverage.
Include planning/preparation overhead and report cap-affected results separately.
The recorded preparation intervals use run-directory creation to frozen-binding
creation (filesystem timestamps), excluding pre-directory validation/final write
and evaluator/implementation labor; they are not complete end-to-end latency.
Source schema/native admission alone does not establish security correctness.

Readiness checks pass: 98 workspace tests, including three new matched-batch tests,
source-union/membership parity for all four datasets, and provider preflight with
zero inference. Tests use deterministic provider replies and cover native default
multi-member batches, actual ordinary worker/private admission, complete workspace
finalization/reporting and restart rejection. The dependency-receipt rendering
gap is fixed and tested in an actual provider packet before freezing this study.
