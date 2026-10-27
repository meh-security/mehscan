# Directus file deletion AD: shared enforcement, separate scope

Status: pre-dispatch design after [checkout completion AC](review-workspace-checkout-completion-results.md).
This is a fresh two-claim comparison on another real implementation. It does not
resume R or spend any unused prior allowance. Runtime, reviewer guidance and action
schema stay unchanged. Preserve all supported earlier cases and costs.

## Selection and the pre-audit correction

Use the saved Directus source at
`C:/dmitry/scan-runs/directus-review-source-20261023`, repository key
`evaluation:directus`, fingerprint
`review-sources-v1-dd8e919b18edb6952d521d6aad95b439faac593534362545ab6ab28178ef619a`.

| Actual native claim | Selected HTTP operation | Independent deciding work |
| --- | --- | --- |
| `observation-review-febf2c4abc4f1c48` | `api/src/controllers/files.ts:347`, DELETE `/:pk` | Caller accountability → `deleteOne` → overridden `deleteMany` → item delete permission → database and storage effects |
| `observation-review-92fdeebb392a6ce8` | `api/src/controllers/files.ts:324`, DELETE `/` | Array/keys and sanitized-query branches → actual key selection → same deletion chain; query sanitization alone is not authorization |

Both share one implementation and HTTP accountability context. Native generation
already puts them in one two-claim authorization bucket at its ordinary maximum
of **20**. This comparison tests complete review packages, not grouping versus
singleton review, and is not a mixed-rule or full-app acceptance test.

**Red flag in treating this pair as clean negative controls:** `FilesService`
fetches metadata for the original keys before `super.deleteMany`. The parent
validates and deletes `keysAfterHooks`, but storage deletion iterates the original
metadata. `Emitter.emitFilter` permits a returned replacement payload; configured
filter flows can return one. Thus "the same resources are checked before every
effect" needs a key-set qualification. Do not quietly label both routes safe from
the service name or the presence of `validateAccess`.

The inspected ordinary path has affirmative enforcement: middleware constructs a
non-null accountability object even without a token, routes preserve it, both
wrappers dispatch through `FilesService.deleteMany`, and item delete permission
validation rejects before database mutation and before the awaited storage loop.
The permission implementation evaluates the requested action and item keys, not
merely collection membership. Admin/system authority is an explicit trust boundary.

Preserve two component judgments per claim rather than force an oracle label:

- The ordinary HTTP path with unchanged deletion keys has a source-supported
  authorization control. A scoped negative must show caller binding, key flow,
  denial behavior and both effects; it must state its applicable boundary.
- A key-changing hook can separate checked database keys from original storage
  targets. The snapshot does not establish an installed hook/flow producing an
  exploitable substitution. Precise `needs_review` naming that binding is valid;
  a conditional finding must establish the mismatch and state the configuration
  and authority conditions. A generic unauthenticated-deletion finding is not
  supported by the privileged metadata read alone. An unconditional dismissal of
  all physical deletion paths is not supported by the ordinary-path proof alone.

These are implementation-agent source judgments, not independent human truth.
If a reviewer presents a different mechanism, audit its evidence and conditions
instead of forcing agreement. Neighboring storage-prefix, credential and extension
administration concerns remain separately identified leads unless actually proved
for the selected action. No exhaustive audit of every service caller or extension.

## Matched inputs and execution

Primary: Sol medium ordinary native versus Sol medium workspace. Retain the
requested supplementary Terra 6.1 medium workspace arm. Use fresh stores and the
current archived runtime. Initial canonical source and bundle memberships must
match across all arms. Use ordinary preparation only: no carried source, evaluator
answer, retained proposition, deciding question or hook-specific prompt hint.
The evaluator audit and source copies stay outside reviewer packets.

Freeze source hashes, exact claim/property/sweep, native default membership,
initial source parity, model/medium/CLI descriptors, package/provider bindings,
runner scripts and this plan before any paid call. Verify unchanged runtime against
AC and retain its passing 138-test receipt; no production code change calls for
another full test run. Preparation/preflight uses zero inference calls.

Run serially: Sol native, Terra workspace, Sol workspace. Each matched bundle has
six calls including corrections, 24 query units, 512 KiB received JSON and 900
seconds; dataset/arm ceilings are 1,800 seconds, 3M input and 100K output. Effective
aggregate ceiling is eighteen calls. Control admits only into its fresh private
study store; workspace finalizes without admission. No target execution, builds,
installation, publication or changes to the Directus source.

## Evaluation, stopping and what follows

Trace the stated deciding question, returned source, remaining relationship and
decision. Count how often shared service/permission source is requested or replayed,
whether the second claim reuses it, and whether single/batch/query differences
survive. Record actual input/cache/output, calls, model/active/preparation time,
controller checks and lookup spending. Byte/token reductions are descriptive.
No latency/model ranking is justified by shallower or incomplete proof.

Close an observed failed arm without repair. Independent frozen arms may continue
only while global bindings match. Unknown usage blocks the affected model/workflow;
changed global binding stops the study. Preserve formal validation separately from
semantic source coverage, partial success separately from missing proof, and all
failed spending. Unused slots authorize neither a repair nor another selection.

Do not expand because labels agree. A qualified ordinary-path proof, actionable
hook uncertainty and a source-supported conditional mechanism are different
outcomes. Stop broadening if supported enforcement is lost, assumptions are hidden,
or controller behavior fails; correct only that observed boundary offline. If the
pair completes adequately, reassess evidence across SQL/local closure, conditional
policy and real shared authorization before choosing a small diverse package.
The other twelve R-main claims and eight reserves stay outside AD, and R's original
execution stays closed. No full-app rerun follows automatically.
