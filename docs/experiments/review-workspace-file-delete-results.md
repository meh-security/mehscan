# Directus file deletion AD: useful uncertainty, unfinished caller proof

Status: **closed after sixteen observed calls**. Both workspace models return
independent `needs_review` decisions for single and batch file deletion. Native
stops on a recoverable filter mistake that its old protocol-error allowlist no
longer recognizes. Keep its useful source analysis, both workspace partial proofs,
Terra's explicit hook uncertainty and every call's spending. This is neither a
complete authorization comparison nor evidence of an efficiency win.

The [frozen plan](review-workspace-file-delete-plan.md) is committed at `adc8070`.
No runtime, reviewer guidance, model schema or source-assistance change precedes
inference. The archived runtime exactly matches AC's corresponding files and
retains its 138-test receipt. Models are Sol and Terra 6.1, both medium, using CLI
`0.164.0-alpha.11.1`. Execution order is Sol native, Terra workspace, Sol workspace.

## The case selection needed a correction

Actual native IDs `observation-review-febf2c4abc4f1c48` and
`observation-review-92fdeebb392a6ce8` select DELETE `/:pk` and DELETE `/` in
`api/src/controllers/files.ts:347` and `:324`. They already share one native
authorization bucket at the ordinary maximum of **20**. This is a package/state
comparison, not a grouping-versus-singleton test. Initial source is exactly equal
across arms: **789 canonical bytes**, comprising the two complete route windows.
There is no carried source, evaluator hint, saved answer or initial question.

Pre-audit rejects the proposed interpretation as two clean negative controls.
`FilesService.deleteMany` fetches storage metadata for the original keys, awaits
parent deletion, then deletes objects from that metadata. Parent `ItemsService`
validates and deletes `keysAfterHooks`. The emitter allows a filter to replace its
payload; configured filter flows can return one. A checked post-hook key set
therefore does not universally establish authority over the original storage set.
The actual installed hook/flow state is absent from this source-only snapshot.

The ordinary path still has affirmative enforcement worth preserving. Authentication
precedes the `/files` mount (`app.ts:329,366`), constructs a non-null public/accepted
actor context, and passes it through the route and service constructor. Both
wrappers converge on file deletion; item delete authorization rejects denied
post-hook keys before database deletion, and awaited rejection stops the storage
loop. A qualified ordinary-path negative, a precise hook-binding uncertainty and
a source-supported conditional mechanism have distinct meanings. No label agreement
oracle was imposed. These are implementation-agent judgments, not independent
human truth; no target application or target tests were executed.

## Actual results and cost

| Arm | Calls | Input | Cached | Output | Model time | Active time | Formal decisions |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Sol native | 4 | 125,876 | 0 | 2,066 | 64.609 s | 73.856 s | None; filter failure |
| Terra medium workspace | 6 | 131,049 | 0 | 2,759 | 59.974 s | 97.649 s | Two `needs_review` |
| Sol workspace | 6 | 154,666 | 0 | 3,287 | 90.802 s | 124.830 s | Two `needs_review` |
| Total | 16 | 411,591 | 0 | 8,112 | 215.385 s | 296.335 s | Four unresolved |

All paid usage is observed; no paid repair or retry follows. Preparation adds
99.620 seconds, including the unused Terra control preparation, but excludes the
implementation agent's audit/planning labor. Six calls, 24 units and 512 KiB per
bundle were frozen ceilings, not targets or new allowances on failure.

Terra uses all 24 query units, including two directory/file filter errors returned
as bounded non-source feedback. Sol workspace uses only **13 of 24** units: it
runs out of six model turns, whose final-only sixth turn advertises zero new
lookups. Its wording about exhausted lookup allowance must not be interpreted as
natural exhaustion of the query-unit ceiling. Increasing that ceiling would not
address this run's limit.

Workspace state/work checks are **53 / 27.242 seconds** in Terra and
**48 / 24.623 seconds** in Sol. Together they consume 51.865 seconds; total
outside-model workspace time is 71.703 seconds. This remains material overhead,
but controller optimization would not supply the missing caller evidence.

The named sequence X + Z + AA + AB + AC + AD totals **82 observed calls,
1,678,799 input, zero cached input, 38,678 output, 1,143.009 seconds model time
and 1,396.580 seconds active execution**. It is not total project spending or one
matched trial. Token reductions remain descriptive, not acceptance gates.

## What the traces establish

**Native preserves useful investigation before failing.** It reads the controller,
file override, inherited wrappers, parent delete implementation, access validator,
authentication middleware and service constructor. Its fourth response explicitly
notes the original-versus-post-hook key distinction without assuming a deployed
rewriting hook. The next batch requests the missing app registration region,
accepted-token producer and item validator. The last request incorrectly names
`api/src/permissions/modules/validate-access` as a definition file path. Whole-batch
validation raises `ResearchFilterError` before any of those three reads executes.
There are no formal native verdicts; the failure is not a semantic label error.

**Terra retains actionable uncertainty.** One shared question serves both claims.
It inspects the single/query dispatch, file effect ordering, post-hook delete
validation, per-key denial/count logic and emitter replacement behavior. Its final
decisions distinguish the missing HTTP accountability source from the unestablished
installed key-changing hook. It does not convert the privileged metadata read into
a demonstrated bypass or dismiss the storage concern. Actual app/middleware and
constructor bindings remain unread, so this is a useful partial proof rather than
a complete ordinary-path review. Both calls and query units reach their ceilings.

**Sol workspace retains a local control but loses a final qualification.** Its
shared investigation inspects constructor binding, wrapper dispatch, access
rejection and the full item validator. It eventually locates the actual app and
authentication files but cannot read them on the final-only turn. Those paths are
present in the delivered final context; this is not demonstrated state loss.
Intermediate reasoning names post-hook database keys, but the final conclusions
do not retain the original-storage-key condition. Its two unresolved labels avoid
a wrong dismissal, while that omitted qualification remains an artifact-quality
gap. `blockers` is empty despite the unresolved relationship described in prose.

Neither workspace proves the full HTTP check-to-effect chain, exercises partial
claim closure, or naturally tests the narrowed/widened shared-question fixes.
Formal native validation of their four unresolved dispositions does not establish
four completed semantic reviews. Preserve AC/AA/X's supported mechanisms unchanged.

## Repeated work is not the only bottleneck

| Arm | Lookup receipts | Query units | Received JSON | Returned source | Repeated returned source lines |
| --- | ---: | ---: | ---: | ---: | ---: |
| Native | 12 | 18 | 58,390 B | 32,502 B | 0 |
| Terra workspace | 18 | 24 | 42,972 B | 13,195 B | 0 |
| Sol workspace | 13 | 13 | 69,412 B | 23,055 B | 0 |

Every returned source window matches the bound snapshot. Line repetition here
counts overlap across actual source lookup results within each arm; it excludes
initial snippets, navigation previews and source replay inside provider contexts.
It is not a claim of zero prompt repetition or a whole-app memory improvement.

Both workspaces share service research across their two claims without separate
conversations or duplicate source retrieval. Yet serial discovery, delayed caller
reads, typed-error handling and repeated validation still prevent a complete,
efficient package. Adding generic memory would target no demonstrated loss here.
Native's existing shared bundle is already the appropriate reference.

## Surgical correction and next directions

After closure, a real native/controller regression reproduces the failure offline.
The existing correction logic matched three old error strings; the structured
`ResearchFilterError` introduced for workspace feedback changed those messages.
The fix recognizes that exact exception type and returns its declared allowed
arguments through native's existing **one** bounded correction turn. It adds no
paid allowance, lookup execution, source authority or broad exception recovery.

The regression checks a valid sibling plus malformed directory definition: the
whole rejected batch remains unexecuted, one corrected definition uses its normal
two units and native admission succeeds. Repeating the mistake stops after two
charged model attempts. A separate path-escape case remains fatal with one attempt
and no feedback. Conflict-filter expectations now check structured feedback.
The original AD packages/results stay unchanged; this correction has no new live
result and must not be pooled with AD as a repaired run.

Post-closure verification covers **243 distinct tests: 242 pass, one is skipped**.
The initial aggregate run stalls after 103 completed outcomes and is interrupted.
The isolated next tiered-budget case passes on both frozen and corrected runtimes;
no persistent code regression is established. A bounded runner then passes the
remaining 139 checks, including all 138 workspace tests. This is segmented
verification, not one uninterrupted suite pass. Before/after regression logs,
both isolated logs and the final hash-bound receipt are retained separately.

Two practical directions follow:

1. Keep the implemented and verified bounded native recovery correction. Ordinary
   review and workspace should both remain usable at this API boundary. No unchanged
   paid AD retry is needed to establish the deterministic recovery contract.
2. Improve **deciding-source selection before inference**, using existing source
   preparation and verified native/workspace observations. For authorization,
   pair the actual caller binding with the shared effect and permission code;
   keep single/batch/query operands and key transformations explicit. Stage a
   source-only profile with hashes/provenance and measure its preparation cost;
   do not preload every file, import verdicts, or add a generic reminder paragraph.
   Compare matched source assistance honestly if it later enters a new live trial.

An unapplied `caller-source-profile-proposal.json` makes the second direction
reviewable: eight hash-bound windows, **12,168 canonical source bytes**. Five
windows are covered by actual AD native/workspace receipts; app registration,
default accountability and token-accountability source are three new windows
from the implementation-agent pre-audit. This is explicitly assistance, not wholly
reuse of facts already supplied to reviewers. The request carries source only,
with provenance separate from its neutral caption. It fits the existing eight-window
API, leaves permission helpers available for targeted lookup, and supplies no
deployed hook state. It has not been applied or tested by another model.

There is also a preparation red flag: this hand-selected profile benefits from a
completed implementation-agent source audit. It is an assisted control, not an
implemented automatic selection workflow. The offline readiness check must trace
each selection to native claim locations, prior source receipts or bounded new
binding discovery and account for that work. If assembling the profile requires
another full security investigation per claim, stop calling it a practical saving;
retain it only as a diagnostic of what context was missing.

Do not rerun the same pair merely to collect an omitted app read, increase budgets,
or expand on the strength of matching unresolved labels. The next action is an
offline profile/readiness audit; then select a small diverse package only if its
actual initial source resolves the known navigation gap while preserving genuine
configuration uncertainty. Twelve other R-main claims and eight reserves remain
outside this sequence. Full-app acceptance is still open.

Raw study: `C:/dmitry/scan-runs/workspace-file-delete-20261027-ad`, including frozen
inputs, requests, execution, metrics, traces, source-window verification and
component audit. Closure verifies **205 frozen artifacts**, unchanged AB/AC results,
all observed usage and source hashes. Post-closure code/tests are separate artifacts.
