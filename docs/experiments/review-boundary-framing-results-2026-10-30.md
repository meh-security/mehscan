# Deciding-boundary framing — 2026-10-30

The bounded prompt/guidance correction passes offline delivery checks. The
shared prompt now separates a local implementation guarantee from deployed
caller exposure. Existing filesystem, SQL and authorization references explain
the category-specific stopping and promotion rules. **No inference, changed
verdicts or new provider spend.** Freeze this wording pending behavioral evidence.

This completes item 4 of the [latest hardening plan](../review-flow-hardening-plan-2026-10-30.md).
It does not make the [live acceptance package](review-orchard-acceptance-results-2026-10-30.md)
unattended-ready or establish that workspace's earlier benefit came from framing
alone. Mode, arrangement and the question changed together in that experiment.

## Audit and red flags

The old prompt already limited review to selected operations, allowed local
SQL closure and discouraged exhaustive transitive review. The references also
distinguished parameter binding from ownership, and authentication from
authorization. Replacing that workflow or adding another universal procedure
would repeat useful instructions without resolving the observed ambiguity.

Three gaps warranted correction:

| Gap | Why it matters | Targeted correction |
| --- | --- | --- |
| Local containment versus deployed exploit | Native had the resolver and normalizer, recognized the prefix defect, then kept investigating HTTP callers. That could withhold a supported local finding for an unrelated exposure gap. | Establish the actual promised root and operation; preserve root/platform/access/existence conditions. A local API defect need not prove an HTTP exploit. An arbitrary-path API or constrained operand does not inherit that defect. |
| SQL wrapper inventory and intentional grammar | The loaded SQL bucket asked for every relevant wrapper argument and callers outside that inventory. It did not explicitly separate trusted query authoring from values expected to remain data. This could cause repeated caller discovery or promote an intentional query capability. | Bind the selected query's value-versus-grammar contract and caller; expand only for a fact that could change that judgment. Missing actual templates/input authority remains a question, not a finding or a safe verdict. |
| Missing granular authorization check | General check-to-effect guidance did not spell out grant/denial composition. Treating a missing per-item check as a bypass can ignore a valid global grant or invent an active custom denial. | Establish the prohibited actor/resource/effect under actual permission composition. Trace applicable grants and denials; preserve a policy gap instead of promoting a bypass or clearing the endpoint. |

The edits preserve the opposite cases: a demonstrated local contract violation
can still be a conditional issue; source-established unsafe SQL value
construction can still be an issue with exposure uncertainty; a concrete
identity/check-to-effect mismatch can still be an authorization issue under
supported permission conditions. No deployed victim/account is universally
required. Complete parameter binding still settles that query's grammar question.

## Implementation and routing

- `codex_protocol.REVIEW_SCOPE` adds one stable 82-word/607-byte paragraph before
  source data. The workspace uses the same existing shared prefix. The native
  continuation path does not resend it.
- Detail stays in existing `references/buckets/resource-boundary.md`,
  `references/buckets/interpreted-input.md`, `references/buckets/authorization.md`
  and the SQL/file category guides. The existing skill routes still lead there.
  Manual review's chain step carries the same distinction.
- Existing guidance catalog descriptions now expose these deciding questions.
  The generated `references/worker-api.md` table was regenerated. No guide,
  tool, schema field, progress requirement, mode or automatic reviewer was added.
- Native uses its existing relevant bucket delivery; additional detail remains
  available through the existing `guidance` lookup. The compact workspace still
  uses its existing question/state and guidance delivery. No change to native
  engine contracts, the runtime-contract compiler or selection/grouping logic.

All instruction changes are generic. Application names, claim IDs, prior answers
and the following assessment notes occur only in this audit, not in the prompt
or guidance. A new prompt/reference binding requires fresh work; historical
conversations and the earlier candidate replay remain frozen.

## Source checks and countercases

These are reviewer assessment obligations, not labels supplied to a model and
not claims that the changed prompt has produced these outcomes.

| Saved case | Deciding source/relationship | Preserve during behavioral testing |
| --- | --- | --- |
| Copy source, copy destination, delete: `91f839f8922d7c05`, `eabc9cecdd946517`, `dff6d76d819b6158` (all prefixed `observation-review-`) | `FileSystemStore.cs:418–437` promises a designated root but compares a canonical target using a lexical prefix. `IFileStore.cs:209–217` replaces/trims separators rather than enforcing containment; copy/delete consume the resolved paths. | Separate conditional local findings with material root/platform/access/existence conditions. Do not demand an HTTP exploit to describe the local mechanism or transfer it to fixed-path effects. |
| Query template: `observation-review-e0cbebadef197e27` | `SqlQuerySource.cs:50–89` renders a selected template before parsing/executing with parameters. Query documentation at `src/docs/reference/modules/Queries/README.md:243–264` intentionally permits shape changes and requires bound parameters for user values. | Retain the actual template/input authority gap unless a value-boundary violation is shown. Do not call the whole query API injection, or certify all its templates safe. |
| Parameterized query: `observation-review-ddcf1da3ade9bc1e` | `IndexingTaskManager.cs:84–99` builds fixed predicates and binds their values. | Preserve local grammar closure; do not start caller discovery solely to prove that parameter binding is needed. |
| XML-RPC: `observation-review-22e4c91704149b68` | `MetaWeblogHandler.cs:224–251` requires null-resource EditContent before reading posts. `PermissionHandler.cs:17–28` grants from claims; `ContentTypeAuthorizationHandler.cs:20–45` retains prior grants and returns for null resources. | Missing per-item authorization is insufficient to prove a bypass without the relevant active denial/principal/resource. Keep unresolved policy and other branches distinct; do not infer endpoint safety. |
| Owner/publication: `observation-review-abef9b7f2da930ad` | `AdminController.cs:438–452` authorizes publication against the current user before creation/editor processing. The separately audited initialization and owner-editor flow establishes the conditional final-owner mismatch. | Keep the supported mechanism and permission conditions. If native still lacks the decisive initialization/handler evidence, preserve that exact question rather than inventing closure from framing alone. |
| Other scoped controls and client uncertainty | Unchanged dashboard, resized-cache, redirect, markup and receiver/configuration evidence in the 30-claim package. | A new paragraph must neither reopen complete local controls without cause nor turn absent authority/configuration into safety. |

Source semantics were checked against the frozen application, including the
normalizer, permission handlers, query documentation and bound-value control.
No target application was executed. These checks support the guidance rationale;
they do not substitute for an independent accuracy measurement.

## Offline delivery verification

Artifacts: `C:/dmitry/scan-runs/orchard-boundary-framing-20261030-ce`.
The full pre-edit skill/controller snapshot is retained under `before/`.
`audit.py` constructs before/after prompts in separate interpreter processes
using the actual saved source packets. It rebuilds only trusted reference
delivery for each side; native task envelopes/aliases are offline fixtures,
not dispatched historical tasks. Saved workspace task/context inputs are used
for the two follow-ups. No authentication is accessed and no launcher is used.

| Check | Result |
| --- | --- |
| Native coverage | All nine saved initial packets, all 30 claims |
| Workspace coverage | Filesystem and owner/publication follow-ups |
| Source evidence, claim IDs and bound/stable wire schemas | Identical before/after for all 11 prompt cases |
| Shared scope delivery | Exactly once in each initial prompt |
| Native continuation prompts | Byte-identical before/after; no scope repetition |
| Relevant extra guidance | Normal broker loading/delivery works; guides remain instructions rather than source proof |
| Initial native prompt bytes | +10,954 across nine bundles, including category/catalog edits |
| Initial workspace prompt bytes | +1,491 across two follow-ups |
| Historical public artifacts | All 469 files unchanged |
| Frozen hashes | 90 runtime files, 15 inputs and 12,872 source files verified |
| Provider calls and new provider spend | Zero / $0 |

`verification.json` records per-case sizes, evidence/schema hashes and all nine
changed skill-file hashes. `before-prompts/` and `after-prompts/` retain rendered
inputs. Bytes are not token or currency measurements. Unchanged continuation
construction is not evidence of fewer continuation calls or improved cache use.

Existing checks: **69 adapter tests completed with one optional skip; all 13
context tests passed** (81 passed, one skipped). The skill validator, generated
API documentation check, Python syntax and diff whitespace checks pass. The
initial context check correctly detected the stale generated guidance table;
it passes after regeneration. No tests merely asserting the new prose were added.

## Stop and next decision

Freeze guidance here. Keep cached native review and selective question-driven
workspace, source-bound reuse, candidate-only recovery and selective flow audit.
The prior package remains $0.934469 for 58 receipted review-provider attempts,
with extra unmetered coordination/source-audit work. This change does not reprice
it or establish a new quality/cost result.

The remaining behavioral question is specific: **does the framing package let
native retain conditional local findings without unnecessary exposure research,
while preventing unsupported SQL/authorization promotions and retaining useful
uncertainty?** If another live test is pursued, use one fresh native-only replay
of the same 30-claim/nine-bundle acceptance slice and neutral prepared evidence,
with the saved provider/profile/schema/source presentation and research limits.
Compare against the saved native outputs and claim-level audit. Do not regroup,
change model/selection/budget, rerun the full application or start another mode
matrix. Record all attempts, cached/uncached input, output, actual price and wall
time; cache/load differences limit causal price/time conclusions. Do not describe
native-only price as a new whole-package price.

Audit changed promotions/dismissals and lost mechanisms against actual source,
including the countercases above. Accept useful uncertainty where a genuine
deciding fact remains. Stop after the bounded result or an explicit failed-ID
accounting; do not add turns or rewrite prompts to force closure. Native and
workspace remain available if results are mixed. No new live run is queued by
this offline implementation, and clean unattended acceptance remains unpassed.
