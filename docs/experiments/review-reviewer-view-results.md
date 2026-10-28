# Reviewer navigation and source addresses AP

The experimental workspace Markdown/CLI view now shows existing closure
information without repeating shared questions and notes under every claim.
Six saved packages preserve all **52 original results and JSON package
identities**. This is a reviewer usability correction, not a new live result,
model-time saving, inferred qualification or corrected model citation.

Raw artifacts: `C:/dmitry/scan-runs/workspace-reviewer-view-20261028-ap`.
`audit-view.py` derives full/focused views and `verification.json` records original
package/DB hashes, output hashes, coverage, physical-source checks and timings.
No model calls, input/output tokens, native admission, old-session resumption,
target application execution or budget expansion occurs.

## Why this implementation

The exact selected native question already exists as each claim's `property`.
The package also retains original results, shared questions and latest reasons,
qualified notes, applicability judgments and source provenance. Adding a new
closure schema would duplicate that state without resolving a missing fact.

The previous Markdown repeated question and proposition text per claim. AP puts
those records once in linked sections, retains the full affected IDs and displays
the latest reason without truncation. Each claim still has its own unchanged
decision, summary, reason and complete remaining result fields. Per-claim
resolution remains distinct from a globally blocked shared question.

Notes retain revision, origin, scope, conditions, exclusions and evidence.
`context_only` exposure remains distinct from recorded caller applicability, whose
original reasons and evidence are displayed per caller. Free-form explanations
are not automatically classified into source findings or stronger impact chains.
An assumption absent from the original result remains absent; no evaluator
annotation is silently added to qualify generated-role findings.

The repeatable `review-package --format markdown --review-id ID` option focuses
on included claims. It keeps original claim numbers, discloses included-but-hidden
IDs separately from original package omissions, and retains the entire source
catalog. It changes no JSON scope, result, identity or workspace record. Unknown,
duplicate and JSON-mode focus requests fail. The CLI emits UTF-8, including on
Windows redirected output. See [usage](../review-workspace.md#reviewer-visible-package).

## Saved-state comparison

| Saved package | Claims | Questions / notes | Source records | Addressed rows |
| --- | ---: | ---: | ---: | ---: |
| AO Sol hybrid | 15 | 2 / 2 | 43 | 1,729 |
| AO Terra hybrid | 15 | 1 / 2 | 33 | 1,442 |
| AL Sol policy control | 3 | 1 / 1 | 9 | 58 |
| AL Terra policy control | 3 | 1 / 1 | 9 | 58 |
| AL Sol local/SQL peers | 8 | 0 / 1 | 16 | 459 |
| AL Terra local/SQL peers | 8 | 0 / 1 | 13 | 382 |
| Total | 52 | 5 / 9 | 123 | 4,128 |

Rows and source records count captured windows across packages, not unique
physical lines. Every source hash and complete captured line is checked against
the bound source. The one partial native fragment stays partial and matches its
physical source. Addressing preserves blank captured lines, Unicode separators
and lone CR; terminal EOF positions are not fabricated as source lines.

The product exporter regenerates each archived package exactly, including its
identity, and the focused CLI output matches the renderer. Each question, note
and source has one section, with valid internal links. Claim questions/results,
latest reasons, note qualifications and applicability reasons are checked for
literal preservation. Global status and individual resolution are checked
separately in deterministic fixtures.

AO Sol remains eight issues, three negatives and four unresolved results; Terra
remains twelve issues and three negatives, including its existing conditional
claims. Both AL policy packages retain one positive, one scoped negative and one
genuinely unresolved external policy. Both local/SQL packages keep four positives
and four negatives with no new deciding questions. This verifies presentation
fidelity, not independent security adjudication or an engine ranking.

All 668 AO closure-manifest files still match. All 703 files present in AO and
1,527 in AL at the start of this audit remain byte-identical afterward; no archive
output is overwritten. Only new AP views and receipts are written. The measured
audit took 2.686 seconds, including six projections, focused CLI subprocesses,
physical-source checks and archive hash comparisons. This is one local offline
measurement, not a model or human-review timing comparison.

## Caller evidence and remaining work

The correct registrations at `server.ts:427` (basket-item addition) and `:604`
(checkout) are present in broader source retained by both AO hybrid packages.
AP displays their actual addresses. The old, sometimes incorrect short caller
citation sets remain unchanged. Source availability does not certify that a
claim's selected excerpt proves its asserted relationship.

The focused AO views are still about 115/99 KB because the source catalog remains
available. Focus is navigation, not context reduction. No new source cache,
model-side fact reuse, avoided continuation or lower review cost is established.
The human renderer is not used by `codex_protocol.build_prompt` or the workspace
provider prompt; it cannot affect paid source selection.

The [corrected next plan](../review-closure-and-evidence-plan.md#next-bounded-slice-after-ap)
therefore targets opt-in addressed source in actual native/workspace initial and
continuation inputs. First verify exact source shapes, fragments, handles and
receipts offline. Only a later small frozen paired test should measure caller
citation selection and closure behavior. Another unchanged fifteen-claim speed
run would not test this implementation.

## Verification

47 distinct tests pass: ten package/view tests, 35 workspace state tests, one
native bootstrap/finalization integration and one mixed native/workspace assembly
integration. Compilation and whitespace checks pass. Checks include literal
fencing, UTF-8 CLI output, per-claim versus shared status, focus scope/identity,
source changes rejecting export, qualified context versus applicability, line
round trips, blank lines, fragments and terminal positions. Native integration
providers are deterministic fixtures; no paid calls occur.
