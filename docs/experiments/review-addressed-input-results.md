# Addressed provider input AQ

The native and workspace adapters now support opt-in `source_presentation:
"line-addressed-v1"`. It replaces displayed source text with physical line
addresses while retaining raw artifacts, handles, coordinates, qualifications,
receipts, cache keys, budgets and source validation. Default raw prompts remain
unchanged. This implements the model-input part of the [closure/evidence plan](../review-closure-and-evidence-plan.md).

All **57 saved prompts reconstruct exactly** in raw mode. Their addressed
projections recover the original source text and metadata, with 579 displayed
source records and 30,973 addressed rows checked against physical source. No model
calls, new verdicts, old-session resumption, target execution or budget expansion
occur. Better live citations, closure, actual input tokens and time remain untested.

Raw artifacts: `C:/dmitry/scan-runs/workspace-addressed-input-20261028-aq`.
The completed replay uses `prompts-v4/` and `verification-v4.json`; `replay.py`
preserves pre-change adapter copies, paired prompt text and archive/source checks.
Earlier partial and complete audit outputs remain with correction receipts.

## Source shapes and the correction

Native initial source lives in bound `primary.windows` and sweep source contexts.
Native continuation facts carry source results or a definition's actual source;
navigation-only definitions, reference previews and outlines remain navigation.
Workspace replacement contexts put captured source in `primary.windows` and carry
stripped lookup receipts plus reviewer state separately. There is no need to
recursively number every `text` field or rewrite questions/propositions.

The projection accepts only offered inspected-source handles and explicit known
source slots. It supports native/current source, prepared source, pinned base
source, native source contexts and actual definition source. A known source slot
with unsupported coordinates fails before inference. Source text is replaced in
the display copy, not appended as another full copy. A short format notice explains
the prefixes; existing result schemas and citation validators are unchanged.

The physical audit caught a real edge before any paid use. AL's native excerpt
of `lib/insecurity.ts` starts at line 41, column 1 and ends at line 42, column 1.
Its byte range contains the hash declaration and terminal LF, not the following
HMAC declaration. The first implementation labeled the empty terminal position
as line 42. The correction honors explicit byte/column ranges and preserves the
delimiter without numbering that position. Excerpts beginning or ending mid-line
remain explicitly partial, including when their native `truncated` flag is false.

Joined captures preserve final blank captured lines; raw query slices retain
their original terminal delimiters. Unicode line separators and lone CR are not
treated as physical newlines. No missing source lines or prefixes are invented.
Opt-in native decision-target selection uses the same physical-line semantics
and qualifies clipped target text. Raw-mode target behavior remains unchanged.

## Saved-turn comparison

| Saved inputs | Turns | Native continuations | Raw prompt bytes | Added bytes | Source records | Rows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| AO native, both models/arms | 24 | 16 | 1,405,384 | 104,942 | 208 | 13,674 |
| AO workspace, both models | 10 | 0 | 1,016,153 | 98,566 | 223 | 13,133 |
| AL native, saved turns | 14 | 3 | 573,495 | 26,115 | 74 | 2,890 |
| AL workspace, saved turns | 9 | 0 | 254,458 | 13,164 | 74 | 1,276 |
| Total | 57 | 19 | 3,249,490 | 242,787 | 579 | 30,973 |

Addressed prompts total 3,492,277 UTF-8 bytes: **7.47% more displayed bytes**.
These are not token counts, unique source sizes, conversation-history totals or
billing estimates. All existing repetition across packets and workspace contexts
remains counted. This change seeks better evidence selection; it is not another
source cache or a claim of reduced input. The one local complete replay took
1.975 seconds including reconstruction, paired output, physical checks and archive
hash comparisons; this is not model or human-review timing evidence.

Each raw prompt matches both the pre-change implementation and its exact saved
prompt. For workspace turns the task snapshot predates final `work_remaining`
allowance/time injection, so the audit reads that exact historical budget object
from the saved prompt. No value is inferred, granted or applied to old state.
Native continuation reconstruction preserves the original new-fact filtering and
receipts. Projection round trips restore the entire packet/fact objects exactly.

The actual caller registrations at `server.ts:427` and `:604` remain available
with their correct addresses in the relevant saved source. Original paid answers
and their sometimes incorrect short excerpts remain unchanged. An addressed
registration is available evidence, not automatic proof of a selected claim.

The replay includes AO's local fixed redirects and conditional cookie findings,
AL's SQL positives and scoped local negatives, Directus source and the unavailable external
policy fixture. Questions, interpretations, conditions, exclusions, guidance and
navigation records remain unchanged. There is no new mandatory caller lookup for
a complete local negative and no conversion of an unknown policy into a finding.

## Binding, controls and verification

The configuration field accepts only `raw` or `line-addressed-v1`. Omission keeps
raw mode. The full reviewer-configuration fingerprint still binds worker jobs;
the private adapter conversation additionally pins the selected mode. Raw and
addressed conversations cannot silently resume each other. Metrics disclose mode,
actual prompt bytes and the existing observed usage counters. The native provider
descriptor, default maximum 20, engine placement and source/query allowances are
unchanged. See [configuration](../codex-reviewer.md#configuration).

56 adapter tests pass, including eleven new presentation tests; one POSIX-only
launcher fixture is skipped on Windows. One native bootstrap/source-reuse/
finalization integration also passes with a deterministic provider. Compilation
and whitespace checks pass. Checks cover exact resume/new-fact behavior, mode
switch rejection, unsupported coordinates stopping before inference, partial
columns, byte endpoints, blank lines, Unicode/CRLF/lone CR, base/prepared source,
unchanged source/interpretation records and optional configuration validation.

AO's 668-file closure manifest still matches. Its 219 frozen files, fifteen bound
source files and four provider configs verify; AL's 603 frozen files, seventeen
source files and twelve configs verify. All 703/1,527 public archive files and
34/23 saved private prompt files remain unchanged after the final replay.

The initial audit guessed the Directus source-root location and failed; it now
reads each study's explicit source pin. A second audit rejected the byte-endpoint
projection described above, which prompted the code regression fix. A complete
intermediate replay matched all native prompts but omitted workspace's historical
runtime budget injection; the final reconstruction fixes that audit detail.
Those outputs and reasons remain separate, with zero paid repair calls.

The [next bounded test](../review-closure-and-evidence-plan.md#concrete-paired-test-preparation)
should hold engine placement/source constant and compare raw versus addressed
input on caller proof, related cookie questions and local/unresolved controls,
for Sol medium and Terra 6.1 medium. Keep supported mechanisms and useful
uncertainty if results differ. No unchanged fifteen-claim speed run, full-app
review, retrospective verdict repair or automatic reserve wave follows here.

AR preparation corrects a wording/scope risk: the saved Juice inventory has no
safe parameterized SQL candidate. AL's scoped ownership negatives do not provide
that control. The parameterized SQL state/source control remains offline; it is
not counted as a native or paid disposition in the new comparison.
