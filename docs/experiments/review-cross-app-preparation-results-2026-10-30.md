# Cross-app source preparation comparison — 2026-10-30

Implemented an **opt-in, source-only preparation builder** and dispatched a
matched **72-claim slice in each of two concurrent arms**, covering NodeGoat,
Docmost, HedgeDoc, FlaskBB and PyGoat. The experiment finished with provider
failures: **91/144 assessments finalized; 34 claims completed in both arms**.
All 34 paired verdicts agree. This is useful partial evidence, not a completed
quality/price comparison or authorization to enable preparation by default.

## Implementation and workload

`scripts/review_source_profile.py` now builds the existing source-profile format
from native sweep leads. It reads bounded named declarations when discovery is
unambiguous and expands native operation-context ranges. Each bundle retains its
own claim IDs, inventory binding and whole-file hashes. Duplicate symbol lookups
within preparation are cached; source windows are reused without transferring
verdicts or assuming caller applicability. Unique names do not prove dispatch.

The implementation retains missing/ambiguous/oversized edges in a separate trace,
does not recursively discover callers, and adds no app names, expected answers,
guidance changes or automatic model invocation. Limits remain eight windows,
400 lines and 16 KiB per window, 64 KiB per bundle, with existing profile limits.
Oversized declarations remain unread. Expanded context ranges may stop at the
actual file end, recorded alongside the requested range. Changed source fails
normal worker profile validation.

The CLI is documented in [the worker guide](../review-worker.md). Default
preparation is unchanged. Five new regression tests plus four existing profile
tests pass, covering ambiguity, clipped discovery, changed source, caller/bundle
scope, outside-root paths, null native captures and end-of-file context ranges.
Both arms exercised normal native preparation, dispatch and partial finalization.

| App | Value-eligible claims selected | Ordinary finalized | Prepared finalized |
| --- | ---: | ---: | ---: |
| NodeGoat | 8 | 6 | 6 |
| Docmost | 20 | 13 | 15 |
| HedgeDoc | 16 | 6 | 6 |
| FlaskBB | 16 | 5 | 13 |
| PyGoat | 12 | 12 | 9 |
| **Total** | **72** | **42** | **49** |

Selection was frozen before inference, balancing capabilities and source files,
with six explicit NodeGoat controls. All selected IDs pass actual Value selection.
Out-of-slice claims are experiment exclusions, not new Value deferrals. Saved
applications are not unseen holdouts, and source-file diversity is not proof of
independent implementation families. No claim of formal held-out accuracy is made.

Both arms use the same current optimized engine, Terra 6.1 medium, stable schemas,
line-addressed source, prompt text, IDs, 29 native bundles and research limits.
There are at most six simultaneous provider calls per arm, twelve combined.
Each investigation has six total calls, 24 query units, 512 KiB and 900 seconds;
there is no global three-minute cutoff. Isolated package paths and derived
contract IDs differ; actual guidance content and hashes match.

Preparation changes initial source in **17/29 bundles**. The other 12 are
unchanged-source controls. The builder returns 51 windows across the five apps;
only three named helper lookups identify a unique declaration. Fifteen helper
lookups remain ambiguous or missing. Most supplied evidence is expanded operation
context, not the missing credential/policy implementation. Extra native preparation
queries and source are work even though they incur no reviewer-provider charge.

## Provider failures and accounting

There are **181 offered attempts / 166 usage receipts / 15 unknown attempts**.
Every unknown attempt has retained stderr reporting repeated HTTP 403 Forbidden
from the Codex websocket endpoint. This occurred in both arms; later independent
work also completed successfully. Cause is not established as concurrency, sleep,
prompt content or account policy. No transport workaround, automatic retry of the
affected bundle, budget reset or fabricated zero-usage receipt was used.

| Measurement | Ordinary | Prepared |
| --- | ---: | ---: |
| Offered attempts | 94 | 87 |
| Receipted attempts | 87 | 79 |
| Unknown attempts | 7 | 8 |
| Known API-equivalent price, lower bound | $1.253547 | $1.219121 |
| Run wall through final source validation | 204.394 s | 202.199 s |
| Final issue / negative / uncertain assessments | 11 / 17 / 14 | 11 / 20 / 18 |

The combined known price is **at least $2.472668**; total price is incomplete.
Known usage is 5,092,035 input tokens, including 3,228,928 cached (63.4%), and
89,623 output tokens. Unknown usage is excluded from those denominators, not
assumed zero. Rates come from the frozen Standard API rate basis; these are not
invoices. Coordinator/source-audit effort remains unmetered. Run wall is not the
full implementation/preparation/audit time, and aggregate outcome counts cannot
rank arms with different failed subsets.

All **4,796 source-file hashes** and all frozen runtime/input bindings verify;
all **297 exported source excerpts** match exact source bytes. Each observed
usage event matches its unique metrics receipt. Checkouts remain clean; nothing
was admitted into native finding state or published upstream.

## What the surviving comparison says

Eighteen bundles containing 34 claims completed in both arms: **10 issues,
13 negatives and 11 uncertainties**, with no verdict disagreements. Twenty-four
of these claims have changed initial source; ten have identical initial source.
Mechanism and qualification text still differ, so agreement is not an accuracy
score.

| Fully completed paired subset | Ordinary calls / price | Prepared calls / price |
| --- | ---: | ---: |
| Changed initial source, 24 claims | 33 / $0.495534 | 28 / $0.466651 |
| Identical initial source, 10 claims | 24 / $0.283294 | 25 / $0.292764 |

Changed-source survivors use five fewer calls and about 5.8% less provider cost,
with input falling from 1,034,218 to 915,063 tokens. This is a modest descriptive
signal: provider failures select the surviving subset, samples are single runs,
and cache/provider load is shared. The unchanged-source differences show ordinary
run variability. Do not project this percentage to all 72 claims or the apps.

Source/flow review of the surviving controls and negative explanations retains:

- NodeGoat contribution identity mutation and benefits authority violations in
  both arms, with own-profile closure. The two new Mongo/signup controls affected
  by provider failures remain untested in this comparison; earlier results stand.
- Python fixed SQL versus interpolated login SQL, typed/quoted SQL identifiers,
  direct request evaluation, both pickle consumers, fixed configured health
  destinations versus caller-selected server fetches. Preserve deployment and
  selected-operation qualifications.
- HedgeDoc owner-scoped token deletion, session-local pending-state cleanup and
  upload-or-linked-note-owner media deletion. Default js-yaml decoding remains a
  scoped executable-deserialization negative, not a resource-safety certificate.
- PyGoat's title-setting script now closes negative in both arms while preserving
  possible syntax disruption. Its initial source is unchanged between arms;
  this cannot be credited to the preparation change. The inspected title assignment
  does not establish arbitrary execution or alteration of the fixed download link.

For external API assumptions, the audit checked the pinned js-yaml documentation
and standard SQLAlchemy identifier contracts, not installed dependency bytes:
[js-yaml 5.4.1 usage](https://github.com/nodeca/js-yaml/blob/5.4.1/docs/usage.md),
[SQLAlchemy identifier quoting](https://docs.sqlalchemy.org/en/20/core/internals.html#sqlalchemy.sql.compiler.IdentifierPreparer.quote).
This is a bounded source/flow audit, not a complete independent precision/recall
assessment of all attempted or historical claims.

One **unpaired** prepared Docmost result, `observation-review-c643d062f6f03cdf`,
identifies raw page-title interpolation into a downloaded HTML document. The
source audit confirms the string-only title DTO, authorized edit path, direct
title persistence, unchanged `getPageTitle` return, HTML interpolation and
attachment response. Retain the conditional active-content construction when a
reader opens an export of a writer-controlled title. Do not label it same-origin
application XSS or claim a deployed victim path. Ordinary review failed on its
bundle, so there is no matched evidence that preparation caused this finding.

## Corrected direction

**Keep the opt-in builder and its provenance/validation tests; do not enable it
globally.** The paired subset offers modest efficiency evidence without lost
verdicts, but does not close the main relationship gaps.

All eight paired Docmost questions remain uncertain despite fuller operation
source. Their repeated missing relationships are JWT subject/workspace binding,
page-permission enforcement and queued import effect scope. HedgeDoc's public
alias/note questions still need token acceptance and effective permissions. The
next improvement must retrieve the **actual deciding dependency**, rather than
expanding more neighboring controller text or appending more prompt rules.

1. Retain current native/local and selective-workspace modes. Reuse exact source
   with hashes; keep interpreted facts conditional on each caller.
2. Improve binding/navigation from actual import, receiver/provider and registered
   credential implementation. Ambiguous names remain unresolved. Test generic
   same-name/different-module, different-caller, override and stale-source cases
   before adding any new automatic traversal.
3. Keep TypeScript grammar failures separate; do not silently skip the failed
   page-permission repository or guess built workspace exports. Python rendering
   contracts need their own representative cases, not TS-specific fixes.
4. Preserve this incomplete run. A later recovery test needs explicit attempt
   lineage, the original unknown costs and the same frozen selection; never reset
   an old attempt or advertise a complete price comparison while receipts are
   missing. No further provider dispatch is queued here.

The broad test supplied useful partial evidence but **did not pass the planned
complete comparison gate**. The provider incident is a blocker to that gate;
the lack of new paired semantic closures is a separate product lesson.

Artifacts: `C:/dmitry/scan-runs/cross-app-preparation-20261030-ct`:
`comparison.json`, `claim-comparison.json`, `matched-bundle-metrics.json`,
`selection.json`, `comparison-plan.json`, initial parity data and each arm's
immutable worker/receipt/preparation traces. Earlier `...-cr` and `...-cs`
preflights are preserved with zero model calls: null native captures, native
context beyond EOF, and an overly strict absolute-package contract comparison
were corrected before paid dispatch.
