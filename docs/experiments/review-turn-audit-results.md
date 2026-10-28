# Read-only turn audit AU

`scripts/review_workspace_audit.py` now joins saved provider tasks, immutable
working views, committed controller receipts, deciding lookups, recorded dispatch
offers and later observed claim flags. Markdown starts with a turn summary and
supports session focus; JSON retains the detailed evidence links. It reads SQLite
in read-only mode and does not execute historical controller code, a provider or
the target application. There are **zero new paid model calls**.

This implements the [next step after AT](../review-closure-and-evidence-plan.md#after-at).
It improves inspectability, not review decisions or demonstrated efficiency.
Artifacts: `C:/dmitry/scan-runs/workspace-turn-audit-20261028-au`.

## What the operator can inspect

- Active/offered IDs, each claim's selected source location, settled consumers,
  hidden consumers, and exact previous judgments indexed by digest. A judgment
  recovered from an earlier receipt is distinguished from one delivered to the
  model in that turn.
- The questions, qualified propositions and caller applicability actually
  presented. Conditions and exclusions remain unchanged. Previous judgments and
  reviewer notes remain interpretations, not automatic confirmation.
- The requested deciding question and query purpose, charged units, returned
  navigation/limits/feedback or addressed source metadata, captured evidence,
  reuse receipts and later views containing the lookup. Later same-question
  answers show exact evidence-ID intersections; this is an explicit link, not
  proof that a lookup caused a verdict.
- Committed answer changes, decisions and draft dependencies, including local
  resolution of a shared question. An uncommitted `answer.json` is not treated as
  an accepted result.
- Prepared aggregate budgets separately from saved dispatch offers and observed
  usage. A prepared task's zero research remainder is not substituted for actual
  dispatch credit. Missing or unknown usage is not free credit.
- Remaining active claims and reconsideration flags from the next same-work
  prepared view or final snapshot, with revision and intervening receipt records.
  A later observation is not labeled an immediate post-response state.

The tool checks stored view digests and attached task/context/fact hashes. It
does not include append-only bridge traces in that immutable-artifact check and
does not need AT's ad hoc live monkeypatch observer. Current captured-file hashes
are reported separately: stale or unavailable source does not erase historical
judgments, and a current captured file does not certify the whole snapshot or
runtime. No call permission, native state admission or historical recertification
is granted.

## Replay results

| Record | Turns | What the audit establishes |
| --- | ---: | --- |
| AR raw Terra workspace | 6 | Last task offers profile/erasure only; both old image consumers are hidden. The final recorded state flags exactly those two for `question:q-cookie-controls`, with no further round offered |
| AS historical projection | 1 diagnostic | Four IDs are offered and match its saved diagnostic schema; both previous image judgments are exact. There is no bound session, reviewer action, dispatch or resulting decision |
| AT fresh completion | 4 | Two authorization judgments close before all four cookie judgments close together. No consumer is offered and no claim remains active |
| Fresh deterministic native-bound fixture | 1 fake-adapter turn | Prior consumer is delivered and explicitly reconfirmed with the active claim; recorded remaining work is empty and ordinary native finalization passes |

Old public session artifacts do **not** attach their actual output schema. The
audit labels that gap and reports the attached task's decision-authority IDs;
it never runs today's schema builder and claims to have recovered the historical
enum. AS's separately saved schema remains diagnostic authority only. Similarly,
saved dispatch records are outside the prepared artifact hash binding and are
labeled as recorded observations.

All three archive/API reports match their CLI JSON output, including focus on
AR's actual sixth turn. Both historical workspace databases remain byte-identical.
All **1,630 AR, 30 AS and 179 AT closed files** remain unchanged. Captured-file
checks cover 13 AR files, 13 AS files and 12 AT files; these checks do not run an
application or reconstruct missing source.

## Verification and decision

**14 tests pass**, including the fresh native-bound fake-reviewer fixture. Cases
cover hidden versus delivered consumers, omitted confirmation, unknown credit,
uncommitted output, source staleness, provider artifact tampering, receipt gaps,
lookup/evidence links, next-view observation boundaries, runtime trace appends,
unsafe source paths, diagnostic eligibility and focused Markdown qualifications.
The commands, logs, replay reports and archive checks are in `verify.py`,
`tests.txt` and `verification.json`. No production controller, adapter, schema,
budget or engine default changes in this slice.

Keep native default batching for complete local SQL/parser/API questions and
qualified workspace state for compatible relationship work. Keep addressed
source for the relationship citation problem already observed. AU gives the
operator a reproducible way to inspect future failures and useful continuations
without another model-maintained progress inventory.

Stop this implementation at the verified read-only audit. The next useful work
is offline selection of a genuinely different rule/caller family from available
inventories, with its default native packets inspected first. Produce a concrete
source-bound question or record why no eligible coherent slice exists. A new
paid run, generic grouping engine, larger budget or additional memory subsystem
does not follow automatically from this tooling improvement.
