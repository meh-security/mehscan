# App and AI review release readiness

Updated 2026-10-31. The release unit is the executable plus its matching security
skill, worker and adapter. The released version remains **0.8.0**; the Changed
workflow and finalized AI defaults described here are in the development source.
No new version, tag or publication has been created.

## Current product behavior

- The scanner runs locally without a model. AI review starts explicitly through
  the security skill or a configured worker. The Action remains native by default.
- Value is the ordinary AI profile: policy-based selection, explicit unreviewed
  deferrals and one configured reviewer. Comprehensive selects every admitted ID.
- Both worker profiles allow five research rounds (six total model calls),
  24 query units, 512 KiB and 900 seconds per investigation. Effective overrides
  are bound into the plan. A completed investigation may retain uncertainty.
- The bundled adapter defaults to stable schemas and addressed source. Native
  evidence validation, finalization, execution traces and usage/cache accounting
  remain active. Install the adapter's Python requirements before use.
- Detailed authority/token tables require `"boundary_checks": true`. They are
  optional diagnostics. Selective automatic second review, broad workspace routing
  and dependency preloading have not been promoted into the ordinary profile.

See [worker setup](review-worker.md), [adapter configuration](codex-reviewer.md),
[installation](installation.md) and [state/history](review-state.md).

## Acceptance completed locally

The installed 12-claim live package finalized 11 claims. One uncertainty draft
failed a mandatory auxiliary table citation check. Those detailed tables are now
opt-in; the ordinary source/evidence guards remain. A fresh six-claim targeted
retest completed normal admission in isolated acceptance state, retained two
complex authority findings and the own-profile/parameterized-SQL controls, and
preserved two explicit dependency questions.

All 49 calls across the two runs have receipts. Total frozen Standard API-equivalent
cost was $0.6127784; no provider 403s occurred. These are bounded development
results, not an invoice, general precision/recall estimate or proof that historical
intermittent provider failures are resolved. Some available helpers remain unread.

Development archives pass exact membership, scanner/report/finalization and
installed Changed-worker smoke checks. Focused native/profile checks and the
full adapter suite pass locally. CI records worker test classifications and
per-test durations while retaining all tests. These results do not substitute
for platform CI or acceptance of versioned optimized release assets.

## Remaining release gates

1. Run full CI against the final reviewed commit, including the minimum supported
   Rust version and supported operating systems. Verify both macOS release targets.
2. Choose the release version, build the optimized paired archives and verify
   installation, checksums, source pins and client compatibility from those exact
   assets. Confirm package documentation matches the chosen version.
3. Review the concise release notes and publish only after those gates pass.

Further app/model tournaments, automatic semantic verdict rewriting and a
universal second reviewer are not prerequisites for this release. Preserve
coverage boundaries, actionable uncertainty and explicit execution failures.
The experiment records and older acceptance history remain in repository history
and the repository's development plans/reports.

## Separate automation acceptance

Local skill/worker acceptance and real company-auth GitHub execution are distinct.
Before promoting unattended BYOK automation, use one pinned synthetic integration
repository and follow [GitHub acceptance setup](github-acceptance.md). Exercise
actual delivery, endpoint drift, cancellation, duplicate/late runs, missing/bad
auth and explicitly authorized manual fork review. Automatic forks remain native-only.
Existing local simulations do not certify real company-key or hosted acceptance.

JSON, Markdown and SARIF are advisory outputs. Automatic GHAS publication,
protected merge gates, hosted persistence and automatic fixes need separate work.
Successful execution or an empty SARIF does not establish security clearance.
