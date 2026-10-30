# Final experiment closure — 2026-10-29

BU completed the final planned serial/two-worker comparison on the same 13 JWT/authentication claims. Both arms received the same model, guidance, source, schema and budgets. The control paths keep independent groups separate; source or prompt routing was not changed to increase parallelism.

| Metric | Serial | Two workers |
| --- | ---: | ---: |
| Claims | 13 | 13 |
| Calls / reconciled receipts | 8 / 8 | 10 / 10 |
| API equivalent | $0.1305212 | $0.1671024 |
| Input / cached input / output | 305,500 / 219,904 / 6,786 | 385,956 / 268,288 / 7,204 |
| Cached fraction | 71.98% | 69.51% |
| Elapsed | 116.789s | 86.487s |
| Lookups | 32 | 38 |
| Observed peak active calls | 1 | 2 |

Two workers reduced elapsed by 25.9% and increased review price by 28.0%. The total study cost is $0.2976236 at frozen Standard equivalents, not invoice charges. All cache-write counters are zero. Both expiry explanations distinguish configured duration from emitted expiration. The only verdict difference is the quantity-delete case; both preserve the independent IP gate. Counts do not establish a quality ranking.

This single run does not isolate stochastic call-count differences from scheduling/cache effects. It does not meet the proposed 30%-faster/at-most-10%-extra-price promotion target. Keep one worker in the price-focused profile and two as an explicit speed option. Do not repeat the tournament to optimize this modest difference.

Artifacts: `C:/dmitry/scan-runs/concurrency-20261029-bu`, including `comparison-audit.json`, `claim-comparison.json`, `readiness.json` and `closure-audit.json`. Fake-provider checks verified unique reservations, retained receipts and peak one/two concurrency before dispatch. Raw usage/citations and frozen inputs reconcile afterward. All 223 cited ranges across arms were checked against supplied source. No native admission or live target execution occurred.

## Final integration

The normal adapter now supports opt-in `schema_mode=stable`, using pinned `jsonschema` requirements and exact local validation after paid usage persistence. Existing dynamic configurations remain compatible. Missing dependencies and mid-conversation mode changes fail before inference. Invalid stable handles are rejected with usage retained; diagnostics remain outside the usage-metrics glob. The reusable workspace format rejects navigation IDs while local offered-handle membership remains exact.

Launcher failures now preserve returned provider events/stderr privately instead of discarding them when no answer exists. Failure diagnostics do not fabricate a usage receipt or override provider controls.

Adapter/workspace protocol tests, release/context checks and the stable-adapter-to-native-finalizer integration passed. Product schemas replay 90 recorded native responses and four workspace replies successfully, while rejecting the old malformed navigation-ID response. Source-receipt reuse was separately verified by 17 evidence tests, 35 workspace tests, CLI packet checks and the completed two-consumer diagnostic. The exact integration evidence is in `product-replay-validation.json` and the repository tests.

The [final workflow](../review-workflow-final-2026-10-29.md) is the selected solution. The small experiment sequence is closed; no new paid experiment is queued. Automatic reviewer selection, external dependency resolution and cross-application precision are not claimed as solved by these experiments.
