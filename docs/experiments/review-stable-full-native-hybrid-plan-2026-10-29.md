# Full stable-schema native and hybrid test — 2026-10-29

Authorized after the 27-claim Terra slice showed 61.4% lower total price with stable schema, matching verdicts/severities and no local-schema rejection. Test both full review packages; keep the task source and review workflow otherwise frozen.

Study root: `C:/dmitry/scan-runs/stable-full-20261029-bk`.

## Arms

| Arm | Population | Review mode |
|---|---|---|
| Terra native stable | All 116 claims, 25 original bundles | Existing native review with stable per-conversation schema |
| Terra hybrid stable | All 116 claims, 24 units | Saved BG routing: 108 native claims in 23 units; 8 claims in one workspace group |

Run in parallel, one worker per arm, Terra 6.1 medium on the privately pinned `0.165.0-alpha.1.2` runtime. Same native scanner, source fingerprint, original bundle default maximum 20, source profiles, source presentation, instructions, lookup API and routing. Compare native with BI2 and hybrid with stored BG Terra hybrid. There is no fresh dynamic full-app control; model variation and shared provider routing limit causal claims from those historical comparisons.

All 49 initial native/hybrid packets must match the saved BG source and questions. Review-package coverage remains 116, not just the changed workspace subset. No evaluator-only dependency source, artificial cache warmups or new reviewer guidance. Fresh conversations are not assumed cold; parallel arms may share provider cache prefixes.

## Stable schema and unchanged authority

Native uses the already-tested unbound wire schema and validates against the exact current native schema locally. The workspace wire schema fixes the original eight-claim group, uses unconstrained handle strings, and keeps its structural lookup slots available. Local validation still uses the actual offered claim set, current inspected handles, current lookup availability and current decision count. Existing workspace envelope, state machine, question/revision/applicability, query-unit, source and finalization checks remain authoritative.

Workspace continues to use a fresh context each turn; do not convert it to conversation resumption in this test. Its cache potential differs from native. Record workspace costs and cache fractions separately so native savings cannot disguise a workspace miss. Fixing the wire's group scope does not authorize a response about a retired or otherwise unoffered claim.

Both hooks are installed inside the bound study skill before native preparation. The native command-binding guard is unchanged. Usage and continuation state are recorded before local validation, including rejected paid responses. Diagnostic logs do not match the provider-usage filename glob. The validator remains a frozen private experiment dependency, not a product packaging/default change.

## Limits and stops

Preserve original six-call, 24-query-unit, 512-KiB per-bundle/unit allowances and 900-second local deadlines, including hybrid component accounting. Preserve the existing global call/query/byte allowances. Remove aggregate input/output-token and elapsed-time censoring via the previously used execution-only overlay; no three-minute or three-million-token cutoff.

Unknown paid usage or frozen-input drift blocks further dispatch. No silent retries. Retain successful units and every failed/rejected call. An incomplete package is not priced as a complete winner. If failure needs a narrow repair, preserve the original attempt and distinguish its cost and authority from any separately recorded continuation. No native decision admission in this experiment.

## Offline readiness

Recheck native adapter invariants. Test workspace stable hash across narrowed claim sets, changed/missing proof handles and zero query allowance; valid partial decisions; rejected unoffered IDs, unknown evidence, exhausted lookups, privileged actions, duplicate decisions, no-op responses and same-claim lookup/decision conflicts. Confirm paid rejections retain usage and out-of-scope tasks fail before dispatch. Run relevant existing workspace protocol/action/consumer tests. Exercise all native dispatch boundaries with inference blocked and verify the real workspace state is still undispatched.

## Evaluation

Primary: supported mechanisms, wrong dismissals, actionable uncertainty and whole-package total price. Also report actual input/output, cache reads/writes, counterfactual same-usage price without cache discounts, provider time, review elapsed, local rejections and native finalization failures. Break down native versus workspace and initial versus continuation calls. Record wire/local schema hashes and exact raw receipt reconciliation.

Audit all changed verdicts and material qualifications, plus SQL/ORM clean controls omitted from the small slice. Retain the known JWT version/expiry and broad-verifier limitations; cache savings do not resolve them. Check exported citations against pinned source and unchanged native admitted work. A source-valid package is not a semantic gold score.

Keep multiple useful modes. Do not promote a default on price alone or discard a mode for an isolated repairable defect. After this broader cache validation, return to the dated targeted-completion plan rather than adding prompt or memory redesigns to this comparison.
