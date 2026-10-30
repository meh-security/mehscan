# Source-evidence receipt reuse — 2026-10-29

Implemented an opt-in controller path to reuse an existing deciding-evidence receipt across work items in the same workspace. This extends `prepare-evidence` and existing evidence records; it does not add a generic memory store or another model stage.

The request identifies the source work/receipt, recipient work and recipient deciding question. The recipient record retains `reused_from` provenance. Source hashes and dependency metadata observations are checked on preparation and replay, and the recipient still needs its own caller applicability and conclusion. Writes use the existing atomic workspace transaction; identical operation retries replay, changed requests fail, and a bad later target rolls back earlier additions.

No propositions, answers, verdicts, applicability decisions, or model usage are copied. Existing source records remain deduplicated and do not consume source-storage budget twice. Independent reviewer contexts still receive their selected source, so their model input is counted normally. A fresh session is required after changing evidence. Model interpretation updates cannot invoke this controller operation.

The request format and limits are documented in [workspace evidence](../review-workspace-evidence.md#reuse-an-existing-deciding-evidence-receipt). The bridge's existing `prepare-evidence --evidence-request` entrypoint accepts the new version; no new model tool or native scheduling default is introduced.

Verification: 17 evidence tests pass, including source/dependency drift, changed retries, missing origins, transactional rollback, model privilege boundaries, budget deduplication and CLI-to-fresh-packet provenance. Another 35 workspace and 13 context/packaging tests pass. These are offline checks with no paid inference.

Limits: source must already be in this workspace's authorized root. This does not automatically resolve nested/installed/deployed dependencies, import external vendor snapshots, or infer consumer compatibility. The earlier JWT diagnostic supplied versioned external snapshots through a separate broker; its savings do not establish this new API's product performance. Existing notebooks remain the route for qualified model interpretations.

Next validation should use a fresh bound workspace with two relevant consumers: prepare the shared source for one, reuse its receipt for the other, then compare actual deciding lookups, model input/price and caller-specific outcomes. Freeze routing and prompts for that test. Keep bounded-concurrency evaluation separate so evidence reuse and scheduling effects can be assessed independently.
