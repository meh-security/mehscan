# Sol stable-schema comparison — 2026-10-29

User requested “Add sol X2 for comparison”: two full Juice Shop arms, Sol 6.1 medium native and hybrid, launched in parallel. Compare with the completed Terra BK native and partial hybrid runs. This extends the comparison; it does not replace the targeted-completion plan.

Artifacts: `C:/dmitry/scan-runs/stable-full-sol-20261029-bl2`. Private execution state is separate. Both arms have 116 selected claims; native uses 25 original bundles, hybrid uses the saved 108-native/8-workspace routing. Source, initial source/question packets, prompts, stable schemas, local validators, runtime and original per-unit/component limits are held equal to BK. The workspace source-handle syntax fix is deliberately deferred so model and schema effects are not confounded.

Execution uses the existing stable runtime copy and fresh state. No aggregate three-minute or three-million-token cutoff. Native source validation remains validate-only. Known hybrid unit failures preserve receipts and accepted drafts, remain explicit gaps, and permit independent units to continue. Unknown usage or frozen-input drift stops affected dispatch. Failed evidence is not admitted, budgets are not reset, and only complete original bundles are finalized. The isolation overlay is study-only and tested before inference. Its elapsed-time receipt check uses the top-level metric.

Before paid calls: run existing native/workspace schema adapter checks, capture all 49 initial packets with dispatch blocked, compare exact source/question metadata against BK, test failure-isolation accounting, freeze inputs, and pass both runner checks. Existing unchanged protocol test results remain supporting evidence; do not rerun expensive unrelated suites merely for changing model configuration.

Measure actual input, cached input, output, cache writes, provider time, arm elapsed, failure/retry overhead, full-package price equivalents and source-validated coverage. Parallel arms may share cache routing; fresh sessions are not guaranteed cold cache. No synthetic cache warm-up.

Sol Standard API rates were rechecked against [official model documentation](https://developers.openai.com/api/docs/models/gpt-6.1-sol): $2/M input, $0.10/M cached input and $10/M output. Preserve nonzero/unknown cache-write counters and apply long-context adjustments if relevant. Rates are published equivalents, not invoices. Use the frozen rate file for comparable Codex credit equivalents.

Quality audit: compare all claim-level disagreements and consequential changes in mechanism, qualifications and evidence—not just labels. Include raw SQL, the mixed ORM controls/positives, NoSQL test-source contracts, CAPTCHA reuse, JWT version/expiry premises, registration fall-through, YAML consumers and unresolved writer-to-effect links. Compare all shared reviewed claims and show missing IDs separately. A partial package cannot win the complete-package cost ranking. Keep useful modes with their limitations rather than discarding either because of mixed results.

After both runs: reconcile raw receipts and local rejections, verify physical excerpts and frozen hashes, save the dated four-arm comparison, and return to targeted completion. Do not launch another full-app experiment automatically.

Offline BL preflight caught a copied Terra design overriding the Sol seed configuration. Zero calls were dispatched. BL is closed; BL2 rebuilds fresh bindings with Sol set in the design before preparation.
