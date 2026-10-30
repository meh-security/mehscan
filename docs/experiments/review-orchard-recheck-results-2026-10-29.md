# OrchardCore archive validation and rollout correction — 2026-10-29

**Keep Terra and both review modes. Do not promote the current package as an unattended CMS reviewer.** Shared implementation evidence recovered useful findings and clean controls, but the first pass overpromoted five security claims, left substantial avoidable uncertainty, and needed offline format recovery. The practical next work is specific evidence/validation hardening and selective finding review, not another universal model tournament.

All **537 first-pass claims** now have assembled, native source-validated results. The selected workspace follow-up exported **17 completed judgments**; three original remote-cache uncertainties remain. The measured price is **$4.5397108 known, plus one unpriced aborted provider attempt**. This is not a complete-price comparison. No findings were automatically admitted.

## Scope and comparability

- Archived source: `C:/dmitry/mehscan-internal/corpus-cache/apps/OrchardCore`. It has no own Git checkout; the ancestor workspace HEAD is not an Orchard revision.
- The main inventory contributes 415 claims in 31 native bundles. All marker continuation pages contribute another 48/48/26 claims in eight bundles, without repeating ordinary reviews: **537 unique claims, 39 bundles**, maximum 20 reviews per bundle. Twenty is the native default, not an improvement introduced by this experiment.
- Scan coverage: 9,448 discovered files, 7,167 scanned, 2,278 ignored, three parser failures. Parser recovery affected MediaPickerModal.vue, LogProvider.cs ranges, and a project-template Manifest.cs. Unresolved/ambiguous index edges also remain; these are not safe verdicts.
- Same frozen package as PyGoat: scanner SHA256 `6e85284b76bc41edf9c6d2e07fac59464db5cee552db91ca3305be0624903031`, Terra 6.1 medium, stable schema, line-addressed source, pinned CLI and trusted Python. This is a frozen-runtime test, not a claim that the latest Rust source was rebuilt.
- Each native bundle has five continuation rounds, 24 query units, 512 KiB and a 900-second conversation allowance. No aggregate three-minute/three-million-token cutoff. No target builds, restore, installation, execution or live probing.
- The main worker ran serially; a serial marker-page queue overlapped it, then the selected filesystem follow-up overlapped already completed portions of the main run. At most two model calls were active. This is not a controlled concurrency experiment.

Current source fingerprint: `review-sources-v1-d58e30d5bb194438cf27e353b116744f131ad9b0fbd80a9fdf4aa6227d63db9f`. All frozen source/runtime hashes were rechecked at completion.

## Measured price, cache and time

| Stage | Offered / receipted calls | Known input / cached input / output | Known API equivalent |
| --- | ---: | ---: | ---: |
| Full native first pass, including failed attempts | 167 / 167 | 9,306,557 / 6,464,896 / 211,991 | $4.2248608 |
| Selected filesystem follow-up, including rejection | 10 / 9 | 263,065 / 0 / 10,357 | $0.3148500 + one unpriced attempt |
| Whole package | 177 / 176 | 9,569,622 / 6,464,896 / 222,348 | **$4.5397108 + unknown** |

Native cached input is **69.466%**; the known whole package is **67.556%**. Cache reads occurred in 128 of 167 native calls; there were 39 first calls and 128 continuations. Workspace did not obtain cache reads in its nine receipted calls. Cache writes are verified zero for observed attempts. The same observed usage priced without the cache-read discount would be $10.681362; the arithmetic discount is $6.1416512. This is a same-usage calculation, not a second uncached run or a causal end-to-end saving.

Prices use the saved published Standard API basis: Terra input $1/M, cache reads $0.05/M, output $5/M, with applicable long-input multipliers. These are equivalents, not invoices. The aborted attempt has no returned usage counter and is neither estimated nor counted as zero.

The timed main review was **70 minutes 48 seconds**. The marker queue took about 21 minutes 15 seconds and overlapped it. The selected follow-up used 7 minutes 53 seconds initially, then 9 minutes 17 seconds for its final recovery attempt, also within the main review window. Preparation, coordinator source auditing and final export/verification are additional work, not included in the 70:48 figure.

The longest receipted native provider call was 317.352 seconds. Provider latency varied as well as local lookup time; no cache-induced latency saving is inferred.

**Timing qualification:** this frozen scanner is a debug binary. Across native runs, measured state/work operations accumulated 1,496.794 seconds and symbol lookups 805.905 seconds; these are operation totals across overlapping runs, not additive critical-path estimates. A read-only optimized-binary check returned the exact same 67-symbol `Permissions` response in 3.986 seconds versus 378.037 seconds in debug. Different executable artifacts and one equal response do not establish full runtime equivalence. Do not infer optimized production latency or an architectural bottleneck from this debug wall time.

Native delivery covered 358 source files and 421 file/conversation pairs. Verified physical lines repeated **1.155× across conversations** after deduplication within each conversation, before replay. Continuations still consumed **86.561% of native input**. These metrics exclude navigation previews and workspace, and are not directly comparable to a different application's historical source-repeat count. Cheap cached replay helps price; it does not prove investigation is balanced.

## Quality: preserve originals and audit the whole package

| Package | Scoped negative | Issue decision | Needs review |
| --- | ---: | ---: | ---: |
| Assembled first pass | 327 | 7 | 203 |
| With 17 accepted workspace judgments, before coordinator corrections | 332 | 19 | 186 |
| Audited diagnostic package | **343** | **14** | **180** |

The 14 retained issue decisions are **12 sites sharing one local containment defect, plus two conditional application flows**. They are not 14 independently demonstrated deployed vulnerabilities. No anonymous exploit, deployed permission combination, browser execution or live filesystem effect was tested.

### Supported mechanisms

**FileSystemStore: 12 sites, one shared implementation.** The native pass retained uncertainty across reads, enumeration, copy, move and deletion. Giving one investigation the constructor, private resolver and actual `IFileStore.NormalizePath` implementation settled all 12 in one model call. Normalization retains parent components; canonicalized paths are checked with a case-insensitive string prefix rather than a directory boundary. A root without a final separator can admit a matching sibling. The review keeps root shape, platform/case behavior, filesystem access and each operation's existence conditions explicit. This is a broken local containment contract, not proof that every HTTP caller exposes it.

**Create-and-publish owner change:** `observation-review-abef9b7f2da930ad`. Publishing is authorized against a synthetic requester-owned item. An enabled owner editor with EditContentOwner can change the actual owner before publication without the equivalent final-owner publish check. Retain the custom permission/editor conditions; the default author role does not supply that combination. This useful conditional mechanism was an old negative, not an independently revalidated old control.

**Workflow form-location redirect:** `observation-review-118ac0eccba8b7c3`. The HTTP event stores a submitted location; the configured redirect activity forwards it; URI serialization does not approve a destination. Keep enabled activities, endpoint token/antiforgery conditions and the earlier-result branch explicit.

### Rejected security promotions

**Dashboard layout:** `observation-review-eb93526f88623d37`. The action requires ManageAdminDashboard and changes layout fields. The module documents arranging widgets as authority granted by that permission. A different EditContent filter in the management view does not establish an unauthorized layout effect.

**Four build-tool shell sites:** `f26fa259997bcfb3`, `f4c738c2abc3e768`, `aa409a12cc5f9a15`, `2d317534b0567d41` (all `observation-review-` IDs). String interpolation and joined argument boundaries are real hardening observations. The supplied inputs are checked-in `.node-version` and local invocation arguments; the version-manager branch is interactive and CI mismatch exits earlier. No lower-trust input crossing into greater execution authority was established. Keep the observations; reject their promotion to application command-execution findings.

Thus **five of seven first-pass issue decisions require rejection or correction of their security promotion**. Evidence validation alone did not catch this. Do not turn this selected application's audit into a universal model precision estimate, and do not automatically accept the cheapest model's positives.

### Useful negative closure and remaining uncertainty

- Five resized-cache effects close under the actual SHA-256 key producer, fixed extension mapping, inspected middleware callers and temporary-file cleanup relationship. This is scoped pipeline closure, not a promise about arbitrary future callers.
- Six further coordinator closures cover two summary views and four title claims. The summary views import the MVC utility that decodes **before** stripping tags; the historically cited ContentManagement utility is different. Title generation preserves IHtmlContent behavior, ordinary Razor text is encoded, and both shipped Liquid search views set `search` to the translated fixed “Search” label. Variable spelling did not establish request input.
- Three remote-cache sites retain their original uncertainty after the failed follow-up. The unchecked join and provider entry handling need a concrete escaping entry/caller relationship; neither unsupported dismissal nor unconditional promotion is justified.
- Saved SQL template review retains the distinction between bound `@name` values and Liquid output rendered into grammar before parsing. Current documentation explicitly requires parameters for untrusted values. No deployed vulnerable saved template was identified; support for trusted query shaping alone is insufficient to label every query vulnerable.
- XML-RPC media creation retains a concrete permission question: it discards the password-validated principal before the inspected shared creation pipeline, while the normal upload checks media/folder permissions. Effective feature/policy and extension applicability remain explicit.

The remaining **180 uncertainties** include deployment questions and avoidable missing implementation evidence. They are not 180 safe decisions, nor automatically 180 model errors. Before follow-up, 167 of 175 uncertainties at an intermediate checkpoint mentioned budget/limit exhaustion; this was a text signal, not a semantic taxonomy. Broad family bundles can consume their lookup allowance before a later claim gets its deciding helper. More universal callers or more prompt rules would not fix that allocation reliably.

The coordinator audited all seven current positives, the 25 exact matched independently revalidated cases, the 17 completed workspace judgments, and a varied ten-case negative sample. This is not exhaustive certification of every negative or uncertainty.

## Historical comparison

The old Luna/coordinator run reviewed 468 Orchard IDs. Its original 26 issues / 437 negatives / five uncertainties became 22 issues / 446 negatives after selected source revalidation. Old run-specific token and price receipts are unavailable. Its two-app wall time includes coordination and other work; it is not a controlled timing or price baseline.

There are **331 exact ID/rule/path/line/kind/symbol matches**, including 25 independently revalidated cases. The other 137 old reviewed IDs remain unmapped or ambiguous. All 1,632 sources in the old semantic-input hash manifest match current bytes, covering the selected file for 209 matched claims. Saved decisive excerpts match at their original UTF-8 offsets for 329 matches; two have no excerpts. This strengthens the comparison without asserting complete archive/version equality.

Raw first-pass disagreements total 163: 157 are old labels becoming explicit uncertainty, and six are new positive decisions. The audit rejects five of those six promotions and retains the conditional owner/publish mechanism.

For the **25 previously independently revalidated matched cases**, the final audit retains 13 conditional positive sites, corrects two summary positives for actual current binding, confirms six scoped negative controls, and leaves four old positives actionable but unresolved (three remote-cache sites and SQL template applicability). Three older Directory.CreateDirectory positive sites are currently unadmitted by design, not dismissed by the model; other sites retain both containment relationships.

## Execution failures and recovery

1. **Five native bundles / 66 claims:** generated physical lines exceed the brief format's 4,000-character limit. Offline conversion to the existing full format preserved decisions and reason words, using exact byte/column spans. Two references were narrowed to complete, actually delivered selected-operation fragments of 46 and 719 characters rather than pretending the rest of their long lines had been read. Native validation accepted the results; no new model calls or source edits.
2. **One marker bundle / six claims:** local stable validation rejected a locator cited as source-only boundary proof. The unchanged verdict draft separately passed native validation. The adapter rejection and original failed worker status remain preserved; boundary metadata was not silently repaired.
3. **One workspace attempt:** an invented artifact handle was rejected. Its known spend remains included. The final permitted turn returned no answer/usage before the original investigation deadline and was stopped. Its private returned events contain no usage record. Three originals remain unresolved; the 17 completed judgments were exported without marking failed workspace work complete.

All four assembled first-pass packages pass native report validation. Original main/marker worker states remain incomplete where they failed; **72 first-pass claims required offline recovery**. This is a completed assembled diagnostic review, not a clean unattended execution success. Failed jobs did not discard other completed work.

## Corrected implementation milestones and stop gates

1. **Completed: preserve the evidence and evaluate the package.** The 537-claim base, 17 workspace amendments, 11 coordinator amendments, historical comparison, failures, receipts and explicit unknown spend are saved. Freeze this experiment; no further paid reruns are queued.
2. **Before rollout: repair the concrete output/recovery gaps.** Support inspected sub-line evidence through normal brief/full finalization; test oversized generated lines and bounded fragments. Preserve exact current-handle validation. An invalid handle may receive only a bounded correction with remaining allowance, not silent remapping or free budget. Export completed independent judgments when another claim in a bundle fails. Keep unavailable usage explicit. Stop if this requires relaxing evidence checks or losing original costs/results.
3. **Keep relationship-specific routing; improve deciding evidence preparation.** Native remains useful for complete SQL construction, API contracts and locally complete authorization checks. Workspace is useful when claims share the actual resolver/transform/check with compatible callers. Prepare the needed interface/default implementation, import, serializer or caller relationship before spending a shared allowance. Reuse source-bound facts with applicability; do not copy verdicts or group solely by file/category. This study changed both evidence preparation and review mode, so it does not prove workspace alone caused the gain.
4. **Require targeted finding/flow review for promotion.** Review a claimed input-to-authority-to-effect relationship and intended permission contract, especially when the proposed finding admits no lower-trust path. Retain supported conditional mechanisms and hardening observations separately. A second capable reviewer is a selective option; this experiment does not establish an automatic reviewer's correction rate. Validate these concrete cases and format failures first, using an optimized frozen build for any new timing gate. Stop on evidence/quality acceptance, not universal agreement or a zero-uncertainty count. Do not start another full-app/model matrix until a specific change needs it.

These corrections retain the [selected balanced workflow](../review-workflow-final-2026-10-29.md), while narrowing its rollout claim. Cheap cached native review is a useful base; prepared shared investigations and selective source/flow audit still do substantive work.

## Reproducibility and verification

Main artifacts: `C:/dmitry/scan-runs/orchard-recheck-20261029-bx`; marker runs: `orchard-markers-{1,2,3}-20261029-by`; follow-up: `C:/dmitry/scan-runs/orchard-followup-20261029-bz`.

Important saved files are `whole-package-analysis.json`, `aggregate-claim-results.json`, `first-pass-assembly.json`, `audited-whole-package.json`, `historical-comparison-all-pages.json`, `historical-comparison-audited.json`, `historical-source-hash-comparison.json`, `historical-excerpt-comparison.json`, `coordinator-audit-notes.json`, `negative-control-audit.json` and `verification.json`. Scripts preserve original attempts and private sessions outside exported evidence.

Final verification checked **13,450 frozen source/runtime files and 1,141 audited source excerpts**, all 537 base IDs, 17 exported workspace judgments, 176 receipts/177 attempts, and the explicit unknown-price flag. No target application was executed, no admissions were written, and no product/prompt changes were made during this frozen test. Experiment documentation and harness artifacts are uncommitted.
