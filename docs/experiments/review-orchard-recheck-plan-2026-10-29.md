# OrchardCore archive recheck — 2026-10-29

Test the [selected balanced workflow](../review-workflow-final-2026-10-29.md) on the older production CMS corpus, and compare its source-level conclusions with preserved historical reviews. Do not tune the prompt to the old answers or treat historical closure rates as ground truth.

**Completed:** see the [results and corrected implementation milestones](review-orchard-recheck-results-2026-10-29.md). All 537 first-pass results are assembled and source-validated; 17 workspace judgments and 11 coordinator amendments are preserved separately. Known spend is $4.5397108 plus one unpriced aborted attempt. Original failed worker states remain unchanged. No further paid runs are queued.

## Frozen scope

- Source archive: `C:/dmitry/mehscan-internal/corpus-cache/apps/OrchardCore`. It has no application `.git` directory; the ancestor workspace's Git revision is not an Orchard revision. Historical source fingerprint: `a48c107ebdb21dca`. Current fingerprint: `review-sources-v1-d58e30d5bb194438cf27e353b116744f131ad9b0fbd80a9fdf4aa6227d63db9f`. Different fingerprint formats do not establish source changes.
- All **415 current inventory claims in 31 native bundles**, maximum 20. Coverage: 9,448 discovered files, 7,167 scanned, 2,278 ignored, three parser failures. Preserve these gaps.
- Same frozen scanner, current skill/adapter, pinned Codex CLI and trusted reviewer Python used for PyGoat. Terra 6.1 medium, stable schemas, line-addressed source, serial native review, native bundle maximum 20.
- Five continuation rounds, 24 query units, 512 KiB, 900-second conversation deadline per bundle. No aggregate three-minute/three-million-token cutoff.
- No target builds, restore, dependency installation, application execution or live probing. No automatic admission.
- Fresh source/runtime-bound state and private sessions. Source/archive and runtime files hashed before inference. Historical reports, corrections and expected verdicts remain coordinator-only, outside the model evidence.

## Historical comparison

The preserved October 5 Luna run was coordinator-assisted. It reviewed 468 Orchard IDs including reopened claims, originally returning 26 issues, 437 scoped negatives and five uncertainties. Independent source revalidation changed the assessed counts to 22 issues and 446 negatives, with deployment conditions still explicit. Four title findings were withdrawn. There are no reliable run-specific model tokens/prices; missing historical cost is not zero.

The old inventory had 498 entries. There are **331 exact ID/rule/path/line/kind/symbol matches** to the current inventory, including **25 independently revalidated claims**. The other 137 historically reviewed claims are unmapped or ambiguous under this strict match; do not silently substitute a nearby claim. Current claims outside historical reviewed scope remain separate.

Three earlier positive **directory-creation** site claims are not admitted currently: two in FileSystemStore and one in the remote-media cache. Other current claims retain both containment mechanisms. Audit the admission reason and source, rather than count candidate reduction as quality improvement or model efficiency. An initial progress update incorrectly described these as delete sites; the exact historical entries establish Directory.CreateDirectory calls.

The current inventory also records 170 recognized review markers, of which page zero admits 48 and budget-defers 122. Cached continuation pages 1/2/3 contain 48/48/26 additional claims with zero overlap. Include these as fresh, separately bound supplemental native work: **537 unique claims across page zero and all marker pages**. Ordinary reviews are not repeated. The original 415-claim run stays unchanged. No additional source scan is required for marker discovery; normal source/runtime validation and bundle preparation still apply.

Prepare the supplemental pages independently while page zero runs. Execute supplemental pages as one serial queue overlapping the original single worker, so global review concurrency is at most two. Record that scheduling choice; do not present this as a controlled serial-versus-parallel experiment or infer savings. Measure all 537 claims and all paid attempts once. Supplemental artifacts are `C:/dmitry/scan-runs/orchard-markers-{1,2,3}-20261029-by`.

Historical assessment is evidence to recheck, not a gold label. Compare the actual mechanism, intended contract, caller applicability and conditions. In particular preserve the distinction between a broken local containment contract and a demonstrated anonymous filesystem exploit, and between explicit trusted markup and an attacker-controlled unencoded value.

## Observation and stop gates

**Observed build-performance qualification:** the frozen scanner used by PyGoat
and this run is the debug binary (`6e85284b…`). A read-only check with the existing
optimized binary returned the exact same 67-symbol response for the repo-wide
`Permissions` query in 3.986 seconds, versus 378.037 seconds in the running debug
binary. A scoped optimized query took 0.689 seconds. Preserve this run's paid
results and bindings; do not silently swap executables. Its local lookup/wall
time is not a representative optimized production benchmark, and does not by
itself justify an architectural rewrite. The binaries are different artifacts;
one equal query response is not proof of full inventory/runtime equivalence.
Saved evidence: `symbol-release-benchmark.json` and exact query responses.

1. Complete the unchanged native first pass; reconcile every offered call and actual usage, including failures/unknowns. Measure full input/output, cache reads/writes, published price equivalents and execution time. Record source/bundle preparation time separately from model review.
2. Compare the exact matched subset with original and corrected historical assessments. Re-audit all material disagreements, all current positives, consequential uncertainties and a varied sample of negatives. Audit missing historical positive sites separately from model verdicts.
3. Inspect whether known implementation evidence is repeatedly rediscovered or absent from a later work item. A file/category match is insufficient for sharing; require the same deciding implementation and compatible caller context.
4. Use a bounded selective follow-up only for an actual deciding question that could change a material conclusion. Keep native local closure for complete SQL/API contracts. Shared containment or rendering relationships may use workspace with separate verdicts. Preserve originals and charge all added review cost.
5. Stop after the first pass, disagreement audit and any justified bounded follow-up. Keep actionable uncertainty and conditional findings. Do not launch another universal model/mode tournament to force agreement.

## Artifacts

- Preflight inventory: `C:/dmitry/scan-runs/orchard-preflight-20261029-bx`.
- Run and coordinator comparison: `C:/dmitry/scan-runs/orchard-recheck-20261029-bx`.
- Historical artifacts: `C:/dmitry/scan-runs/planv9-orchard-lancommander-luna-20261005`, including `revalidation/`; whole-inventory scan observations also remain in `planv9-orchard-full-20261005`.
- Private state stays outside source and artifact exports. The saved preparation/observation scripts are experiment harnesses, not an automatic production scheduler.

## Observed corrections and selected follow-up

The coordinator selected **20 unresolved filesystem effects in three investigations**: 12 FileSystemStore operations sharing its private resolver and normalization contract; five resized-cache operations sharing a generated key, extension mapping and actual middleware caller; and three remote-cache create/delete effects sharing the entry-to-local-path relationship. This is a selected diagnostic follow-up, not a universal workspace rerun or an automatic admission. Original verdicts and all paid attempts remain preserved. Run: `C:/dmitry/scan-runs/orchard-followup-20261029-bz`.

Two evidence-format failures must remain visible. Generated JavaScript has inspected physical lines exceeding the brief format's 4,000-character limit. An offline conversion to the existing full response format splits exact source excerpts by column/byte position, preserves decisions and reasoning, and passes native validation without new model calls or source changes. Separately, a six-claim marker reply cited a locator in source-only boundary metadata. Its unchanged verdict draft passed independent native validation; the original adapter rejection is not relabeled a success. A workspace attempt later invented an artifact handle and was rejected; the remaining permitted final turn retains that cost and the original failed state.

Historical label comparison now has stronger source checks: all 1,632 files in the preserved Roslyn semantic-input hash manifest match current bytes. Of the 331 exact claim/locator matches, 209 selected files occur in that manifest. All preserved decisive excerpts match at original UTF-8 byte offsets for 329 claims; two have no excerpts. These checks do not establish whole-archive version equality. The old summary-XSS assessment cites a different extension namespace from the one imported by the current views; inspect actual binding rather than require agreement with an old positive label.

The first native pass, selected follow-up, offline format recovery and coordinator source audit must be reported separately. Do not equate `needs_review` with a wrong dismissal, native evidence validation with semantic correctness, or retained conditional library mechanisms with demonstrated anonymous application exploits.
