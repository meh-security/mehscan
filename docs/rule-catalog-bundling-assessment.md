# Rule catalog bundling assessment

## Decision

Keep the current rule catalog layout. The YAML files are source organization,
not runtime bundles: Mehscan embeds and parses all of them, validates the
combined rules and relations, then compiles patterns by language. Moving rules
between files would not reduce scan work or change triage behavior. Do not
rename rule IDs as part of a layout change; they are used by identity gates,
investigation logic, and evidence IDs.

## What exists

- `rules/code` has 52 catalogs, about 497 KB of YAML, 426 rules, and 2,268
  structural patterns across 12 languages. Thirty-six catalogs contain more
  than one language. The paths are listed once in
  `crates/engine/src/rules/loader.rs`; a test checks that every shipped catalog
  is embedded.
- Most catalogs use CWE-oriented folders for sinks and controls, while the
  relation contracts compose sources, sinks, and controls across files.
  Kotlin and PHP have language-specific catalogs. The 76 KB
  `extended-database.yml` is the largest file, with 36 rules across languages.
  Its YAML anchors share patterns and guidance among JavaScript, TypeScript,
  and TSX rules; a language-based split would duplicate those definitions.
- `rules/relations/security-paths.yml` has 52 cross-rule contracts. The
  typed `language`, `kind`, `capability`, capture roles, and relation contracts
  carry the meaning. Directory names do not select or compose rules.
- The matcher applies a compiled language's rules to each source file and
  uses a literal-text prefilter before AST matching. Several ownership and
  context checks in Rust dispatch by rule ID. Reorganizing catalog files does
  not remove that code.

## Measured cost

Single local runs with the 0.6.2 release CLI and `scan --timings`; these numbers
are diagnostic, not a benchmark:

| Source | Total | Parse and validate rules | Compile all languages | Pattern checks |
| --- | ---: | ---: | ---: | --- |
| Two-file C# fixture | 78 ms | 14 ms | 40 ms | 344 considered; 15 executed |
| Fifteen Rust core files | 882 ms | 15 ms | 45 ms | 2,370 considered; 275 executed |

Loading and compiling dominate tiny scans, while source analysis dominates
the larger sample. All 12 languages are compiled even for these single-language
scans. Review-bundle construction also loads the catalogs again after its scan.
Neither cost is addressed by renaming or moving YAML files.

## Options

1. **Keep current catalogs** for now. This preserves shared YAML anchors,
   nearby CWE relationships, and the existing loader completeness check.
2. **Select active languages before compilation** as a focused performance
   experiment. Compare repeated single-language and mixed-language scans,
   assert identical evidence and candidate IDs, and report wall time plus the
   existing phase timings. This changes execution, not file packaging.
3. **Reuse parsed rules within review-bundle construction** if its repeated
   load is material in a measured end-to-end run. A process-local cache alone
   would not help separate CLI invocations.
4. **Split an oversized catalog only when editing it becomes error-prone.**
   Preserve IDs and semantic fields, and account for YAML anchors that cannot
   cross files. A wholesale language-based or one-rule-per-file migration adds
   duplication and loader churn without a demonstrated scan benefit.

The first useful experiment is active-language compilation. If it does not
materially improve the small-scan or review-bundle path, leave the catalog
packaging as it is.
