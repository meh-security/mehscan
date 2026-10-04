# Mehscan commands

Use the executable and root supplied for the task. `ROOT` is the source
repository, not the directory containing a saved bundle.
Append `--journal JOURNAL.jsonl` to source, outline, references, paths, and
other code-evidence lookups while reviewing a bundle. Bundle listing, cards,
finalization, and validation do not accept `--journal`. Name the journal for
the ID that prompted the query;
Mehscan appends the exact arguments, result or error, and elapsed milliseconds.
Read shared source once and reuse its inspected location for related IDs rather
than issuing the same query into each journal. The response cites only decisive
source; the journals preserve the complete lookup history.

| Need | Command |
| --- | --- |
| Candidate scan | `mehscan scan ROOT --format candidates` |
| Review requests | `mehscan investigate review-bundles ROOT --output DIR` |
| Large-repo inventory | `mehscan investigate review-inventory ROOT --output RUN/inventory` |
| Reuse finalized IDs | `mehscan investigate review-ledger --inventory RUN/inventory --history OLD_RUN_ROOT,RUN --output RUN/review-ledger.json` |
| Filter remaining inventory | `mehscan investigate review-inventory-list --inventory RUN/inventory --ledger RUN/review-ledger.json --cwe CWE --limit 50` |
| Value selection / deferred work | Add `--selection value` / `--selection deferred`; Comprehensive uses `--selection all`. Inspect `dependency_review_ids`; rebuild the ledger to reopen unsafe/unresolved dependents (`reopened_count`). Deferrals retain IDs and reasons, not safe verdicts. |
| Filter operand facts | `mehscan investigate review-inventory-list --inventory RUN/inventory --operand-kind fixed_code_relative_path --limit 50` (also `configured_root_path`, `encoding_call`, `local_operand_origin`, `operand_boundary`, `query_structure`, `process_shell_mode`, `unclassified`) |
| Shared contract queue | `mehscan investigate review-inventory-list --inventory RUN/inventory --ledger RUN/review-ledger.json --group-by contract --limit 12` |
| Contract members | `mehscan investigate review-inventory-list --inventory RUN/inventory --contract KEY --limit 50` (combine with ledger/component filters) |
| Selected requests | `mehscan investigate review-bundles ROOT --inventory RUN/inventory --ledger RUN/review-ledger.json --review-ids ID,ID --output RUN/chunk-N` |
| Bundle IDs | `mehscan investigate review-bundle-list --bundle REQUEST` |
| One review lead | `mehscan investigate review-card --bundle REQUEST --review-id ID` |
| Related review leads | `mehscan investigate review-sweep --bundle REQUEST` (exact cards with merged source windows) |
| Exact source | `mehscan investigate source ROOT --path FILE --start-line N --end-line M` |
| File outline | `mehscan investigate outline ROOT --path FILE` |
| Find readable paths | `mehscan investigate paths ROOT --name TEXT` |
| Enclosing code at known location | `mehscan investigate enclosing-at ROOT --path FILE --line N` |
| Enclosing code from ID only | `mehscan investigate enclosing ROOT --evidence-id ID` |
| Identifier uses | `mehscan investigate references ROOT --symbol NAME --path FILE --limit 20` (omit `--path` for repository-wide search) |
| Symbol definitions | `mehscan investigate symbol ROOT --name NAME --path FILE --limit 20` (omit `--path` only when the defining file is unknown) |
| Import uses | `mehscan investigate imports ROOT --name NAME --limit 200` |
| Exact syntax | `mehscan investigate structural ROOT --language LANG --pattern PATTERN --path FILE` |
| Native call syntax | `mehscan investigate native-call-sites ROOT --callee NAME --path FILE` |
| Response shape | `mehscan investigate review-response-schema --bundle REQUEST --output SCHEMA` |
| Finalize brief or full draft | `mehscan investigate review-bundle-finalize --bundle REQUEST --draft DRAFT --journal-dir RUN/journals --output RESPONSE --source-root ROOT` |
| Validate existing response | `mehscan investigate review-bundle-triage --bundle REQUEST --responses RESPONSE --source-root ROOT --summary true` |
| Summarize run | `mehscan investigate review-bundle-summary --run DIR --responses RESPONSES_DIR --source-root ROOT` |
| Final report | `mehscan report --run DIR --responses RESPONSES_DIR --source-root ROOT --format json --output findings.json` |

Use `--format sarif` or `--format markdown` for those report projections.
Write response drafts as files instead of embedding prose JSON in shell command
strings. If a report needs correction, change the reviewed response and rerun
finalization and `mehscan report`; do not edit the generated report directly.
The response schema and CLI help are authoritative for the installed Mehscan
version. Query results are JSON; inspect all `results`, `truncated`, and
`skipped_files` before concluding that a lookup found nothing.
Save finalized responses as `RUN/responses/REQUEST_FILENAME`; `report` reads
that directory and matches each response to its manifest request filename.
For C/C++ structural calls use a complete statement such as `memcpy($DEST,
$SRC, $SIZE);`, or use `native-call-sites` for a callee inventory. PHP structural
patterns are parsed as one code construct; do not combine several statements.
Pass structural patterns literally so the shell preserves `$VALUE` and
`$$$ARGS`; in PowerShell use a literal here-string for patterns containing quotes.
`source` reads an exact requested text file under the scan root, including
templates omitted from scan admission; repository ignore rules still apply.
Use a known path directly, or `paths` when the path is unknown. Read the
applicable engine contract or a repository behavior test when template
interpretation determines the verdict.
`--path` always names one file, never a directory. `outline` and `enclosing-at`
need a file with a supported parser; use `source` for tests or templates that
Mehscan reports as text-only.
The default brief draft needs only `results` with `review_id`, `decision`,
`confidence`, `summary`, optional `reason`, and optional `evidence` source
ranges (`path`, `start_line`, `end_line`). Finalization reads those exact lines,
fills the full response and journal summary, and validates it. Use
`review-response-schema` only for exceptional full schema 1.3 drafts.
Keep each `summary` and `reason` on one line within 500 characters.
`paths` is
navigation, not code evidence: read a returned path before citing its contents.
`--source-root` checks that every decisive artifact excerpt occurs in a file
inside that root. It catches paraphrases presented as source text; it cannot
prove that every executed query was recorded.
