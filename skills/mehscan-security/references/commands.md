# Mehscan commands

Use the executable and root supplied for the task. `ROOT` is the source
repository, not the directory containing a saved bundle.
Append `--journal JOURNAL.jsonl` to every read-only investigation query while
reviewing a bundle. Use one journal per review ID; Mehscan appends the exact
arguments, result or error, and elapsed milliseconds. The response cites only
decisive source; the journal preserves the complete lookup history.

| Need | Command |
| --- | --- |
| Candidate scan | `mehscan scan ROOT --format candidates` |
| Review requests | `mehscan investigate review-bundles ROOT --output DIR` |
| Exact source | `mehscan investigate source ROOT --path FILE --start-line N --end-line M` |
| File outline | `mehscan investigate outline ROOT --path FILE` |
| Find readable paths | `mehscan investigate paths ROOT --name TEXT` |
| Enclosing code at known location | `mehscan investigate enclosing-at ROOT --path FILE --line N` |
| Enclosing code from ID only | `mehscan investigate enclosing ROOT --evidence-id ID` |
| Identifier uses | `mehscan investigate references ROOT --symbol NAME --path FILE --limit 20` (omit `--path` for repository-wide search) |
| Symbol definitions | `mehscan investigate symbol ROOT --name NAME --limit 200` |
| Import uses | `mehscan investigate imports ROOT --name NAME --limit 200` |
| Exact syntax | `mehscan investigate structural ROOT --language LANG --pattern PATTERN --path FILE` |
| Native call syntax | `mehscan investigate native-call-sites ROOT --callee NAME --path FILE` |
| Response shape | `mehscan investigate review-response-schema --bundle REQUEST --output SCHEMA` |
| Finalize draft | `mehscan investigate review-bundle-finalize --bundle REQUEST --draft DRAFT --journal-dir RUN/journals --output RESPONSE --source-root ROOT` |
| Validate existing response | `mehscan investigate review-bundle-triage --bundle REQUEST --responses RESPONSE --source-root ROOT` |
| Summarize run | `mehscan investigate review-bundle-summary --run DIR --responses RESPONSES_DIR --source-root ROOT` |
| Final report | `mehscan report --run DIR --responses RESPONSES_DIR --source-root ROOT --format json --output findings.json` |

Use `--format sarif` or `--format markdown` for those report projections.
The response schema and CLI help are authoritative for the installed Mehscan
version. Query results are JSON; inspect all `results`, `truncated`, and
`skipped_files` before concluding that a lookup found nothing.
`source` reads only files admitted to the investigation index. Check `paths`
before requesting a guessed template path; an absent template is a coverage
limit, not proof of safe rendering. Read the applicable engine contract or a
repository behavior test when template interpretation determines the verdict.
`--path` always names one file, never a directory. `outline` and `enclosing-at`
need a file with a supported parser; use `source` for tests or templates that
Mehscan reports as text-only.
Response schema 1.3 uses `investigation.decisive_artifacts` for exact source
needed by the verdict. Set `journal_summary` to null in the draft; finalization
fills it from the query journal.
`paths` is
navigation, not code evidence: read a returned path before citing its contents.
`--source-root` checks that every decisive artifact excerpt occurs in a file
inside that root. It catches paraphrases presented as source text; it cannot
prove that every executed query was recorded.
