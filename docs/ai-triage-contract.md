# AI triage contract

Mehscan scans source and prepares review leads. It does not assign security verdicts. The reviewer follows the [Mehscan security skill](../skills/mehscan-security/SKILL.md) and its [review workflow](../skills/mehscan-security/references/review-workflow.md) for each request in `manifest.json`.

## One review path

1. Run `mehscan investigate review-bundles ROOT --output RUN` or use an existing run. Read the request's security question, selected operation, anchor evidence, and matching bucket guide.
2. Test the exact security relationship. Use Mehscan investigation queries with `--journal RUN/journals/REVIEW_ID.jsonl`; read source around a known location, then expand only where a missing edge could change the verdict.
3. Submit one schema 1.3 draft result per review. Get the exact response shape with `mehscan investigate review-response-schema --bundle REQUEST --output SCHEMA`. Cite the selected anchor and any decisive source. Put only exact, decision-relevant source text in `investigation.decisive_artifacts`. Keep inference separate from source facts. Set `journal_summary` to `null` in the draft.
4. Run `mehscan investigate review-bundle-finalize --bundle REQUEST --draft DRAFT --journal-dir RUN/journals --output RESPONSE --source-root ROOT`. It attaches measured query counts and validates the response and source excerpts.
5. Run `mehscan report --run RUN --responses RESPONSES --source-root ROOT --format json|sarif|markdown`. Only `issue` decisions become confirmed findings. `needs_review` remains an unresolved check.

`issue` needs a demonstrated weakness on the selected operation. An unparameterized SQL construction, variable-built shell command, or variable-fed code evaluator can qualify when runtime or attacker reachability remains unresolved: use low confidence and state that exploitation is unproved. A CLI option by itself does not establish user control. `not_issue` needs affirmative evidence that the relationship is safe or inapplicable. `needs_review` names the exact unavailable fact and how to obtain it. A scanner lead, missing file, empty query, truncated result, or nearby control does not settle that question by itself.

The query journal records the complete lookup history. The response cites decisive evidence, including the selected anchor. Validation checks structure, anchors, citation links, and exact source text. The reviewer remains responsible for whether the cited facts support the verdict.

See [output contract](output-contract.md) for final formats and [CLI command reference](../skills/mehscan-security/references/commands.md) for queries.
