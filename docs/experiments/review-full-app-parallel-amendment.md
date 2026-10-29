# Full-app comparison: run independent arms concurrently

The user requested parallel execution. Sol native had already completed its
recovery when this change was applied: 116 source-validated claim results,
91 known provider calls, 3,721,453 input tokens and 83,469 output tokens.
This establishes completion and accounting, not semantic quality.

Run the remaining Sol hybrid, Terra hybrid and Terra native arms concurrently,
with at most one provider call per arm in flight. Their native stores,
workspaces and private provider-session directories are distinct and do not
contain one another. Source and reviewer implementation files are shared for
reading. No completed work is repeated.

Remove the result-order and Sol-pair prerequisite gates for these independent
arms. Preserve source/question checks, provider bindings, complete usage
accounting, the shared dispatch-stop signal and the matched investigation
allowances. A shared drift or unknown-usage fault blocks subsequent dispatch;
already in-flight calls finish and remain charged. The
[completion amendment](review-full-app-completion-amendment.md) still removes
aggregate token/time censoring consistently across all four arms.

The original and completion runners/freezes remain unchanged. A separate
`run-parallel.py`, `parallel-amendment.json` and `parallel-freeze.json` under BD
record this scheduling change and verify the prior immutable inputs. Model,
reasoning effort, routing, prompts, source selection and quality criteria stay
fixed. Each arm retains its own observation and result files.

Record overlap and actual study wall time. Concurrent arm/provider latency is
affected by contention and must not be presented as a controlled serial speed
comparison. Quality and total known price remain the primary comparison;
retain the interrupted Sol native history and any recovery overhead.
