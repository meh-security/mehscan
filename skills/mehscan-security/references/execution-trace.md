# Inspect review execution

Use this when a run stalls, repeatedly searches, changes scope, reports an
unsupported claim or leaves a known relationship pending. Inspect execution
before buying another model pass. Source audits/replay references stay outside
reviewer input.

```text
python TRUSTED/scripts/review_trace.py --run ATTEMPT --review-id EXACT_ID
python TRUSTED/scripts/review_trace.py --run ATTEMPT --format json --output TRACE.json
```

The view reads existing artifacts without changing state or running a model.
New worker attempts retain an append-only `review-trace.jsonl`: provider starts,
returned responses, validated progress changes, completed queries, native
validation/admission operations and failures. The latest working hypothesis and
progress also live in job checkpoints for compatible recovery. Older attempts
can reconstruct queries, saved drafts and job status but do not have a complete
per-turn progress history. Keep original attempts when recovering.

Ask these questions in order:

1. **Was execution complete?** Inspect controller admission, native failures,
   unfinished jobs and unknown provider calls. A drafted answer is not native
   admission. Pending can be a completed review outcome.
2. **Did research address the selected question?** Compare query purposes and
   returned source with the selected operation/actor/effect. Repeated empty
   symbol searches may indicate a locator or tool-use problem; unrelated helper
   reads may indicate task drift. Neither automatically proves a wrong verdict.
3. **Did a decisive relationship disappear?** Progress transitions flag previously
   open relationships absent from the next snapshot. Inspect whether the model
   resolved, rephrased or abandoned them. These flags are not semantic judgments.
4. **Does the answer follow from evidence?** Inspect its actual effect, condition,
   counterevidence and missing fact. Source supplied is not source understood;
   a valid artifact handle does not establish a correct explanation.

Choose the smallest remedy: source locator/API documentation, missing category
guidance, clearer task scope, native finalization, or a model reasoning limitation.
Do not treat every pending case as a budget problem. Do not turn a clean trace
into certified security coverage or automatically override a verdict from flags.

`state status` and `state history` remain the native decision authority.
Diagnostic trace files are not a second findings store. Raw provider prompts and
session logs remain private; this view does not read or export them.
