# Mehscan 0.18.0

## Features

- Use a prepared project reference and a private claim for local and GitHub reviews. Close an admitted review to freeze its findings and open checks, then use the receipt to render reports, run a Fast or Full audit, continue eligible Value work, or publish review memory.
- Supply a source-bound Value selection to the GitHub Action. Without a selection, the Action returns a checkpoint with zero provider calls.
- Use the same Value-first scheduler for named checks and source assignments in Comprehensive reviews. Completed work and remaining provider allowances carry forward on eligible continuations.

## Performance

- Compile structural rules for the languages being scanned and reuse the validated catalog in long-lived processes. A one-file JavaScript scan fell from 83 ms to 35 ms in the local release-build comparison with PR 48.
- Verify large journal snapshots outside the exclusive write lock. On a 2.7 MB journal with four writers, median record latency fell from 164 ms to 51 ms.

## Bug fixes

- Package the direct OpenAI Responses transport so installed reviews can dispatch it.
- Find published reviews through the prepared inventory even when source review derived a new inventory before admission.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.17.0...v0.18.0)
