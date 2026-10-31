# Unreleased changes

## Features

- Follow JavaScript and TypeScript imports and re-exports during AI review.
- Use a consistent Value review budget and cache-friendly AI input by default.

## Bug fixes

- Avoid incorrect source links through ambiguous or type-only exports.
- Restore typed request flows through supported embedded evaluator contexts.
- Continue independent lookups when a requested file is missing or its language is unsupported.
- Allow reviewers to correct malformed lookup questions without losing completed work.
- Keep detailed flow diagnostics opt-in during ordinary AI review.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.8.0...improve/single-model-review-finalization)
