# Mehscan 0.14.0

## Features

- Add budget and coverage targets with ranked investigations and reports of unfinished checks and risks.
- Add optional factual-question delegation while keeping security decisions with the review owner.

- Plan Value reviews across native candidates and bounded AI discovery with a configurable mix and shared budget; scripted Value reviews require a work, selection or domain plan. Use Comprehensive for broader coverage.
- Add opt-in domain reviews that reuse related source context while keeping claims and flow coverage distinct.
- Add automatically selected Fast reviews, Full audits and scoped threat follow-up for AI-only source reviews.
- Group related findings by repair point while preserving callers and conditions.
- Keep passive data models, supporting declarations and database schemas available for lookups without reviewing them by default.

## Bug fixes

- Preserve completed findings when source-review tasks fail, keeping unanswered work explicit.
- Handle repository-root lookup filters without aborting a review.
- Fix expert-owner startup when factual-question delegation uses domain sessions.

- Improve Python ORM query coverage and reduce duplicate candidates.
- Preserve valid review results when optional grouping annotations are invalid.
- Fix AI review startup on large repositories.
- Avoid prematurely stopping reviews with large context.
- Preserve review completion when AI discoveries replace generic native questions.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.13.0...v0.14.0)
