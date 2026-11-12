# Mehscan 0.14.0

## Features

- Focus Value reviews on a few source-backed operations; scripted Value source reviews now require `--source-selection`. Use Comprehensive for broader coverage.
- Add automatically selected Fast reviews, Full audits and scoped threat follow-up for AI-only source reviews.
- Group related findings by repair point while preserving callers and conditions.
- Keep passive data models, supporting declarations and database schemas available for lookups without reviewing them by default.

## Bug fixes

- Improve Python ORM query coverage and reduce duplicate candidates.
- Preserve valid review results when optional grouping annotations are invalid.
- Fix AI review startup on large repositories.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.13.0...v0.14.0)
