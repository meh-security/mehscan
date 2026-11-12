# Mehscan 0.14.0

## Features

- Add Fast, Full and scoped threat follow-up for AI-only source reviews.
- Group related findings by repair point while preserving callers and conditions.
- Automatically select a bounded Fast review queue; use Full to audit every eligible claim.
- Keep supporting declarations and schema-only migrations available for lookups without reviewing them by default.

## Bug fixes

- Improve Python ORM query coverage and reduce duplicate candidates.
- Preserve valid review results when optional grouping annotations are invalid.
- Fix AI review startup on large repositories.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.13.0...v0.14.0)
