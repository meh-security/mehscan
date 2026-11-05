# Unreleased changes

## Features

- Add optional Fast and Full second-pass reviews, with scopes for findings, dismissals and unresolved items.
- Export first/final comparisons and training-label candidates with linked review evidence.
- Expand C/C++ and Rust memory, ownership and lifetime review.
- Broaden Python credential, Rust state and HTTP, and Go identity review.
- Improve helper discovery and source context during AI review.

## Bug fixes

- Reduce noisy hashing, token and filesystem review candidates while preserving unresolved security questions.
- Respect Rust source-module conditions and exclude additional test, spec and sample conventions.
- Preserve review evidence and second-pass exports when recovering interrupted work.
- Reduce repeated source analysis and improve cache reuse between AI reviews.
- Include linked coverage guides and license files in release packages.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.9.0...main)
