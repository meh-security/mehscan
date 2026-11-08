# Mehscan 0.12.0

## Features

- Expand Rust security review for parser and transport lengths, archive extraction, unsafe memory, and authentication boundaries.
- Match Cargo lockfiles against a local RustSec advisory database, including informational advisories.
- Reuse cited implementation facts across review batches on the same source snapshot.

## Bug fixes

- Retain intact C and C++ structural matches when a file contains syntax the parser cannot fully recover.
- Keep source review moving when a definition cannot be parsed or a lookup directory is missing on Windows.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.11.0...v0.12.0)
