## Features

- Expanded dangerous sink coverage across supported languages, including database execution variants, process APIs, outbound requests, and framework trusted-HTML APIs.
- Added framework and route authorization facts to AI review bundles while preserving application-defined guards for review.
- Structural investigation now supports every scanned language and continues repository-wide queries past malformed files.

## Bug fixes

- Dynamic or unknown high-risk sink origins remain reviewable instead of being dismissed prematurely.
- Middleware and decorator names alone no longer prove authentication, authorization, or resource ownership.
- Authorization context is scoped to the reviewed path or observation instead of unrelated helper and configuration files.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.5.0...v0.5.1)
