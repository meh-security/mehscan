## Features

- Added bounded authorization review admission for sensitive server mutations and credential lifecycle changes across supported web languages, including operations without a modeled data sink.
- Expanded Express and Spring review context with exact session selectors, generated routes, and bounded controller, service, and policy facts.

## Bug fixes

- Authorization review now distinguishes authentication and coarse guards from checks covering the exact action and selected resource.
- Review markers preserve uncertain custom policy behavior for AI analysis without treating marker presence as a confirmed vulnerability.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.5.1...v0.5.2)
