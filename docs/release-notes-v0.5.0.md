## Features

- Broader SQL and NoSQL detection with bounded origin context across supported languages, including common repository, service, EF Core, Dapper, JDBC, and PHP query patterns.
- New coverage for filesystem access, dynamic code, executable deserialization, XPath, native process execution, and framework trusted-HTML sinks.
- Partial triage and report generation with explicit review coverage, plus built-in response schema generation.
- Verified Linux and macOS installation without PowerShell.

## Bug fixes

- High-risk sinks with unknown or dynamic origins stay in AI review instead of being dismissed prematurely.
- Investigation funnels continue past parser failures, and validated partial response sets can be summarized or reported.
- Additional JDBC statement execution and PHP database-property query patterns are detected.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.4.0...v0.5.0)
