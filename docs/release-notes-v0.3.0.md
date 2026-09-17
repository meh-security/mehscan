## Features

- Native PHP scanning for injection, unsafe file operations, deserialization, dynamic code, and insecure cURL settings.
- PHP analysis recognizes JSON request inputs, included PDO/mysqli configuration, and PDO parameter binding.
- Scope, project, and revision labels included in JSON, SARIF, and Markdown reports.

## Bug fixes

- Aggregated findings preserve explanations for every affected input.
- More accurate review of helper calls, conditional branches, and input origins across languages.
- Clearer finding explanations and more precise TLS configuration review.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.2.1...v0.3.0)
