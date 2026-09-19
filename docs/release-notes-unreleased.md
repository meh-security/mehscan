# Unreleased changes

## Features

- Extended SQL and NoSQL rules across supported languages.
- Broader filesystem, dynamic-code, and executable-deserialization sinks.
- Typed Java and .NET XPath expression review, plus additional native process launch APIs.
- Partial triage reports and summaries with explicit completion coverage.
- Built-in review response schema generation.

## Bug fixes

- Strong interpreted sinks now retain origin review across supported languages,
  with bounded service and repository caller context.
- Investigation funnels continue when a file cannot be outlined.
- Detect more JDBC execution and PHP database property query patterns.
- Preserve origin review for dynamic template, outbound-request, redirect, and XPath operands.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.4.0...HEAD)
