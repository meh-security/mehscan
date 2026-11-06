# Mehscan 0.11.0

## Features

- Review original source by default, including security issues beyond scanner candidates, while sharing context across related questions.
- Include Razor and Blazor in default source review, with an optional SDK backend for additional C# analysis.

Custom reviewers need source-review support for the default workflow. Use `--phase native` to retain scanner-candidate-only review.

## Bug fixes

- Let reviews use relevant project files, configuration and templates across supported languages.
- Reject stale, unread, clipped or binary evidence consistently.
- Improve AI review recovery and recognition of effective API behavior, including compatibility packages.
- Improve C# HTML file-response detection and avoid findings from quoted code examples.

[Full changelog](https://github.com/meh-security/mehscan/compare/v0.10.0...v0.11.0)
