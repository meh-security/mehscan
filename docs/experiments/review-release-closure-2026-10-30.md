# Review study closure and release fixes — 2026-10-30, CZ

**Decision: close the preparation/navigation experiment series and prepare the
tested changes for release.** Keep native review plus selective workspace and
leave dependency preparation opt-in. Do not make a new semantic verdict rewriter,
another app/model matrix or universal second review a prerequisite for shipping.
Live AI reliability and review quality retain their documented limits.

## Scope audit closed

All 13 saved cases were reconciled against the existing source audit, with all
26 bound source files and both audit inputs hash-verified. No historical decision
or provider receipt was changed. The retained conclusions are:

| Cases | What must survive in the review package |
| ---: | --- |
| 4 optional identity/workflow questions | Real local authorization checks, with separately scoped credential/workflow limits |
| 2 sanitizer callers | Inspected local sanitizer behavior, conditional on the unresolved package/build binding |
| 2 supported local closures | Sidebar permission filtering and token/owner binding for alias insertion |
| 1 import task | Authorization of task creation, separate from downstream parsing and writes |
| 1 export filter | Same-space/filter invocation facts, with the unread policy-helper obligation retained |
| 1 generated HTML case | Conditional unescaped-title mechanism, separate from direct-response interpretation |
| 2 FlaskBB claim sites | One supported conditional reply-target mismatch, not two independent vulnerabilities |

These cases do not support a deterministic rule that rewrites verdicts from
summary wording, missing helpers or the amount of retrieved source. Such a rule
could reject valid local closure and still miss the underlying mechanism. Use the
existing checks/source-lead channels for distinct remaining obligations; retain
this corpus as evaluation evidence. Automated semantic scope adjudication is
deferred rather than left as an indefinite release blocker.

The audit also caught a **replay fixture error**: CY swapped the link/card claim
IDs and their initial import-query paths. Its cache/transport measurements remain
historical, but caller-specific validation was overstated. The corrected replay
asserts both mappings against the native inventory before dispatch. CY artifacts
remain intact and its report now carries the correction.

## Product fixes

- **Type-only import aliases no longer create runtime scanner links.** The old
  executable connected both `import type {run as local}` and
  `import {type run as local}` through re-exports to a process-execution caller.
  The corrected scanner removes those two impossible links while retaining the
  runtime alias control. Tests also cover mixed type/value imports and barrels.
- **Malformed deciding questions receive bounded correction feedback.** The
  typed schema now matches the broker's 1–300-character limit. A bad question
  rejects the whole query batch before execution and can use the existing single
  protocol correction. It does not discard prior work or reset budgets. Foreign
  claim IDs and escaping paths remain fatal and cannot be masked by a bad question.
- **The earlier navigation/broker fixes remain included:** nested-export
  ambiguity is preserved, named export lookups are bounded, shared source retains
  per-claim attribution, and narrowly recognized missing/unsupported lookups can
  coexist with successful independent results.

## Acceptance and remaining release work

**102 tests pass, with one existing POSIX-only skip:** 15 native engine/CLI tests,
six broker tests, nine package/existing-lookup checks and 73 provider-adapter tests
(72 pass, one skip). Workspace formatting and generated-reference checks pass.
The optimized executable builds successfully; its type-only alias counterexample
retains only the runtime control. No full local workspace/MSRV suite or hosted
cross-platform CI result is claimed for this candidate.

The corrected three-claim replay passes through the normal worker with both
caller mappings checked against the native inventory. It uses 11 requests,
14 reserved query units, eight unique facts, three research-cache hits and ten
native CLI executions. Preparation/replay/post-checks take 9.185 seconds; all
4,796 pinned source hashes verify, no decisions are admitted and zero provider
calls are made. These are deterministic protocol checks, not new semantic verdicts
or a model price/quality result. The original CY attribution error is not erased.

Artifacts are under `C:/dmitry/scan-runs/release-closure-20261030-cz`, including
the 13-case closure, old/new scanner counterexample, test logs and corrected
`broker-replay`. The optimized scanner SHA-256 is
`e87dd3a1b4bb29b7d2d4cad0949d7e933c0271c72d4e0024e8aa1119bae873d7`.

A supplementary strict Clippy run on local Rust 1.98 stops at a pre-existing
`len_without_is_empty` warning in `ReviewLookupArguments`; it did not establish
a clean Clippy result. The configured hosted gate uses Rust 1.88 tests, not that
Clippy invocation. Do not treat this local pass as hosted/MSRV/macOS acceptance.

Before tagging: run full hosted CI on the exact candidate commit, then choose the
version and build/verify the paired assets and installer pins. The native release
can proceed with AI review explicitly opt-in/experimental. Recurring provider 403s
and company-auth acceptance remain blockers for claiming reliable unattended AI
review or promoting it by default; they do not require another source-preparation
experiment. No paid test, version bump, tag or publication is part of this closure.
