# Changed review release readiness

## Current candidate — 2026-10-30

The review preparation/navigation study is closed for release. Ship the tested
native navigation and recovery fixes; retain native plus selective workspace and
keep preparation experiments opt-in. The [closure report](experiments/review-release-closure-2026-10-30.md)
records the retained scope limits, TypeScript alias fix, bounded query correction
and corrected caller-attribution replay. Semantic verdict rewriting and another
app/model comparison are not release prerequisites.

The remaining release gates are full hosted CI on the exact reviewed commit,
including MSRV/platform acceptance, followed by the selected version's paired
assets and installer/pin verification. Existing provider-403 failures and real
company-auth acceptance remain open for the optional AI reviewer: do not promote
it by default or claim reliable unattended completion. No tag or publication has
been performed. The sections below retain the broader workflow's acceptance history.

## Earlier workflow acceptance

The Changed scope and advisory workflow are implemented on the V11 development
branch. They are experimental until the reviewed commit passes hosted acceptance.
The released 0.8.0 executable does not include these options. No version bump or
new release is included in this change.

## What is implemented

- Whole changed-file scope with pinned PR merge-base/head and direct release endpoints.
- Paired CLI/skill workflow, repo-scoped native fingerprints, review history and
  exact supersession. History never makes an answer valid for changed evidence.
- Native default; optional Value/Comprehensive review with bounded unchanged-source
  research, native finalization and explicit pending/deferred work.
- Read-only advisory Action with an opt-in BYOK Codex/Luna reviewer, explicit auth,
  manual fork authorization, and JSON/SARIF/usage/completion artifacts.
- SARIF locations, fingerprints and native-supported flows. Missing flows are not
  invented; successful execution or an empty SARIF does not establish safety.

Local Rust 1.88 workspace tests/doctests, Windows and Ubuntu orchestration suites,
installer checks and installed-package workflows pass. Ubuntu package acceptance
uses a freshly built optimized binary. Local live Luna/medium simulations used
ChatGPT auth; they do not establish company-key or actual GitHub acceptance.
Optional corpus tests remain explicitly ignored when those corpora are absent.

## Before merging and releasing

1. Review the paired engine/skill/controller diff and run full hosted CI on its
   exact commit, including Windows/MSRV and both macOS release architectures.
2. Pin that reviewed commit in one synthetic integration repository. Start with
   native artifacts, then test real company-auth Value/Comprehensive review.
   Follow [GitHub acceptance setup](github-acceptance.md); no GitHub App is needed.
3. Observe real delivery/fetch, force push, base movement/retarget, duplicate/late
   runs, cancellation, missing/bad auth, malformed model output, deadlines and
   explicitly authorized manual fork review. Automatic forks remain native-only.
4. Close the supported-scope quality matrix and measure matched Changed/full costs
   on backend and frontend/monorepo changes. The earlier Go/Owncast removed-guard
   case has no established native finding representation; keep its source-only
   effect pending and qualify coverage. Unresolved work must never become clean.
5. Choose the release version, build the exact assets and verify installers,
   source pins, client compatibility and documentation before tagging.

Battle testing follows release acceptance: use varied real PRs/release deltas,
spot-check verdicts and track missed effects, false positives, pending burden,
latency and tokens. Synthetic passing tests are not a recall rate or token-savings
claim. Current limits do not cap currency/total tokens; failed-call usage can be
incomplete.

## Later integrations

SARIF files are available now. A trusted publisher, automatic GHAS upload,
comment commands, Copilot/Claude parity and required merge gates need separate
implementation and acceptance. GHAS dismissal must not import a native safe verdict.
Org memory, hosted inference and automatic fixes are outside this release scope.

## Review-evidence follow-up

The `feat/v11-review-evidence` branch adds inferred C# ZIP extraction questions
and bounded ASP.NET startup/base-class source preparation for the reviewer.
Credential and authorization guidance requires actual effects. Extraction and
temporary-file deletion retain separate native identities; source preparation
supplies navigation evidence, not proof that a policy is active.

Local acceptance covers inferred ZIP and existing C# filesystem regressions,
source-bound policy preparation through worker admission, and Windows/Ubuntu
provider and worker tests. These tests verify evidence delivery and admission;
they do not certify the model's security reasoning.

The paired Luna/medium run at vulnerable .NET revision
`60d060faf08079887e71a98498fe9a9d623e8ffc` passed normal native admission.
Value settled 45 of 47 selected questions with two pending and two deferred;
Comprehensive settled 46 of 49 with three pending. Both dismissed the simulated
password-reset operations and exported the new extraction sink at its actual
line. Structural SARIF checks passed, including unique fingerprint sets within
each run and identical maps for all 15 issue IDs shared between modes on that
snapshot. Input tokens increased relative to the saved baseline in both modes.

Live Luna/medium review of a pinned vulnerable .NET application found remaining
quality gaps: a ZIP defect can still be attributed to adjacent cleanup, shell
allowlist reasoning can miss permitted newlines, and public operations can be
flagged without establishing a required access policy. Executable C# inside Razor
and non-UTF-8 LDAP source remain coverage gaps. Treat these as release evaluation
work, and do not infer safety or token savings from fewer pending questions.

## Development builds and reruns

Reuse the checkout's `target` directory and overwrite the existing executable,
archive and run logs. Do not create a target, source clone or binary per rerun.
For local test builds use `CARGO_INCREMENTAL=0` and `CARGO_PROFILE_TEST_DEBUG=0`,
as CI does; full debug metadata can make this workspace's test executables large.
Keep one build cache during validation. Afterward use Cargo's scoped clean command
for that cache, retaining only the current CLI/archive and compact acceptance
records. Check free space on the host volume as well as inside WSL: its virtual
disk consumes host space even when the guest reports a large available capacity.
