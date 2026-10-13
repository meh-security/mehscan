# Changed review release readiness

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

## Development builds and reruns

Reuse the checkout's `target` directory and overwrite the existing executable,
archive and run logs. Do not create a target, source clone or binary per rerun.
For local test builds use `CARGO_INCREMENTAL=0` and `CARGO_PROFILE_TEST_DEBUG=0`,
as CI does; full debug metadata can make this workspace's test executables large.
Keep one build cache during validation. Afterward use Cargo's scoped clean command
for that cache, retaining only the current CLI/archive and compact acceptance
records. Check free space on the host volume as well as inside WSL: its virtual
disk consumes host space even when the guest reports a large available capacity.
