# BYOK Codex reviewer

The bundled adapter, `skills/mehscan-security/scripts/codex_reviewer.py`, reviews
Mehscan evidence using a company-selected Codex CLI and explicit authentication.
It returns structured drafts and research requests to the native engine; the
engine controls queries, findings, fingerprints, finalization and admission.
Value/Comprehensive research profiles remain configurable.

## Configuration

Install a trusted Codex CLI outside target source. Pin its package/version in the
workflow. Create configuration and private session storage outside the checkout
and the entire artifact upload directory:

```json
{
  "schema_version": "1",
  "executable": "/TRUSTED/codex",
  "executable_version": "EXACT_INSTALLED_VERSION",
  "model": "gpt-6-luna",
  "reasoning_effort": "medium",
  "auth_file": "/PRIVATE/codex-auth.json",
  "private_directory": "/PRIVATE/provider-sessions"
}
```

Use an explicit Codex authentication JSON file supported by the chosen CLI.
Credentials are never discovered from inherited workflow environment variables.
The selected model must be available to that authentication lane; there is no
fallback model or automatic login. The adapter copies only this authentication
file into its private Codex home and preserves refreshed authentication on resume.
Create the parent of `private_directory`; the adapter creates and marks its own
store. It refuses arbitrary existing directories or incompatible stores.

Export the provider descriptor:

```text
python TRUSTED/skills/mehscan-security/scripts/codex_reviewer.py --config PRIVATE/codex.json --contract
```

Save the output as `PRIVATE/provider.json`. The descriptor contains provider, client
version, model and effort, with no executable hash or launcher policy. Supply it
as `--provider-contract FILE` to native runtime/plan preparation, bound
plan/work/record commands and the worker. The Action accepts `provider-contract`.
Model/effort/version changes require fresh work. Engine/skill package integrity
checks remain mandatory. Metadata establishes compatibility, not authentication
of the producer or process isolation.

Use this trusted reviewer argv file outside exported artifacts:

```json
["/usr/bin/python3", "/TRUSTED/skills/mehscan-security/scripts/codex_reviewer.py", "--config", "/PRIVATE/codex.json"]
```

The worker checks this bundled adapter and its configuration against the native
binding. See [the handoff consumer](github-action.md#active-review-handoff-local-integration-preview).

## Execution and continuation

No Mehscan bubblewrap wrapper, binary staging, root rejection or Linux-only gate
is required. Use a disposable company-managed or GitHub-hosted runner; the company
owns host isolation and provider-account administration. Ubuntu/WSL2 is useful
for Linux integration testing, not an additional security prerequisite.

Every start/resume uses Codex's supported analysis-only tool controls, a private
working directory, disabled project/user instructions and rules, strict config,
structured output and upstream permissions denying generated writes/network.
The packaged `reviewer-base.md` replaces the client's built-in coding-agent
instructions through `model_instructions_file` on both starts and continuations.
The runtime contract and requested category guidance supply review-specific detail.
Shell, apps, plugins, hooks, delegation and applicable browser/computer tools are
disabled. Only the small required set of tool controls is checked; unrelated new
client features are not automatically disabled. Incompatible CLI versions fail
before a review. No repository build scripts or installations execute.

The provider client retains inference networking and may write its own private
session state. This adapter is not a process sandbox and does not contain a
malicious client. Output tool-event rejection is an admission check, not proof of
process containment. The investigator must have no GitHub write token or unrelated
cloud credentials; optional publication belongs to a separate trusted job.

Continuations use the exact UUID with unchanged packet/schema/provider bindings,
monotonic rounds and only new facts. Missing state never silently restarts, and
`--last` is never used. Deadline/cancellation terminates the client; POSIX launches
also terminate its process group. Private prompts, diagnostics, authentication
and session state stay outside exports. Metrics contain provider settings, timing,
prompt bytes and reported token counters, not raw diagnostics or credentials.
Codex completion counters accumulate across the resumed conversation. The adapter
stores the baseline in private session state and exports per-turn deltas with
`usage_basis: conversation_delta`; summing resumed totals would double-count
earlier calls. Numeric cumulative counters remain in provider metrics for audit.
Missing baselines or reset counters remain unknown for that turn.
These are reported usage measurements, not hard currency budgets.

## Acceptance

Deterministic tests exercise protocol, actual subprocess launch, start/resume,
authentication refresh, failures, deadlines and native admission. They do not
establish live model quality or actual upstream tool enforcement. Local live
Luna/medium acceptance completed four synthetic PR reviews on Windows, then six
reviews on Ubuntu release. Two multi-file cases used native source queries for
unchanged helpers and two exact-session continuations each. Corrected usage sums
matched the client session counters. The Action can execute this adapter with
opt-in `provider-config`; actual hosted GitHub/company-auth acceptance remains pending.
Current Codex clients emit an intentional disabled-Code-Mode startup notice as an
error item. The adapter accepts only that exact notice before execution; all other
errors and tool attempts remain rejected. First accept an
artifact-only same-repository workflow, then a separate publisher and explicitly
authorized fork scans. No GitHub App is needed for that first slice.

Upstream reference: [Codex CLI options](https://learn.chatgpt.com/docs/cli/reference)
and [configuration](https://learn.chatgpt.com/docs/config-file/config-reference).
