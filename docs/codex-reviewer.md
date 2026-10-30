# BYOK Codex reviewer

The bundled adapter, `skills/mehscan-security/scripts/codex_reviewer.py`, reviews
Mehscan evidence using a company-selected Codex CLI and explicit authentication.
It returns structured drafts and research requests to the native engine; the
engine controls queries, findings, fingerprints, finalization and admission.
Value/Comprehensive research profiles remain configurable.

## Configuration

For the tested cost-conscious native workflow, use Terra 6.1 medium with
`"schema_mode": "stable"` and `"source_presentation": "line-addressed-v1"`.
Model access still depends on the configured account. Install the adapter's own
Python requirements before enabling stable mode:

```text
python -m pip install --requirement skills/mehscan-security/scripts/requirements.txt
```

Stable mode sends the unbound wire schema and validates the reply against the
exact current-turn schema locally. Handles, offered claims, query/final-turn
constraints and existing envelope/source checks still apply. Usage and private
continuation state are recorded before a completed reply can be rejected.
`schema-validation-<conversation>.jsonl` records validity and wire/local schema
hashes outside the provider-metrics glob. Missing dependencies fail before
inference. A fresh conversation is required when changing schema mode.

For an auxiliary proof-reference failure, `reply-validation-<conversation>-<round>.json`
records a bounded, exact-task diagnostic. The ordinary worker and experimental
workspace bridge may spend one remaining turn correcting it in the same thread.
Only originally invalid reference slots may change to offered handles; decisions,
reasoning, evidence windows, existing valid references and list structure are
protected. A corrected reply still passes the normal envelope/source checks.
The private exact reply and usage survive rejection. Other schema, provider and
account failures do not receive this automatic correction.

New rejected workspace replies with valid decision components also retain a
private `dispatched-task.json` and public `reply-candidate-<conversation>-<round>.json`
hash binding. The workspace records that binding with the call receipt. Its
`export-candidates` command invokes the adapter's read-only `--inspect-candidate`
operation, checks the original task/context/reply/usage and supplied citations,
and source-validates decisions through the ordinary native finalizer. This makes
a separate candidate available for semantic review; it applies no rejected
actions and performs no inference or native admission. It cannot recover old
sessions lacking these bindings. See [workspace candidate export](review-workspace.md).

Omitting `schema_mode`, or setting it to `"dynamic"`, preserves the existing
bound-wire behavior and has no extra validator dependency. The provider descriptor
is unchanged; configuration fingerprints and private conversation binding retain
the option. Stable native continuations demonstrated substantial cache-adjusted
price savings in the saved studies. Fresh-context workspace calls retain exact
validation but have not demonstrated equivalent cache savings. Cache hits remain
provider-dependent, and neither mode guarantees a hit.

The native worker already supports bounded independent reviewers through
`--workers` (use `1` for serial). Choose concurrency separately from model/schema
or evidence routing; do not transfer shared-fact interpretations or caller
applicability merely because jobs run together. Failed launcher attempts preserve
returned provider events and stderr privately; an absent usage receipt remains
unknown rather than zero.

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

An experimental, optional configuration field selects addressed source input:

```json
"source_presentation": "line-addressed-v1"
```

Omit it, or use `"raw"`, for the original prompt presentation. The opt-in view
replaces text only in explicit, bound source windows/contexts and source-query
results with `L<number> | ...` rows. It does not recursively number arbitrary text,
guidance, discovery previews, signatures or reviewer interpretations. Raw artifacts,
source hashes, handles, physical ranges, source completeness, query/cache receipts
and budgets remain authoritative. Partial columns and clipped excerpts remain
qualified; a byte-range endpoint at the next line's column 1 is not a blank line.
Unsupported source shapes fail before inference rather than receive guessed labels.

Native initial prompts and new continuation facts support this mode. Workspace
replacement contexts address their captured `primary.windows`; their saved facts,
questions, conditions and exclusions remain literal. Existing native continuation
filtering still sends only new facts. The mode is pinned to the private conversation
binding: switching between raw and addressed presentation requires a fresh
conversation. It is also recorded in provider metrics alongside actual prompt bytes
and usage. The provider descriptor below is unchanged; the worker's full reviewer
configuration fingerprint and the adapter's conversation binding retain the mode.

[AQ's offline replay](experiments/review-addressed-input-results.md) checks 57 saved
prompts and physical source recovery. It measures extra displayed bytes, not token
or time savings or improved model citation selection. The mode remains opt-in;
native batching and rule-specific review placement are unchanged.

The later [AR comparison](experiments/review-addressed-pair-results.md) retains
the option: addressed input fixes four selected caller-citation examples, and
completed Sol pairs use fewer calls. Terra's policy pair is slightly slower/larger;
raw Terra Juice is cap-censored by a shared-answer completion gap. These bounded
observations do not establish a whole-app speed win or change the default. The
next controller fix must preserve the source and invalidation guards.

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
