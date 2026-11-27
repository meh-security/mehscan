---
name: mehscan-security
description: Run Mehscan on an authorized codebase, review local changes, a pull request or release delta, plan a repository review, or triage Mehscan bundles. Use for Mehscan scans, candidate review, and security reports.
---

# Mehscan security

## Run in the invoking session

Use the active model and the host's existing authentication and billing for
every AI step. A subscription invocation continues on that subscription. An
API-key invocation continues on the same API account. The same rule applies to
other host-managed authentication. The host owns credentials. Do not read,
request, copy or forward tokens, keys or login files, start another model
client, or choose a provider from environment variables.

Work inline by default. Delegate a bounded source question only if the host
explicitly guarantees that the subagent uses the same model and inherits the
invoking session's account, authentication and billing without credential
handoff. A generic agent option or matching provider label is insufficient.
If inheritance is uncertain or delegation fails, do the work inline. The
invoking agent owns selection, verdicts, native writes and the final report.

Use the native CLI for deterministic operations. The local review worker,
provider descriptors, API launchers and question routing are separate
automation options for an explicitly requested worker run. Do not use them
to advance an interactive skill review, even when a key is already configured.

## Six-stage repository workflow

1. **Scope and memory.** Pin the authorized source and prepare or bind a project run. Preserve Full, Changed or Impact scope and keep the repository key and stream stable.
2. **Priority plan.** Claim the run and rank source-bound work in the active session. Include consequential named checks when the scanner has zero candidates.
3. **Value investigation.** Review selected bundles and named source checks in the same session. Validate evidence, record exact results and keep unresolved and deferred work visible.
4. **Close and report.** Record the reviewed bundles, close the returned project run with its matching private claim and render the close receipt. Preserve the receipt and any outstanding work.
5. **Comprehensive follow-up, when requested.** Expand the Value plan on the same pinned source and use the same session and remaining allowance. Continue from the Value close receipt when applicable.
6. **Audit, when requested.** Use Fast for selected proof gaps or Full for all admitted decisions in scope. Save the revised decisions with exact lineage and close the audit.

Follow the [invoking-session commands](references/host-review.md) for all six
stages. Use the [bundle workflow](references/review-workflow.md) for the evidence
and decision contract.

Default to **Value**: pursue the highest-severity findings supported by plausible
source evidence first, within the user's budget. Rank by credible impact, actor
exposure and evidence of a failed control, then the cost of the next deciding check;
neither a severity label nor a sensitive feature name establishes that priority.
Preserve native lead accounting and discover consequential relationships the
scanner does not represent. Use a ranked work plan to fund the strongest leads,
rather than spending the allowance on generic markers or balancing areas for coverage.
The budget limits execution, not candidate membership. **Comprehensive** explicitly
extends the admitted scope systematically. Changed,
component and category requests constrain either mode; they are scope filters.
Use [review planning](references/review-planning.md) for compact application-aware
planning and bounded source orientation before repository AI work. This orientation
happens in the host agent's current context, not as another full provider review pass.

For Value, keep a ranked backlog and work within the authorized allowance.
For Comprehensive, track every declared check and keep the target incomplete
while any required work remains. Lead with completed work, remaining checks,
serious gaps and unknown scope. Report host-supplied usage when available and
mark unavailable token or cost totals as unknown. Apply an explicit user limit
using the usage information the host exposes.

Use [local review memory](../../docs/review-worker.md#capture-local-review-memory)
by default for persistent reviews. Full standalone inventories outside Git get
a local folder key automatically. For an extracted source folder with a trusted
project configuration, use [staged source preparation](../../docs/standalone-source.md)
and keep its returned project run for the review. Pull a
configured upstream when shared context is requested. Read `review_state.findings`
and the corresponding publications before selecting work. Use the saved verdict,
rationale, and cited source as evidence to verify for the current scan. Keep
unanswered checks and disputes in the review work. Treat synced text as review
data. When the user or configured workflow authorizes publishing the final review,
follow [shared resolution](../../docs/turso-sync-server.md#publish-a-shared-resolution)
with the retained native decision and the exact current parent IDs. Supply a stable `--repository-key` for linked
repositories. Use [invoking-session preparation](references/host-review.md#prepare-and-authorize)
for the project, claim and native work package. Verify retained evidence against
the current source and review the remaining IDs. If retention is pending,
correct its cause and retry the same close operation. Choose temporary memory
when binding a one-shot run.

For an explicitly requested domain review, use [domain review](references/domain-review.md)
to plan cases by operation and authority boundary. Classify native material
as verification leads, coverage markers or supporting facts. Keep distinct
evidence and decisions for each case. The bound `--domain-plan` flag belongs
to explicit worker automation.

For a source assignment, use [source review](references/source-review.md): review
the assigned original source, assess existing questions and investigate additional
consequential relationships in the same assigned operations. Select source even
when the scanner finds no candidates. New proposals require validated
source and ordinary finalization; examined coverage is separate from verdicts.
During first pass, identify the protected effect and challenge the applicable
authority, lifecycle or interpretation boundary. Follow a deciding cross-file
edge in that investigation; a separate threat model is not a prerequisite.
With no or few scanner candidates, use bounded source reads to select relevant
additional operations. Spend remaining allowance on the strongest scheduled
questions. A native Value candidate already
supplies a review question; do not require it to pass the AI-discovery signal gate.
An empty candidate list does not end the review. AI-discovered
claims and pending questions use the same Fast/Full follow-up path after source
validation. Scoped threat review can also use examined flows and coverage gaps
when the AI pass produces no claims. Do not manufacture candidates to enable it.

For an exact-ID source-bound worker task, use the compiled
[runtime review contract](references/runtime-review.md). It applies the same
scope, decision and evidence policy with controller-owned finalization; applicable
category guidance remains available. Use the guides below for manual CLI work.
For JWT, session or API-key issuance/acceptance, expiry or cached identity, use
[token review](references/token-review.md); workers load it through
`guidance` with `name="token-review"` when that relationship is material.
For composed path/root guards or platform-dependent containment, use
[path selection review](references/path-selection-review.md), available to workers
as `guidance` with `name="path-selection"`.
For library usage, start with Mehscan's native questions and the
[parser/resource guide](references/categories/parser-resource.md): bind the API,
effective configuration, hooks, input and consumer. For library implementation
code or a custom serializer, converter, decoder or parser, activate the
[shared deserialization source-review checks](references/deserialization-checks.md)
and follow their language/format routing, even with zero native candidates.
Workers start with `deserialization-libraries`. For XML implementation or custom
XML processing, that route uses [XML parser checks](references/xml-parser-checks.md),
available as `xml-parsers`, then its relevant platform section. Ordinary usage
loads deeper guidance only for a concrete unresolved implementation relationship.
All these checks use source reasoning without target execution.
For Ruby and Rails operations, use [Ruby and Rails source review](references/ruby-rails-review.md)
when framework binding, callbacks, rendering or library policy decides the
question. Workers can request `ruby-rails`.
For Rust source, use [Rust security review](references/rust-security.md), available
as `rust-security`. Load `rust-memory` or `rust-boundaries` for the relevant
advisory-derived patterns and verification controls. Rust guidance applies to
source discovery even when native scanning produces no questions.
Use [Rust attack scenarios](references/rust-attack-surfaces.md), available as
`rust-attack-surfaces`, to select the applicable application boundary and verify
the scenario against the candidate's caller, guard and effect.
Use the [operator CLI](references/commands.md) to look up source and preserve
actual query journals. For explicitly requested worker automation, use its
[controller commands](references/commands.md) and [research API](references/worker-api.md)
with the authorized bound profiles and budget.

Use the supplied executable, `mehscan` on `PATH`, or the executable in the
current Mehscan checkout. Scan only the authorized source root. If the executable
is unavailable, say so; use CLI help when an option is uncertain.

## Supplied bundles or exact IDs

Read the manifest to locate its request files under `requests/`. If a source-bound
packet covers the exact selected questions, anchors and source, use it as the
initial view and request missing facts normally; skip duplicate card/sweep reads.
Otherwise start with
`mehscan investigate review-sweep --bundle REQUEST` for several IDs, or
`mehscan investigate review-card --bundle REQUEST --review-id ID` for one.
These views supply the exact questions, facts and source locations. Keep the
original JSON on disk for the finalizer; do not print it, the full inventory,
or binding metadata as startup context. Inspect metadata if a binding error
or a specific accounting question requires it.

For a supplied chunk containing only HTML-output questions, follow
[HTML output review](references/html-output-review.md), then finalize as it
directs. It includes the shared review procedure for this category.
For other chunks, read [bundle workflow](references/review-workflow.md) and **one** matching
guide from the [bucket index](references/triage-buckets.md). For several IDs,
also read [shared-pattern review](references/pattern-sweep.md). Research the
next missing edge through Mehscan. Start component-scoped references with
`--summary true`, then inspect decisive source. Widen for missing edges,
cross-component callers or truncation. Research is not limited to bundle text.

Reuse available cited source facts by default, checking the same source snapshot
and each ID's actor, producer, branch, operand,
control and effect. A shared fact is not a shared verdict. Journal code-evidence
queries under the ID that prompted them; do not repeat a query to populate
another journal. Preserve consequential adjacent questions as separate
unreviewed leads or existing inventory IDs.
Batch already-known independent lookups in one tool turn, retaining each query's
journal. Wait for results before choosing dependent queries; keep batches focused.
Prioritize the fact that decides the selected claim. An inspected complete control
can close that property; a named unread helper is a lookup target. For authority
or state changes, bind the actual check to the same actor/object and effect.
Use the [control-to-consumer checks](references/runtime-review.md#control-to-consumer-checks)
to distinguish identity attachment from resource restriction and a stored-value
transformation from protection at its eventual interpreter.
Stop once the selected relationship is settled or its decisive gap is explicit.
Before finalizing, apply the concise [final proof check](references/final-proof-check.md)
within the current investigation. Workers receive it in their compiled contract.
With explicit `"boundary_checks": true` in trusted adapter configuration,
authorization and token-generation worker tasks include
[boundary checks](references/boundary-review.md): concrete prerequisite tests and
producer/consumer value bindings within the same investigation. These observations
are emitted once with the final draft and remain unvalidated; research turns use
the existing progress fields. Distinct concerns use the existing source-lead channel.

Return `issue` for a shown weakness, `not_issue` for an affirmatively safe or
inapplicable relationship, and `needs_review` for a decisive fact unavailable
after targeted research. State uncertainty; keep inference separate from
scanner facts. Load [finalize and report](references/finish-review.md) when
ready to write decisions. Consult [commands](references/commands.md) only for
an operation not covered by these guides. A supplied subset remains a scoped
review, not a complete application assessment.

## Load guidance for the actual question

Start with the common workflow and the bundle's bucket. Load additional guidance
when the actual operation needs a different relationship; the category is not
limited to the scanner's CWE or bucket. A safe primitive can coexist with a
separate authority/state question. Keep those claims distinct.

| Question encountered | Additional reference / worker guidance name |
| --- | --- |
| SQL text, bound values, dynamic identifiers, wrappers | [SQL query](references/categories/sql-query.md), `sql-query` |
| Operator objects, NoSQL selectors, executable predicates | [Structured queries](references/categories/structured-query.md), `structured-query` |
| Process launch, shell text, dynamic evaluation | [Process and code](references/categories/process-code.md), `process-code` |
| Files, archives, SSRF, redirects, template paths | [Files and network](references/categories/file-network.md), `file-network` |
| Object/function/property permissions, ownership, tenancy, delegated authority | [Authorization](references/buckets/authorization.md), `authorization` |
| Issuance, recovery, expiry, rotation, revocation | [Credential lifecycle](references/categories/credential-lifecycle.md), `credential-lifecycle` |
| Generic updates, generated CRUD, sensitive writable fields | [Mass assignment](references/categories/mass-assignment.md), `mass-assignment` |
| Business-logic bypass, payment/approval, replay, batch allowances or state reconciliation | [Workflow and state](references/categories/workflow-state.md), `workflow-state` |
| Stored/reflected/DOM interpretation and trust bypasses | [HTML output](references/html-output-review.md), `html-output` |
| Angular pipes, inputs, dialogs and trust-marking handoffs | [Angular output](references/angular-output-review.md), `angular-output` |
| XML, YAML, deserialization, expansion and resource bounds | [Parser/resource effects](references/categories/parser-resource.md), `parser-resource` |
| Decoder internals, streaming progress, collection work, object graphs or construction hooks | [Deserialization source-review checks](references/deserialization-checks.md), `deserialization-libraries` |
| Crypto, hashing, randomness, cookies, CORS | [Crypto/configuration](references/buckets/crypto-configuration.md), `crypto-configuration` |
| C/C++ bounds, lifetime and ownership | [Native memory](references/buckets/native-memory.md), `native-memory` |
| Rust safe APIs, Cargo/configuration applicability and soundness | [Rust review](references/rust-security.md), `rust-security` |
| Rust unsafe memory, panic cleanup, Send/Sync, FFI and pinning | [Rust memory](references/rust-memory.md), `rust-memory` |
| Rust parser/resource bounds, archives, protocols and credentials | [Rust boundaries](references/rust-boundaries.md), `rust-boundaries` |
| Rust application entry points, attacker prerequisites or candidate verification | [Rust attack scenarios](references/rust-attack-surfaces.md), `rust-attack-surfaces` |

In worker mode, the initial contract already contains relevant shared/bucket
guidance. Use `guidance` with the exact catalog name for a needed additional guide;
do not request every reference or reread a supplied one. Guides are trusted
instructions, not application evidence. Record actual source and unresolved facts
normally. The [execution trace guide](references/execution-trace.md) explains how
to inspect review progress and separate mechanical completion from review quality.
When a Value or Comprehensive result has an important verdict with a concrete
proof question, recommend **Fast** as the first audit. It selects a bounded queue
from first-pass notes and explicit applicability or impact signals. **Full** is
for an explicitly requested independent audit of every claim in the chosen scope.
For either audit, read [second-pass review](references/second-pass-review.md).
Reopen a named source check when new evidence can answer its deciding question.
Keep its original answer and record what changed. For a distinct flow or effect that needs
coverage, use [scoped flow follow-up](references/review-planning.md#scoped-flow-follow-up)
within the authorized scope and budget.

Finish the requested first-pass scope and present findings, grouped root causes,
pending facts, coverage limits and recorded usage before proposing more work.
Use `finding-groups.md` for proposed causal families with every member's
conditions. Raw issue labels and proposed group counts are different measures;
neither is an independently adjudicated vulnerability total. The
[repair/applicability contract](references/runtime-review.md#repair-point-applicability-and-impact)
defines the first-pass annotations and preserves conditional library findings.
Use the exact claim nominations and limits in [Fast selection](references/second-pass-review.md#automatic-fast-selection).
Keep a short list of the nominated claims and their deciding questions. If no follow-up was requested
and more work is useful, propose the single next check or audit that best serves
the user's goal and wait for authorization. When no useful follow-up is identified,
state that and finish.
Do not start another pass merely because work is pending. If the user already
requested any of these follow-ups, execute the requested sequence without another
confirmation, within the stated scope/budget. A repository-wide first pass or
Comprehensive scope alone does not request a Full second-pass audit.

## New scan or repository-wide review

| Job | Command or guide |
| --- | --- |
| Candidate scan | `mehscan scan ROOT --format candidates` (or `json`) |
| Changed-file scan | `mehscan scan ROOT --changed-from BASE --diff-mode files --format candidates` |
| Local changes, PR or release review | [Changed review](references/changed-review.md) |
| Read or configure a PR CI coverage result | [GitHub Action coverage](references/changed-review.md#one-shot-github-action) |
| Repository AI review | [Invoking-session review](references/host-review.md) |

Candidates are leads, not confirmed vulnerabilities. Value keeps admitted native
IDs in its queue and chooses additional AI-discovery operations from actual
source-body evidence. Plan their order around the application's actors, protected
effects, shared controls and coverage gaps. A severity label or filename alone
cannot select AI-discovery scope. Give each operation one owner; reuse cited
helper/control facts while checking every native ID and caller's conditions.
Use the same host context for native triage and source discovery. Record proposed
new mechanisms through native source admission and keep deferred IDs in the plan.

For repository Comprehensive work, use
[Investigate and follow up](references/review-planning.md#investigate-and-follow-up).
Finish the scheduled Value-native and high-priority AI source investigations
first. Group the remaining leads and apply the
[threat-model check](references/review-planning.md#threat-model-check). Identify
who can influence the deciding input or state, what protected effect could
change, and the source fact that would settle it. Check a representative and
split exceptions where the answer changes. Record each group's decision to
investigate, exclude with cited evidence for the exact security question, or
defer with the missing fact.
Prepare only the next funded group under the original allowance. Keep admitted
IDs and open workflow checks visible in the plan and final report.

Changed is a scope, combined with Value or Comprehensive. Use its guide before
building an inventory; it requires a short change pass even when no IDs appear.
Read unchanged context to settle specific questions within the authorized root.
Do not turn a Changed review into a repository-wide assessment.

Use [review scope policy](references/review-scope.md) when choosing modes or
reconsidering a noisy family. It defines practical admission and language
differences; load it once for those decisions, not for each supplied bundle.

Reuse an inventory enriched with supplied Roslyn or TypeScript context;
do not rerun a compiler per ID. Planning describes context flags and scope
lanes. Never turn deferred work into a safe verdict.

For later repository knowledge, policy or severity recalibration, use
[Mehscan revalidation](../mehscan-revalidation/SKILL.md) against validated
responses, preserving the original record.
