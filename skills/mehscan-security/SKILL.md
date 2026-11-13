---
name: mehscan-security
description: Run Mehscan on an authorized codebase, review local changes, a pull request or release delta, plan a repository review, or triage Mehscan bundles. Use for Mehscan scans, candidate review, and security reports.
---

# Mehscan security

Default to **Value**: preserve the in-scope native Value candidate queue, identify
consequential source areas the scanner does not represent, and prioritize their
investigations within a shared budget. Start with an adjustable 80% native review /
20% additional AI-discovery allocation. The budget limits execution, not candidate
membership. **Comprehensive** explicitly extends the admitted scope. Changed,
component and category requests constrain either mode; they are scope filters.
Use [review planning](references/review-planning.md) for compact application-aware
planning and bounded source orientation before repository AI work. This orientation
happens in the host agent's current context, not as another full provider review pass.

For an explicitly requested domain review, use [domain review](references/domain-review.md)
and a bound `--domain-plan`. It gives native material three roles: concrete claims
to verify, operation markers guiding flow coverage, and supporting facts. Related
cases can reuse one domain session while retaining separate evidence and decisions.
This opt-in path uses its case plan rather than the ordinary 80/20 candidate queue;
supplied exact-ID triage still requires a disposition for every selected ID.

For a source assignment, use [source review](references/source-review.md): review
the assigned original source, assess existing questions and investigate additional
consequential relationships in the same assigned operations. The AI controller can
assign selected source even when the scanner finds no candidates. New proposals require validated
source and ordinary finalization; examined coverage is separate from verdicts.
During first pass, identify the protected effect and challenge the applicable
authority, lifecycle or interpretation boundary. Follow a deciding cross-file
edge in that investigation; a separate threat model is not a prerequisite.
With no or few scanner candidates, use bounded source reads to select relevant
additional operations; never fall back to assigning all source. Unused native
allocation can fund remaining AI discovery. A native Value candidate already
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
For Rust source, use [Rust security review](references/rust-security.md), available
as `rust-security`. Load `rust-memory` or `rust-boundaries` for the relevant
advisory-derived patterns and verification controls. Rust guidance applies to
source discovery even when native scanning produces no questions.
Use [Rust attack scenarios](references/rust-attack-surfaces.md), available as
`rust-attack-surfaces`, to select the applicable application boundary and verify
the scenario against the candidate's caller, guard and effect.
The ordinary controller uses one configured model with direct source lookups.
The worker's [research API](references/worker-api.md) exposes exact tool arguments,
costs and limits. It differs from the [operator CLI](references/commands.md):
the controller owns scans, state writes, finalization and reports. In manual mode,
use the corresponding native commands and preserve actual query journals.
For an explicitly configured experimental tiered run, use the matching compiled
role sections and [controller commands](references/commands.md#tiered-controller).
Preserve bound profiles, shared budgets and assessment provenance. Never resume
a conversation under another model or turn unresolved disagreement into a
confidence threshold.

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
For an explicitly requested Fast or Full second pass, read
[second-pass review](references/second-pass-review.md). It audits completed claims,
retains the first results and separates model-reviewed labels from training approval.
Fast automatically selects a bounded queue from first-pass scheduling notes and
explicit applicability/impact proof signals;
Full audits every claim in the chosen scope. For an
identified flow whose threat coverage needs enrichment, use
[scoped flow follow-up](references/review-planning.md#scoped-flow-follow-up)
within the authorized scope and budget.

Finish the requested first-pass scope and present findings, grouped root causes,
pending facts, coverage limits and recorded usage before proposing more work.
Use `finding-groups.md` for proposed causal families with every member's
conditions. Raw issue labels and proposed group counts are different measures;
neither is an independently adjudicated vulnerability total. The
[repair/applicability contract](references/runtime-review.md#repair-point-applicability-and-impact)
defines the first-pass annotations and preserves conditional library findings.
Start with the worker's compact `review-options.md` for the proposed Fast queue
and reasons; read JSON only for needed selection details. If no follow-up was
requested and more work is useful, recommend a concrete next scope and ask
the user to choose Fast, a broader Full audit, a scoped threat review or stopping.
When no useful follow-up is identified, state that and finish.
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
| Repository AI review | [Review planning](references/review-planning.md) |

Candidates are leads, not confirmed vulnerabilities. Value keeps admitted native
IDs in its queue and chooses additional AI-discovery operations from actual
source-body evidence. Plan their order around the application's actors, protected
effects, shared controls and coverage gaps. A severity label or filename alone
cannot select AI-discovery scope. Give each operation one owner; reuse cited
helper/control facts while checking every native ID and caller's conditions.
For runtime-bound Value work, `--policy value --selection policy` supplies native
admission hints, while `--source-selection FILE` binds additional AI discovery and
can rank native assignments without dropping queue members. Without the latter,
the default `all` phase prepares a planning checkpoint and stops before AI calls.
Use `--native-share` to choose the initial mix and the shared allowance to bound
execution. Explicit AI-only/native-only endpoints are available; mixed work can
transfer unused allocation when a queue finishes. Follow
[controller commands](references/commands.md) and [review planning](references/review-planning.md)
to select and launch the work. Exact-ID/native-only worker tasks, source profiles,
compiler facts and operation grouping keep their existing paths.
Comprehensive retains completed Value work within the same scope and extends it
to admitted plausible medium-or-higher relationships. Ordinary API occurrences
remain supporting facts. Keep scope and deferred coverage explicit, then finish
the prioritized work within its shared budget. Preserve unfinished native IDs
separately from unselected source coverage; budget exhaustion does not exclude an ID.

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
