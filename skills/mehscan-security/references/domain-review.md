# Domain review

Use this guide for an explicitly requested domain review with `--domain-plan`.
The ordinary mixed Value path and exact-ID candidate triage retain their existing
rules. Domain review organizes application work around protected operations and
shared implementation knowledge while preserving source-bound case assessments.
The initial path supports a fresh Value `all` phase. Use `--domain-plan FILE`
instead of `--source-selection`; it does not combine with source-result reuse,
resume, `--first-pass`, second pass, operation grouping or tiered review. A
nondefault `--native-share` is rejected because domain cases use one ordered work
plan rather than separate origin-based allocations.

## Plan cases and evidence roles

Start with the native inventory and bounded source orientation. Identify the
actual actor or local contract, protected effect, applicable control and next
deciding fact. Keep native IDs and source anchors available for precise lookups;
do not reduce a domain to counts or a filename shortlist.
For Value, order cases by the [strongest credible security impact](review-scope.md#value-priority-and-continued-spending),
regardless of native or AI origin. Domain affinity saves research; it is not a
reason to fund a weaker case ahead of an unrelated stronger lead. Keep each case
focused on a consequential control question and a deciding fact rather than a
general review of every property in that area. An evidence-supported failure
hypothesis guides deeper investigation; do not invent one from a Cover marker.
Broad systematic coverage is Comprehensive.

Assign material a role according to its source evidence, independently of whether
the scanner or AI supplied it:

| Role | Planning decision | Assessment obligation |
| --- | --- | --- |
| `verify` | A concrete possible failure merits investigation. | Assess each selected verification ID within its actual caller/effect conditions. Budget-deferred verification stays unreviewed. |
| `cover` | A consequential operation or property needs coverage, but a specific failure is not established. | Examine the owning flow/property and report the limits. Do not manufacture a vulnerability claim or a negative verdict for every marker. |
| `context` | An implementation, policy, configuration or other supporting fact helps decide another question. | Reuse cited evidence only where its source and applicability match. It owns no independent review job. |

Native priority hints and CWE labels do not decide these roles. Retain the
classification reason. An unknown caller or deployment condition does not by
itself demote a source-backed failure indication to context. Unclassified or
unselected material remains unreviewed, never implicitly safe.

A case may combine verification claims, coverage markers and supporting context
for the same protected operation. Additional AI-native cases need no native IDs;
they still require an actual source-backed question and ordinary proof validation.
If coverage work exposes a concrete mismatch, propose a separate source claim
with the deciding source evidence and applicability conditions.

## Choose a coherent domain

Related cases can share a domain when they reuse an actual implementation,
control or configuration contract. A base query repository and its callers can
share construction facts. A permission implementation can inform several actions
while each action retains its actor/resource/effect checks. Different backends,
policies or caller conditions require their own applicability reasoning.

Do not gather all database or billing code under one unbounded reviewer merely
because it shares a category. Use a small ordered case queue. Keep each case's
scope and stopping condition concrete; finish a settled property early and name
the exact unread edge when it cannot be resolved.

Within a domain the reviewer proceeds sequentially and seals each case's result.
Independent domains may run in parallel. The session can retain relevant inspected
source, but the controller owns evidence provenance and case identity. Shared facts
are not shared verdicts. Independent Full audits use their separate review path.

## Bound manifest

Save the domain plan outside the source root. Copy its exact bindings and
assignment IDs from the current native `source-review-plan` output. Each case
uses one existing source assignment and an owner range within one of its original
windows. Its signal cites source ranges in the same bound plan.

```json
{
  "schema_version": "mehscanDomainPlan/v1",
  "source_plan_id": "EXACT_SOURCE_PLAN_ID",
  "source_fingerprint": "EXACT_SOURCE_FINGERPRINT",
  "domains": [{
    "id": "record-permissions",
    "title": "Record updates under the shared permission implementation",
    "shared_facts": [],
    "cases": [{
      "id": "record-owner-update",
      "assignment_id": "EXACT_SOURCE_ASSIGNMENT_ID",
      "owner_path": "src/handler.py",
      "start_line": 20,
      "end_line": 65,
      "question": "Can this actor change the owner of the selected record?",
      "protected_effect": "Update the record's owner",
      "area": "record authorization",
      "reason": "The caller selects a record before an ownership update",
      "next_deciding_fact": "Whether the guard binds this actor to this record",
      "signal": {
        "kind": "source_relationship",
        "evidence": [{"path": "src/handler.py", "start_line": 40, "end_line": 46}]
      },
      "review_roles": {
        "verify": ["EXACT_NATIVE_REVIEW_ID"],
        "cover": [],
        "context": []
      }
    }]
  }]
}
```

Each role list contains exact native IDs belonging to that case's original
assignment. An ID has one role in one case; the case's `reason` records the
classification basis. Leave all three lists empty for an AI-native case. IDs not
listed in a case remain explicit unclassified/deferred work. A supplied exact-ID
triage request requires individual assessments and should use the existing
candidate path instead of converting its required IDs into coverage markers.

Optional `shared_facts` contain `path`, `start_line` and `end_line` source citations
within the bound native plan. The controller attaches the exact quoted source
and hash. Do not provide unbound prose as an established fact. Supporting SQL,
models and declarations outside assignment windows remain available through
targeted research; they are not preloaded because a domain might need them.

The manifest permits at most eight domains, eight cases in one domain and 32
cases overall, with distinct domain/case IDs. Each original source assignment
belongs to one case. Keep the manifest compact; the controller rejects oversized
or stale input before provider calls. Unknown native IDs, duplicate role
membership and citations outside the bound plan are invalid.

## Budget, reporting and reuse

`--domain-session-mode shared` keeps a thread across the domain's cases. For an
explicit comparison, `isolated` creates a fresh thread for each case while keeping
the case plan and controller-validated shared evidence unchanged. Both modes
share the original global budget. Isolation does not disable applicable fact reuse
and is not an independent audit with earlier evidence withheld.

The domain plan orders funded cases; an origin-based native/AI split is not
automatically imposed on it. Honor the original overall call/input/deadline
allowance across all cases, domain sessions and finalization. Closing one case
does not create another allowance. Keep unstarted cases and unresolved questions
visible at the budget stop.

There is no automatic resume of an interrupted domain session in this initial
path. A failed or incomplete case stops further cases in that domain; completed
siblings and their receipts are retained. Do not replay paid work to fill gaps.

Report explicit claim assessments separately from flow/property coverage and
supporting fact use. Markers incorporated into a case do not automatically become
`not_issue`. Preserve every assessed claim's source, actor, operands, effective
configuration and caller conditions. Native validation establishes source bytes
and membership, not exploitability or deployment applicability.

The adapter keeps common instructions and domain context stable and appends new
case/evidence content to its bound conversation. This can preserve reusable input;
it does not guarantee a provider cache hit. Inspect actual cached-input and
uncached-input counters, context growth and latency. Avoid growing a conversation
or repeating material just to increase its cache percentage. Controller evidence
storage remains the source of truth if a new session is required.
