# AI reviewer contract: findings, verification, and control ownership

Mehscan gives an AI reviewer observations and bounded candidates, not confirmed
vulnerabilities. The reviewer must distinguish a defect demonstrated by the
available evidence from a control whose effective state cannot be determined
from the application repository alone. This policy applies across languages,
frameworks, and deployment technologies.

## Decision contract

The model-facing response is deliberately compact. Every supplied review
neighborhood must receive exactly one result:

```json
{
  "review_id": "review-example",
  "decision": "issue | not_issue | needs_review",
  "confidence": "high | medium | low",
  "summary": "At most two sentences explaining the decision.",
  "checks": ["Only the smallest decisive checks still required"]
}
```

`confidence` expresses confidence in the decision, not vulnerability severity.
Use `needs_review` only when a named missing fact could change the decision;
otherwise return `issue` or `not_issue`. `checks` are required for
`needs_review` and prohibited for final `issue` or `not_issue` decisions.
Internal scanner fields such as null path identifiers, promotion
guards, flow-status labels, and individual verification booleans are not part
of this response.

Provider output is wrapped with only the compatibility data needed to validate
it against the exact input:

```json
{
  "schema_version": "1.0",
  "bundle_fingerprint": "review-bundle-...",
  "results": []
}
```

Bundle responses echo `bundle_fingerprint` rather than `job_fingerprint` and
are validated with `mehscan investigate review-bundle-triage --bundle REQUEST
--responses RESPONSE`. Validation rejects stale fingerprints, unknown,
duplicate, or missing review IDs, unsupported enum values, unknown JSON
fields, empty or oversized prose, duplicate checks, unresolved decisions
without a check, and final decisions that still retain checks. The legacy C#
neighborhood endpoint continues to use `neighborhood_id` and a job
fingerprint.

After every bundle validates, `mehscan report` joins the compact verdicts back
to deterministic rule, location, and flow evidence. See
[`output-contract.md`](output-contract.md); models must not author final finding
JSON or SARIF directly.

Before confirming injection, establish a compatible producer representation and
consumer operation, the value's survival through intervening helpers using the
supplied language/reference/mutation semantics, and the relevant attacker
influence. An unknown helper proves neither safety nor continued unsafe flow;
server metadata alone does not establish arbitrary attacker-selected content.
Apply helper excerpts only to their exact callable and owner. For a decision-ready
observation lacking that relationship, dismiss the bounded claim without asserting
whole-component safety. Concrete supplied unresolved facts retain their normal
`needs_review` contract.
Preserve directly shown unsafe branches and request-derived container values:
the branch condition or a dynamic property selector need not itself be attacker
controlled when the shown branch or selected value establishes the weakness.

The more detailed control-ownership contract below remains available for
configuration and deployment questions. Its internal `confirmed` and
`needs_verification` dispositions correspond to final `issue` and
`needs_review` decisions respectively.

Emit no finding when the concern is disproved. Otherwise emit exactly one of:

| Disposition | Meaning | Required action |
| --- | --- | --- |
| `confirmed` | Supplied evidence establishes the weakness and the authoritative owner | `fix_application` with `application`, or `fix_control_layer` with a known layer |
| `needs_verification` | The concern is plausible, but effective behavior depends on evidence not supplied | `verify_effective_control`, plus concrete verification steps |

Allowed control layers are `application`, `framework`, `reverse_proxy`,
`api_gateway`, `service_mesh`, `platform`, `client`, and `unknown`.

Example review-only result:

```json
{
  "cwe": "CWE-693",
  "location": { "path": "server.ts", "line": 42 },
  "disposition": "needs_verification",
  "recommended_action": "verify_effective_control",
  "control_layer": "unknown",
  "verification": [
    "Inspect the final externally visible HTTPS response for this route in each deployed environment",
    "Inspect framework, ingress, reverse-proxy, CDN, and API-gateway header policy for overrides or stripping"
  ],
  "rationale": "No application header policy is visible, but the repository does not establish the effective deployed response"
}
```

If that verification proves the header absent, the final recommendation should
change to `confirmed` plus `fix_control_layer` at the authoritative layer. Do
not prescribe duplicate application middleware unless there is a specific
defense-in-depth or local-development requirement.

## Controls that commonly cross layers

| Control | What source can establish | What may require deployment verification |
| --- | --- | --- |
| HSTS, CSP, framing, MIME sniffing, referrer and permissions policy | Explicit application/framework policy, including obviously unsafe values | Final response by route, status, host, protocol, and environment; gateway/CDN additions, overrides, duplicates, or stripping |
| CORS | Explicit origin and credentials logic in code | Policy applied by gateway/proxy; preflight and actual response behavior; route-specific overrides |
| Cookie flags | Options passed by the application or framework | Final `Set-Cookie`; proxy rewriting; framework defaults; HTTPS termination and cookie scope |
| Inbound TLS | Listener configuration owned by the repository | TLS termination at ingress, load balancer, gateway, or platform |
| Authentication, authorization, CSRF, and rate limiting | Checks visible on the application path | Enforcement performed before the request reaches the application, including route coverage and bypass paths |
| Cache and sensitive-response policy | Explicit response/cache directives | CDN, gateway, browser-visible response, and cache-key behavior |

Outbound client TLS verification, command construction, query construction,
unsafe deserialization, dynamic-code execution, and similar code-owned behavior
usually cannot be excused by an unrelated inbound proxy. Review ownership per
data path rather than treating every configuration observation as externally
compensable.

## Evidence standard

For an effective-control review, request the smallest decisive artifact:

1. The final externally observable response or handshake for the affected
   route, host, protocol, and environment.
2. The authoritative framework, ingress, reverse-proxy, gateway, CDN, service
   mesh, or platform configuration responsible for that behavior.
3. Evidence that the control covers the vulnerable route and cannot be bypassed
   through an alternate host, direct origin, internal listener, error response,
   WebSocket path, or environment.

Source presence is evidence, not proof of effective deployment: a later layer
can overwrite or remove a header. Source absence is also not proof of absence:
a trusted outer layer can add the control. The reviewer rationale must say what
is known, what is unknown, and why the requested evidence resolves it.

## Scanner boundary

Deterministic candidates keep their current evidence-first meaning and do not
receive automatic severity or remediation verdicts. Configuration observations
should generally be passed to the reviewer as contextual facts. Explicitly
unsafe values may justify stronger candidates, but missing repository-local
configuration alone should normally begin as `needs_verification`.

Evaluation pack schema `1.1` embeds this contract in every trial. Evaluation
response schema `1.1` requires `disposition`, `recommended_action`,
`control_layer`, and (for review-only results) at least one `verification` step.
Candidate-assisted trials also carry standalone `configuration_reviews`. These
are intentionally separate from security-path candidates: they ask the reviewer
to establish effective ownership and behavior without inventing a data flow.
