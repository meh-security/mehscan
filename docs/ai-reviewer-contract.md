# AI reviewer contract

Mehscan's observations and bundles are review leads, not confirmed vulnerabilities. The [security skill](../skills/mehscan-security/SKILL.md) defines the current review workflow and response format. Use its bucket guides to check the relationship appropriate to the CWE.

## Verdict standard

- `issue`: source evidence establishes the selected weakness and its reachable effect.
- `not_issue`: source evidence affirmatively disproves that weakness for the selected operation.
- `needs_review`: one named, decision-changing fact remains unavailable after targeted queries. State the check needed to resolve it.

Confidence measures certainty in the verdict, not impact. Keep scanner facts, retrieved source, and reviewer inference distinct. Verify the exact value, branch, actor, resource, and operation; a helper name or adjacent check is not proof of an effective control. If a review uses external deployment behavior, state what the repository establishes and what deployed artifact must be checked.

## Control ownership

Application source may show framework policy or local authorization, but an effective deployed control may depend on a proxy, gateway, service mesh, or platform. For headers, CORS, cookie flags, inbound TLS, and gateway authorization, verify the affected route, host, environment, and any bypass path before assigning an owner or a verdict. Source absence alone does not prove deployed absence. An inbound proxy does not settle outbound TLS, command construction, unsafe deserialization, or another code-owned behavior.

The reviewer returns schema 1.3 results to Mehscan; Mehscan validates them and joins verdicts to deterministic evidence in the final report. See [AI triage contract](ai-triage-contract.md) and [output contract](output-contract.md).
