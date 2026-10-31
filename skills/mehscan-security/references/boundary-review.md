Boundary checks are short, source-bound tests of application behavior,
not an additional model stage or a request for private reasoning. For each offered
ID, examine the selected operation and one directly connected security effect.
Record a concrete input/state/path example and the result the inspected code
produces. The application effect is a change, disclosure, delivery or grant of
authority; merely calling a cryptographic primitive is not that effect. Follow
the immediate application caller when a primitive alone hides its purpose.
Use only a requirement evidenced by code/configuration/tests; do not
invent business policy. If no requirement/effect is established, say so.

Before investigating incidental library helpers, test the local enforcement
relationship already in view: could the effect occur when its stated prerequisite
is false? Evaluate a relevant edge case concretely, rather than paraphrasing that
a guard exists. For an operation spanning multiple endpoints, compare the actual
identifiers/values produced, accepted and changed. Similar names or individually
correct APIs do not establish that they refer to the same authority or state.
Choose only the relevant relationship, not an exhaustive checklist or caller tree.

For token operations, distinguish primitive construction/verification from whether
the application should issue, deliver, accept or revoke that credential on this
path. For authorization, establish the actual protected effect and rejection;
an intentionally public/current-user action need not have a separate owner guard.
If you have only seen one side of a deciding relationship, use native lookup for
the other side within the original budget. A concrete local counterexample must
not be lost while investigating an unrelated external API.

Use these relationships to choose decisive lookups during the investigation.
On research or handoff turns return boundary_checks=[]; keep the deciding unread
relationship in the existing working_chain/progress, without emitting the tables.
Complete the tables once on action=final, including when no research was needed.

Build two small final evidence tables, not an arbitrary illustrative test. controls
records the directly visible application prerequisites governing this effect:
condition, where failure is enforced, and the actual result on a false or boundary
case. Consider the shown alternative branches that can reach the same effect.
Do not replace the application's acceptance conditions with only the primitive's
algorithm settings or a trivial test for input presence.

value_bindings records authority-bearing values this action consumes or changes:
origin (the actual producer expression), presented_as, and effect_key (the actual
value used to select the affected object/credential/state). Follow the producer
when it is unread. A request cookie/header/parameter is transport, not the origin
of its authority. A wrapper can contain a different identifier; compare actual
values and expressions, not the shared label 'token', 'user' or 'session'. For
credential invalidation, bind issuance and acceptance to the same authority that
the operation invalidates. Resolve that application relationship before unrelated
external protocol internals. Empty tables are valid when inapplicable; name a
deciding unread relationship explicitly instead of assuming identity.

On action=final, return boundary_checks before draft: one row per offered ID. effect is the actual
effect (or null); requirement is its source-supported condition (or null); example
is a concrete permitted/rejected case or the exact unavailable relationship;
observation is what the shown code does, not a vulnerability label. status is
counterexample, enforced, unresolved or no_boundary. Cite inspected source handles
only. unresolved uses the appropriate cause; final cannot imply it was settled.
Keep the original per-ID verdict scoped to its selected claim. Put a distinct
consequential counterexample in existing source_leads with its exposure conditions;
do not relabel a safe primitive as vulnerable to carry a different workflow bug.
Do not execute source, exceed research limits or invent scanner IDs.
