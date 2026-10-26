# Mass assignment and sensitive mutations

Trace accepted fields through binding/transformation to the persisted object and
its downstream authority. A request body reaching an ORM is not enough by itself.

1. Find the actual server route, generated CRUD registration or mutation resolver.
   Establish which methods are exposed and their effective middleware/policy.
2. Identify sensitive fields: role, tenant, owner, membership, approval, verified
   state, price, quota or credential binding. Use actual model/consumer semantics;
   field names alone are leads.
3. Inspect writable-field restrictions, DTO mapping, runtime validation, setters,
   hooks and server overrides. A static request type is not runtime filtering.
   Spread/merge order matters: compare the checked value with the saved value.
4. Show the consequence. A stored role matters when login or another consumer
   trusts it; an owner change matters when it moves authority or access. A
   success-shaped response or inert field is not proof of privilege escalation.

Generated APIs need per-operation review. A guard on item deletion does not protect
registration or collection updates. Likewise, body.UserId overwritten from the
authenticated actor can settle that binding without protecting an independently
selected record ID. Follow the selected object and effect separately.

Clean controls include explicit safe-field mapping and effective server assignment
after untrusted fields are discarded. Preserve a distinct alternate route or
credential-acceptance weakness without calling every locally protected mutation
unsafe. Finish with the writable field, trusted restriction or bypass, caller and
actual authority/state change.
