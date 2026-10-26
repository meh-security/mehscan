# Structured query and selector review

Separate three relationships: who controls selector structure, how the actual
database/search API interprets it, and what security-relevant effect it permits.
Object-shaped input is a lead, not a vulnerability by itself.

- Follow decoding and runtime types into the exact filter. A value under a fixed
  key may still accept an operator object; a validated scalar may prevent that.
  Check arrays, nested objects and any spread/merge that replaces a fixed field.
- Establish the registered driver, wrapper and interpretation. Operator objects,
  expression evaluation, raw query strings and ordinary equality are different
  contracts. Follow application overrides when they can change that distinction.
- For a claimed bypass, name the changed result: credential acceptance, another
  subject's private data, unauthorized mutation, multiple-record write, executable
  predicate or resource exhaustion. Choosing another already-public object for an
  action the caller may already perform does not establish that boundary.
- Examine ownership/tenant constraints and update options on the selected call.
  A permissive selector combined with a destructive multi-record update differs
  from a selector that still has a separately enforced owner condition.

Use a documented matching API contract or inspected local implementation/test
when interpretation decides the claim. If only selector construction is known,
preserve the concrete unresolved interpretation/effect; do not force an issue
verdict by lowering confidence. If source establishes executable grammar reaching
an actual evaluator, the separate code-evaluation policy can apply.

Close this property when an effective same-path scalar/selector restriction or
authority constraint disproves the selected bypass. Do not certify the entire
operation from one constrained query. Repository tests are evidence of intended
and tested behavior; do not say they were executed unless they actually were.
