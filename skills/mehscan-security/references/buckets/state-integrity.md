# State integrity

Trace **caller-controlled value → server authority or allowed transition →
rejection → persisted effect**. Focus on the exact field or state the review
names.

- **Object binding:** Identify a sensitive writable field and the persistence
  boundary. A typed request or annotation is not a write allowlist by itself.
- **CSRF:** Establish a cross-site request the attacker can cause, delivery of
  the victim's browser-managed authority on that exact request, and a reachable
  state change. Then check the effective same-route defense. A cookie set
  without an explicit `SameSite` attribute does not by itself prove that a
  cross-site POST carries it: browser policy, cookie age, and deployment can
  change delivery. If that edge decides the verdict and cannot be established,
  name it in `needs_review`.
- **Price or quota:** Compare the persisted value with the server-authoritative
  value or limit. For shared limits, check whether predicate and write are
  atomic through a conditional update, lock or transaction contract.
- **Transition/fail-open:** Compare current and next states. A log, challenge,
  error response or boolean check does not enforce a policy if execution
  continues to the effect.

Stop when the same-path authority or transition is enforced before the write,
or a concrete violating transition is shown. Name the missing adapter or
policy definition if its behavior decides the result.
