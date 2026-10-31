# Tokens and session authority

Use for JWTs, opaque sessions, API keys, refresh tokens and purpose-specific
credentials when issuance, acceptance or lifetime decides the selected question.
For password/MFA/recovery state changes, also use the relevant relationship in
[credential lifecycle](categories/credential-lifecycle.md). A token name, signed
value or cache hit does not by itself establish the authority a consumer needs.

## Establish the effective contract

Trace the relevant producer or verifier through wrappers to its imported
implementation. Check dependency versions, import resolution and configuration
only where their semantics can change the conclusion. A top-level signer and
middleware verifier may use different nested versions or different keys/options.
Do not transfer modern library behavior to a legacy dependency, or behavior from
a same-named helper to the invoked helper.

Before asserting a version-specific property, inspect the deciding implementation,
an applicable versioned contract or a matching test. A configured option is intent
until the invoked implementation consumes it: a wrapper may pass a duration under
an unsupported option name, use different units, or override it. A manifest or
lockfile helps bind a version; it does not itself prove that option's behavior.
If only a versioned snapshot is supplied, state that condition. An unresolved
installed version does not erase a supported conditional mechanism, but do not
present that snapshot as proven deployment resolution.

## Separate the lifetime questions

Distinguish the configured duration, the expiration actually emitted or stored,
and the acceptance deadline enforced by this consumer. For JWTs, determine whether
the signer actually emits `exp`, and how the verifier treats missing or expired
claims. For opaque tokens, inspect the stored expiry/TTL and the accepting lookup.
Do not infer an emitted expiry from the spelling of a signing option.

A cache may store a raw token, decoded payload, verified principal or independent
session record. Identify which one is returned and whether its hit path repeats
verification, enforces a stored deadline, or relies on eviction. Check expiry and
revocation separately. A valid lifetime claim can be “this acceptance path has no
bounded deadline” without claiming “an issued token expired after N hours.”
Do not claim acceptance after a particular expiry unless both that expiry and
continued acceptance are supported. Do not infer missing global invalidation
from one lookup; inspect logout, rotation or credential-change paths only when
they decide the assigned revocation question.

## Follow acceptance to the effect

Identify the credential branch that actually supplies identity: bearer header,
cookie, API key, refresh exchange, temporary proof or cache hit. Decoding and
parsing are not signature verification. Inspect the applicable key/algorithm
selection and claim checks rather than assuming defaults from an API name.
Where relevant, check issuer, audience, token purpose/type and scope: a verified
recovery or partially authenticated token need not authorize a normal session.
For opaque credentials, establish that the lookup or comparison validates the
presented credential and binds the same record and subject used by the consumer.

Trace **presented value → acceptance check → trusted fields → selected object →
independent guards → sensitive effect**. If token data populates a cached user,
determine which fields are authoritative. A later comparison against a password
hash or role from that same data is not automatically an independent control.
Conversely, retain a separate database password check, owner predicate, IP rule
or other applicable rejection; weakening one verifier does not bypass all guards.
An owner-scoped predicate can refute direct parameter substitution while leaving
identity authenticity unresolved. State those two conclusions separately.

## Preserve the selected question

Local signing/key configuration can settle a narrow cryptographic claim without
mapping every consumer. Acceptance, replay, revocation and workflow claims need
the relevant producer/consumer relationship, not an identity-provider-wide audit.
For reset, enrollment, refresh or one-time proofs, inspect account/purpose binding
and consumption at the protected transition when those relationships are material.
Do not invent a one-time-use or reauthentication policy for an ordinary session.

Use a deciding lookup for an unread contract instead of repeating a supplied
application excerpt. Reuse already-inspected source or scoped facts across
compatible consumers while checking each caller's branch and authority. Guidance
is a review method, not evidence that a dependency is vulnerable. Report the
supported mechanism, conditions and precise remaining gap; keep a distinct
credential concern as a lead when the selected claim addresses another property.
