# Credential state

Trace **requester → required current proof or recovery authority → exact
credential transition → rejection before mutation**. This applies to
password, passcode, MFA, authenticator, recovery code and API-key changes.

A valid session identifies a subject but may not satisfy the proof required
for this particular change. Check whether old-secret confirmation, verified
recovery token, step-up proof or equivalent policy attaches to the same
transition and terminates on failure. For recovery, identify who can mint and
redeem the token and whether use is scoped to the intended account.
Trace the token's account binding, storage and validating consumer before
treating it as recovery authority. A random token returned by a demonstration
endpoint, or a success message without a credential write, does not establish
an account takeover. Preserve separately shown URL or disclosure weaknesses
as their own leads rather than substituting them for this transition.

Third-party integration credentials are not automatically the application's
sign-in or recovery credentials. Establish the authority or account association
changed by synchronization and the proof its policy requires. Do not demand
password-change proof for every integration save, or use an adjacent encryption
or destination concern as the verdict on the selected credential transition.

For answer-based recovery, inspect answer creation, seeded answers, applicable
rate limiting, and repository behavior tests before leaving answer quality or
reset authority unresolved. A challenge check after a successful reset does
not by itself prove that its answer was accepted by the reset gate.

For a proof authorizing a single reset/recovery transition, check whether it can
authorize another after success. Signature, account binding and expiry establish
first-use acceptance, not consumption. Follow effective token/nonce consumption,
password or security-state binding, rotation or equivalent invalidation; absence
of token deletion alone is not a defect. If delegated semantics remain unread,
keep that deciding gap. This does not impose single use on ordinary sessions or
operator administration. Load [credential lifecycle](../categories/credential-lifecycle.md)
and [token review](../token-review.md) when that relationship needs further guidance.

Stop when the required authority, rejection and applicable consumption are shown
for this exact change, or a concrete violation is established under stated
conditions. Keep unknown external identity policy or invalidation behavior as
the named missing fact when decisive.
