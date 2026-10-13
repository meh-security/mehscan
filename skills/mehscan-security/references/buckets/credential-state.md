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

For answer-based recovery, inspect answer creation, seeded answers, applicable
rate limiting, and repository behavior tests before leaving answer quality or
reset authority unresolved. A challenge check after a successful reset does
not by itself prove that its answer was accepted by the reset gate.

Stop when the required authority and rejection are shown for this exact
change, or when a concrete path mutates the credential without them. Keep
unknown external identity policy as the named missing fact when decisive.
