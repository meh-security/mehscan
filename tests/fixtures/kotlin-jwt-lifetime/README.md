# Kotlin JWT lifetime controls

The first six original access-credential helpers have a required maximum lifetime of five
minutes and explicit same-token HMAC/issuer consumers without independent
maximum-age or revocation policy. They distinguish missing expiry, bounded
expiry, clearing expiry, configuring a different builder, payload replacement
and restoration after replacement, plus a returned credential consumer enforcing an
independent five-minute maximum age without exp. Operational server keys and clocks are
private harness dependencies. Returned credentials are used only in isolated
owned-token controls; this is intentionally admitted fixture code.

Signature authentication is distinct from the required lifetime bound. Wider
issuance SDKs, helper callbacks, revocation systems and deployment are separate
coverage obligations.
