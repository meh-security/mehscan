# Kotlin Auth0 JWT policy controls

Original credential-consumer helpers distinguish unverified claims, metadata
display, HMAC verification, unsigned algorithm acceptance, swallowed verification
failures and same-token verification before instance decoding. Server key
parameters are operational secret dependencies in the isolated harness, not
request-selected key material. Tokens are generated only for owned test controls.

These helpers do not establish deployed endpoints, issuer discovery, key rotation,
general callback/helper effects or support for other JWT SDKs. Token issuance
and lifecycle policy remain separate coverage obligations.
