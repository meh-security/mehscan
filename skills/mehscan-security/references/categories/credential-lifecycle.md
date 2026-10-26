# Credential lifecycle

For a credential operation, compare the authority across producer, accepted value
and consumer. Safe signing or high entropy does not settle lifecycle correctness.
Use the credential-state guide for password/MFA/recovery transitions.

Select the relationships relevant to this operation:

- Issuance: who can request the credential, which account/role/scope it represents,
  and what prerequisite must reject issuance or delivery. A logged validation
  failure that does not stop delivery is not a control.
- Acceptance: which token/session/API-key branch supplies the authenticated actor,
  whether signature/expiry/revocation checks run on cached and alternate paths,
  and which authority-bearing field the consumer actually trusts.
- Consumption: whether account binding, one-time use, allowance or expiry checks
  apply before the protected effect, including repeated requests when relevant.
- Rotation/revocation: whether the invalidated identifier is the same credential
  or session that was issued and remains accepted. Compare wrapper and embedded
  values, server records and client transport rather than the shared word token.
- Recovery/step-up: bind the proof to the intended account and transition. Public
  knowledge, arbitrary token generation or a success message is not automatically
  valid recovery authority; inspect the actual validating and mutating branch.

Do not demand an entire identity-provider audit for a local signing setting.
Conversely, do not answer an assigned lifecycle question using only algorithm,
expiry configuration or authentication presence. Read a decisive local producer
or consumer while budget remains. Distinct workflow concerns remain separate
leads when the original ID only concerns a narrow primitive.

For business prerequisites, identify a source-supported policy, enforcement
elsewhere, tests or explicit requirement. Do not invent a preferred logout,
recovery or enrollment policy. State conditional deployment facts precisely.
