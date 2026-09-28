# Review bucket index

Read the guide named by `review_playbooks[review_id]`. The review's
`security_question` remains the exact question; a bucket supplies the likely
evidence chain. Read [the common workflow](review-workflow.md) once per bundle.

| Bucket | Read when the question concerns |
| --- | --- |
| `interpreted_input` | [SQL, commands, BSON, templates, HTML, deserialization or loaders](buckets/interpreted-input.md) |
| `resource_boundary` | [Files, URLs, redirects, network destinations or selected resources](buckets/resource-boundary.md) |
| `authorization` | [Server actions, identity, policy attachment or object ownership](buckets/authorization.md) |
| `credential_state` | [Password, MFA, recovery or API-key changes](buckets/credential-state.md) |
| `state_integrity` | [Binding, CSRF, financial values, transitions or shared limits](buckets/state-integrity.md) |
| `crypto_configuration` | [Cryptography, randomness, cookies or CORS](buckets/crypto-configuration.md) |
| `native_memory` | [C/C++ bounds, ownership, lifetime or parser state](buckets/native-memory.md) |
| `operation_policy` | [Another operation-specific invariant](buckets/operation-policy.md) |

If the bundle's bucket conflicts with its named operation, follow the exact
security question and record the mismatch. Do not transfer nearby code or
another review's evidence to make a bucket fit.
For a CSRF question, read `state_integrity` even if an older bundle labels
the capability `resource_boundary`.
