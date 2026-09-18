//! Language-independent handoff text for established security invariants.
//! Prefer the operation's semantics over a broad capability: authentication
//! also contains password storage and rate limiting, which need different fixes.

pub(crate) struct Presentation {
    pub title: &'static str,
    pub remediation: &'static str,
}

pub(crate) fn presentation(rule: &str, cwes: &[String], operation: &str) -> Option<Presentation> {
    let has = |cwe: &str| cwes.iter().any(|value| value == cwe);
    let (title, remediation) = if rule == "kotlin-runtime-exec" && has("CWE-78") {
        (
            "Request values select the executable or process arguments",
            "Keep the executable server-owned and allowlist permitted operations. Pass validated values as separate arguments, reject option injection, and avoid adding a command shell; an argument vector alone does not authorize a request-selected executable.",
        )
    } else if matches!(rule, "kotlin-url-read" | "kotlin-url-connection") && has("CWE-918") {
        (
            if rule == "kotlin-url-read" {
                "Request values select a server-side resource URL"
            } else {
                "Request values select a URL connection target"
            },
            "Prefer a fixed allowlist of server-owned destinations. Otherwise enforce allowed schemes, exact hosts and ports, resolved-address policy and redirect revalidation before access. URI parsing alone is not approval. For connection construction, verify the actual connect/read consumer before claiming resource access.",
        )
    } else if matches!(rule, "kotlin-files-read" | "kotlin-files-write") && has("CWE-22") {
        (
            if rule == "kotlin-files-read" {
                "Request values select an unconfined file read path"
            } else {
                "Request values select an unconfined file write path"
            },
            "Prefer a fixed allowlist of server-owned file targets. Otherwise resolve against a trusted root, enforce component-aware root containment and a deliberate symlink policy before access, and reject absolute or escaping paths. Normalization alone does not confine a path.",
        )
    } else if matches!(
        rule,
        "kotlin-jdbc-statement-query" | "kotlin-jdbc-prepare-query" | "kotlin-jdbc-template-query"
    ) && has("CWE-89")
    {
        (
            match rule {
                "kotlin-jdbc-statement-query" => "Request text alters SQL executed by Statement",
                "kotlin-jdbc-prepare-query" => {
                    "Request text alters SQL before statement preparation"
                }
                _ => "Request text alters SQL executed by JdbcTemplate",
            },
            "Keep SQL syntax fixed and bind request values with JDBC placeholders or JdbcTemplate value arguments. Preparing a statement does not make previously interpolated SQL safe; verify the executed query and confirm hostile text remains a bound value.",
        )
    } else if rule == "kotlin-persistence-query" && has("CWE-89") {
        (
            "Request values alter persistence query syntax",
            "Keep HQL, JPQL and SQL syntax fixed and bind each request-derived value with named or positional parameters; do not interpolate values into the query text.",
        )
    } else if rule.contains("hardcoded-signing-key") {
        (
            "Embedded signing key permits forged credentials",
            "Provision signing keys from a protected secret provider, remove embedded key material, and rotate the exposed key and affected credentials.",
        )
    } else if has("CWE-321") {
        (
            "Embedded cryptographic key undermines data protection",
            "Provision cryptographic keys from a protected secret provider, remove embedded key material, rotate exposed keys, and migrate affected encrypted data or credentials.",
        )
    } else if rule.contains("plaintext-totp") {
        (
            "Sensitive authentication material is stored without encryption",
            "Encrypt persistent authentication secrets with a separately protected key; restrict decryption and access to the verification operation.",
        )
    } else if has("CWE-312") {
        (
            "Sensitive data is stored without encryption",
            "Encrypt sensitive persistent data with separately protected keys and restrict access to its storage and decryption operations.",
        )
    } else if rule.contains("spoofable-rate-limit-key") {
        (
            "Client-controlled addresses bypass rate limiting",
            "Restrict trusted proxy hops and derive rate-limit keys from a validated client address and the target account; reject client-supplied identity overrides.",
        )
    } else if has("CWE-307") {
        (
            "Authentication attempts lack effective throttling",
            "Enforce per-account and validated-client throttling before authentication or recovery attempts, with bounded retries and monitoring.",
        )
    } else if rule.contains("verify-without-algorithm-allowlist") {
        (
            "Token verification does not pin allowed algorithms",
            "Pin allowed verification algorithms and trusted keys, then validate issuer, audience, purpose, and expiry before using token claims.",
        )
    } else if rule.contains("decode-as-identity") || has("CWE-345") {
        (
            "Unverified token claims are used as identity",
            "Verify token integrity with trusted keys and validate issuer, audience, purpose, and expiry before using identity claims; decoding alone is not authentication.",
        )
    } else if rule.contains("password-change-without-reauthentication") || has("CWE-620") {
        (
            "Password change does not require reauthentication",
            "Require the current password or a fresh independently verified authentication factor before changing credentials, and invalidate affected sessions.",
        )
    } else if rule.contains("password-confirmation-not-enforced") {
        (
            "Password confirmation mismatch does not stop registration",
            "Reject mismatched password confirmation and return before any account-creation or downstream middleware executes.",
        )
    } else if rule.contains("registration-rejection-fallthrough") {
        (
            "Rejected registration continues into account creation",
            "Return immediately after registration rejection; ensure downstream account-creation middleware cannot execute after a failed validation.",
        )
    } else if rule.contains("unbounded-coupon") {
        (
            "Coupon values are not bounded by business limits",
            "Validate discount values against authoritative business limits before recording or applying them; reject negative, excessive, and non-finite values.",
        )
    } else if rule.contains("dynamic-sensitive-response-field") {
        (
            "Request-selected fields expose sensitive response data",
            "Allowlist public response fields and serialize only those fields; do not let request keys select internal or sensitive model properties.",
        )
    } else if rule.contains("duplicate-key-mutation") {
        (
            "Duplicate object keys replace an authorization constraint",
            "Construct selectors with unique server-owned keys, reject duplicate request keys, and enforce the authenticated subject constraint on the final selector.",
        )
    } else if rule.contains("mass-assignment") || has("CWE-915") {
        (
            "Request fields can overwrite protected model properties",
            "Allowlist writable fields and assign ownership, roles, and other protected properties exclusively from server-owned policy.",
        )
    } else if has("CWE-1004") {
        (
            "Authentication cookie is readable by scripts",
            "Issue authentication cookies on the server with HttpOnly; move client authentication flows away from direct script access to the credential.",
        )
    } else if has("CWE-1275") {
        (
            "Authentication cookie lacks SameSite protection",
            "Set an explicit SameSite policy suitable for the authentication flow and enforce independent CSRF protection on state-changing requests.",
        )
    } else if has("CWE-614") {
        (
            "Authentication cookie can travel over an insecure connection",
            "Set Secure on authentication cookies and require HTTPS for credential-bearing traffic.",
        )
    } else if has("CWE-352") {
        (
            "Cookie-authenticated changes lack CSRF protection",
            "Validate a session-bound CSRF token or an equivalent strict origin policy before state changes; use suitable SameSite cookies as defense in depth.",
        )
    } else if has("CWE-916") {
        (
            "Passwords lack an adaptive salted storage hash",
            "Use a maintained password-hashing implementation with a per-password salt and an appropriate adaptive work factor; migrate legacy hashes on successful login.",
        )
    } else if has("CWE-521") {
        (
            "Weak password acceptance at account creation",
            "Enforce an effective password-strength policy on every account-creation entry point before password storage; reject known compromised passwords.",
        )
    } else if has("CWE-640") {
        (
            "Password recovery relies on personal knowledge",
            "Replace knowledge-only recovery with single-use, expiring tokens delivered through a verified recovery channel and enforce per-account throttling.",
        )
    } else if has("CWE-613") {
        (
            "Authentication state remains valid after invalidation",
            "Expire and invalidate server-side authentication state on logout and credential changes, and enforce the same lifetime at every consumer.",
        )
    } else if has("CWE-548") {
        (
            "Directory listing exposes file names",
            "Disable directory indexing for non-public material and enforce an explicit publication allowlist and access policy for served files.",
        )
    } else if has("CWE-943") && executable_database_predicate(operation) {
        (
            "Request-built database JavaScript predicate",
            "Replace executable database predicates with ordinary parameterized selectors; validate input types before constructing the selector.",
        )
    } else if has("CWE-943") {
        (
            "Request values alter database selectors",
            "Validate query values against their expected schema and reject request-supplied operators; require scalar identifiers for object-ID lookups and reuse validated values in every database operation.",
        )
    } else if has("CWE-89") {
        (
            "Request values are interpolated into executable SQL",
            "Bind every request-derived value as a database parameter; never concatenate input into SQL syntax, including LIKE predicates.",
        )
    } else if has("CWE-918") {
        (
            "Request-selected URLs permit internal server requests",
            "Allowlist destinations and schemes, reject private and reserved resolved addresses, and revalidate each redirect before the server sends a request.",
        )
    } else if has("CWE-601") {
        (
            "Request-selected redirect leaves the trusted destination set",
            "Resolve and parse redirect targets, then enforce exact trusted origins or relative application paths; do not use substring allowlists.",
        )
    } else if has("CWE-611") {
        (
            "Untrusted XML expands external entities",
            "Disable DTD loading, external resource resolution, and entity substitution; avoid returning parsed sensitive content in errors.",
        )
    } else if has("CWE-502") {
        (
            "Untrusted input uses unrestricted deserialization",
            "Use a safe data-only decoder and validate the resulting schema; disallow object constructors, executable tags, and arbitrary type instantiation.",
        )
    } else if has("CWE-94") {
        (
            "User content is interpreted as executable code",
            "Remove evaluation of user content and parse it as structured data with a strict schema; a timeout or wrapper does not establish safe interpretation.",
        )
    } else if has("CWE-79") {
        (
            "Untrusted content reaches HTML without effective output protection",
            "Keep context-appropriate output encoding; if rich HTML is required, sanitize the exact value with a maintained allowlist sanitizer before any trust bypass or raw HTML sink.",
        )
    } else if rule.contains("layout-filesystem-read") {
        (
            "Request-controlled layout selects a template file",
            "Keep template and layout selection server-owned; allowlist intended template names and exclude reserved rendering options from request-derived locals.",
        )
    } else if rule.contains("poison-null-byte") {
        (
            "Encoded null bytes bypass file-path validation",
            "Decode the path once before validation, reject null bytes and ambiguous encodings, and enforce containment on the exact path passed to file access.",
        )
    } else if has("CWE-98") {
        (
            "Untrusted file selection reaches executable inclusion",
            "Choose executable includes from a fixed server-owned mapping. Never pass request-selected paths to inclusion; constrain targets to an authorized root and disable unnecessary remote inclusion wrappers.",
        )
    } else if has("CWE-295") {
        (
            "TLS peer validation can accept an untrusted server",
            "Enable certificate-chain and hostname verification for the affected client. Configure trusted CA certificates instead of bypassing validation, and ensure later options or callbacks do not disable either check.",
        )
    } else if has("CWE-327") {
        (
            "Weak hashing fails the required security property",
            "Replace weak hashes where the consumer requires a security property. Use an adaptive salted password hash for passwords and a modern vetted digest or authenticated integrity construction for integrity; keep non-security identifiers separate.",
        )
    } else if has("CWE-22") {
        (
            "Untrusted paths escape the intended directory",
            "Resolve the exact path against the intended base directory and enforce path-boundary containment before access; for archive extraction, validate every entry and reject symlink escapes.",
        )
    } else if has("CWE-639") || has("CWE-862") {
        (
            "Request-selected objects lack subject authorization",
            "Constrain the operation by the authenticated subject's owner, tenant, role, or explicit policy—not only by the request-selected object ID.",
        )
    } else if has("CWE-306") {
        (
            "Sensitive operation is accessible without authentication",
            "Enforce verified authentication before the sensitive operation executes; bind the filter to every affected route or entry point.",
        )
    } else {
        return None;
    };
    Some(Presentation { title, remediation })
}

fn executable_database_predicate(operation: &str) -> bool {
    let operation: String = operation
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect();
    [
        "{$where:",
        ",$where:",
        "{\"$where\":",
        ",\"$where\":",
        "{'$where':",
        ",'$where':",
    ]
    .iter()
    .any(|key| operation.contains(key))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shared_invariants_do_not_depend_on_language_prefixes() {
        for language in [
            "typescript",
            "javascript",
            "python",
            "java",
            "csharp",
            "go",
            "rust",
            "cpp",
        ] {
            let totp = presentation(
                &format!("{language}-plaintext-totp-storage"),
                &["CWE-312".into()],
                "",
            )
            .unwrap();
            assert!(totp.remediation.contains("Encrypt"));
            assert!(!totp.remediation.contains("owner"));
            let limiter = presentation(
                &format!("{language}-spoofable-rate-limit-key"),
                &["CWE-307".into()],
                "",
            )
            .unwrap();
            assert!(limiter.remediation.contains("trusted proxy"));
            let sql = presentation(
                &format!("{language}-database-query"),
                &["CWE-89".into()],
                "",
            )
            .unwrap();
            assert!(sql.title.contains("SQL"));
        }
    }

    #[test]
    fn database_predicate_and_selector_repairs_are_distinct() {
        let cwes = ["CWE-943".into()];
        let predicate = presentation("java-query", &cwes, "find({$where: expression})").unwrap();
        let selector = presentation("python-query", &cwes, "find({_id: id})").unwrap();
        assert_ne!(predicate.title, selector.title);
        assert!(predicate.remediation.contains("Replace executable"));
        assert!(selector.remediation.contains("scalar identifiers"));
        assert!(!executable_database_predicate("find({_id: '$where'})"));
        assert!(presentation("unknown-boundary", &[], "").is_none());
    }
}
