use mehscan_core::Rule;

use crate::EngineError;

macro_rules! builtin_catalogs {
    ($($path:literal),+ $(,)?) => {
        &[$(($path, include_str!(concat!("../../../../", $path)))),+]
    };
}

// Keep each embedded catalog path in exactly one place. The YAML remains the
// authority for CWE, title, language, capability, guidance, and provenance.
const BUILTIN_RULE_CATALOGS: &[(&str, &str)] = builtin_catalogs!(
    "rules/code/cwe-78/process-execution.yml",
    "rules/code/cwe-78/process-argument-separation.yml",
    "rules/code/cwe-90/ldap-encoding.yml",
    "rules/code/cwe-89/database-query.yml",
    "rules/code/cwe-89/sql-parameterization.yml",
    "rules/code/cwe-918/outbound-request.yml",
    "rules/code/cwe-918/url-parsing.yml",
    "rules/code/cwe-918/url-destination-validation.yml",
    "rules/code/cwe-22/filesystem-access.yml",
    "rules/code/cwe-22/path-canonicalization.yml",
    "rules/code/cwe-22/path-containment.yml",
    "rules/code/cwe-22/archive-entry-path.yml",
    "rules/code/cwe-94/dynamic-code.yml",
    "rules/code/cwe-94/dynamic-code-restriction.yml",
    "rules/code/cwe-295/tls-validation.yml",
    "rules/code/cwe-327/hash-algorithm.yml",
    "rules/code/cwe-614/cookie-security.yml",
    "rules/code/cwe-613/jwt-token-generation.yml",
    "rules/code/cwe-502/deserialization.yml",
    "rules/code/cwe-502/deserialization-restriction.yml",
    "rules/code/cwe-306/http-entrypoints-authentication.yml",
    "rules/code/cwe-862/authorization-guards.yml",
    "rules/code/cwe-79/html-output.yml",
    "rules/code/cwe-79/html-encoding.yml",
    "rules/code/cwe-601/redirect.yml",
    "rules/code/cwe-601/redirect-validation.yml",
    "rules/code/cwe-434/file-upload.yml",
    "rules/code/cwe-434/uploaded-file-content.yml",
    "rules/code/cwe-434/uploaded-file-path.yml",
    "rules/code/cwe-434/uploaded-filename-validation.yml",
    "rules/code/cwe-434/streaming-upload.yml",
    "rules/code/cwe-20/http-request-data.yml",
    "rules/code/cwe-639/resource-access.yml",
    "rules/code/cwe-611/xml-parsing.yml",
    "rules/code/cwe-117/logging.yml",
    "rules/code/cwe-942/cors-configuration.yml",
    "rules/code/cwe-119/rust-safety-boundaries.yml",
);

pub fn load_builtin_rules() -> Result<Vec<Rule>, EngineError> {
    let mut rules = Vec::new();
    for (path, source) in BUILTIN_RULE_CATALOGS {
        let mut catalog: Vec<Rule> = serde_yaml::from_str(source).map_err(|error| {
            EngineError(format!("built-in rule catalog {path} is invalid: {error}"))
        })?;
        rules.append(&mut catalog);
    }
    super::validate::validate_rules(&rules)?;
    Ok(rules)
}
