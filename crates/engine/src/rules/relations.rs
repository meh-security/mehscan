use std::collections::{BTreeMap, BTreeSet};

use mehscan_core::{
    Capability, EvidenceKind, ProtectionApplication, RelationContract, RelationStrategy, Rule,
};

use crate::EngineError;

const SECURITY_PATH_RELATIONS: &str =
    include_str!("../../../../rules/relations/security-paths.yml");

pub fn load_builtin_relations(rules: &[Rule]) -> Result<Vec<RelationContract>, EngineError> {
    let relations: Vec<RelationContract> = serde_yaml::from_str(SECURITY_PATH_RELATIONS)
        .map_err(|error| EngineError(format!("built-in relation catalog is invalid: {error}")))?;
    validate_relations(&relations, rules)?;
    Ok(relations)
}

fn validate_relations(relations: &[RelationContract], rules: &[Rule]) -> Result<(), EngineError> {
    if relations.is_empty() {
        return Err(EngineError(
            "built-in relation catalog must not be empty".to_string(),
        ));
    }

    let mut ids = BTreeSet::new();
    let mut selectors = BTreeSet::new();
    let mut capture_roles = capture_roles_by_kind_and_capability(rules);
    // The bounded Node response-shaping pass emits this semantic role only
    // after it proves a sensitive computed read reaches an HTTP response.
    capture_roles
        .entry((EvidenceKind::Sink, Capability::ResourceAccess))
        .or_default()
        .insert("field_selector".to_string());
    capture_roles
        .entry((EvidenceKind::Sink, Capability::Authentication))
        .or_default()
        .insert("new_password".to_string());
    capture_roles
        .entry((EvidenceKind::Sink, Capability::CryptographicHash))
        .or_default()
        .insert("password".to_string());
    capture_roles
        .entry((EvidenceKind::Sink, Capability::DatabaseQuery))
        .or_default()
        .extend(["nosql_query".to_string(), "nosql_expression".to_string()]);
    capture_roles
        .entry((EvidenceKind::Sink, Capability::ResourceAccess))
        .or_default()
        .extend([
            "assigned_fields".to_string(),
            "property_key".to_string(),
            "operation".to_string(),
            "stored_value".to_string(),
        ]);
    capture_roles
        .entry((EvidenceKind::Sink, Capability::TokenGeneration))
        .or_default()
        .extend(["signing_key".to_string(), "expiry_key".to_string()]);
    capture_roles
        .entry((EvidenceKind::Sink, Capability::Authentication))
        .or_default()
        .extend([
            "token".to_string(),
            "unverified_token".to_string(),
            "session_token".to_string(),
            "client_key".to_string(),
            "reset_token".to_string(),
        ]);
    capture_roles
        .entry((EvidenceKind::Sink, Capability::CookieConfiguration))
        .or_default()
        .extend([
            "secure_payload".to_string(),
            "http_only_payload".to_string(),
        ]);
    capture_roles
        .entry((EvidenceKind::Sink, Capability::HttpRequestHandling))
        .or_default()
        .insert("policy".to_string());
    capture_roles
        .entry((EvidenceKind::Sink, Capability::HttpHeaderOutput))
        .or_default()
        .insert("header_value".to_string());
    capture_roles
        .entry((EvidenceKind::Sink, Capability::Logging))
        .or_default()
        .insert("message".to_string());
    capture_roles
        .entry((EvidenceKind::Sink, Capability::LdapQuery))
        .or_default()
        .extend(["filter".to_string(), "distinguished_name".to_string()]);
    capture_roles
        .entry((EvidenceKind::Sink, Capability::XpathQuery))
        .or_default()
        .insert("expression".to_string());
    // Exact Jinja import identity plus a proved render call is emitted by the
    // bounded Python project-context pass rather than a syntax-only matcher.
    capture_roles
        .entry((EvidenceKind::Sink, Capability::TemplateEvaluation))
        .or_default()
        .insert("template".to_string());
    capture_roles
        .entry((EvidenceKind::Validation, Capability::LdapFilterEncoding))
        .or_default()
        .extend(["filter".to_string(), "value".to_string()]);
    capture_roles
        .entry((
            EvidenceKind::Validation,
            Capability::LdapDistinguishedNameEncoding,
        ))
        .or_default()
        .extend(["distinguished_name".to_string(), "value".to_string()]);
    let mut source_capabilities = rules
        .iter()
        .filter(|rule| rule.kind == EvidenceKind::Source)
        .map(|rule| rule.capability)
        .collect::<BTreeSet<_>>();
    // These sources are emitted by conservative project-level passes rather
    // than permanent syntax matchers.
    source_capabilities.insert(Capability::StoredUserContent);
    source_capabilities.insert(Capability::RpcRequestData);
    source_capabilities.insert(Capability::BrowserInput);
    source_capabilities.insert(Capability::ExternalInput);
    source_capabilities.insert(Capability::CredentialMaterial);
    source_capabilities.insert(Capability::ModelToolInput);
    capture_roles
        .entry((EvidenceKind::Sink, Capability::BrowserNavigation))
        .or_default()
        .insert("destination".to_string());
    capture_roles
        .entry((EvidenceKind::Sink, Capability::BrowserCredentialedRequest))
        .or_default()
        .insert("request_data".to_string());
    capture_roles
        .entry((EvidenceKind::Sink, Capability::BrowserMessageSend))
        .or_default()
        .insert("message".to_string());
    capture_roles
        .entry((EvidenceKind::Validation, Capability::Authorization))
        .or_default()
        .extend(["value".to_string(), "request_data".to_string()]);

    for relation in relations {
        if !valid_id(&relation.id) || !ids.insert(relation.id.as_str()) {
            return Err(EngineError(format!(
                "relation id must be unique lowercase ASCII kebab-case: {}",
                relation.id
            )));
        }
        if relation.version == 0 {
            return Err(EngineError(format!(
                "relation {} has version zero",
                relation.id
            )));
        }
        for capability in &relation.source.capabilities {
            if !source_capabilities.contains(capability) {
                return Err(EngineError(format!(
                    "relation {} references source capability {:?} without a source provider",
                    relation.id, capability
                )));
            }
        }
        if relation.sink.input_roles.is_empty()
            || has_empty_or_duplicate(&relation.sink.input_roles)
        {
            return Err(EngineError(format!(
                "relation {} must define unique non-empty sink input roles",
                relation.id
            )));
        }
        require_capture_roles(
            relation,
            EvidenceKind::Sink,
            relation.sink.capability,
            &relation.sink.input_roles,
            &capture_roles,
            "sink",
        )?;
        if relation.cwe_candidates.is_empty()
            || relation.cwe_candidates.iter().any(|cwe| !valid_cwe(cwe))
            || has_empty_or_duplicate(&relation.cwe_candidates)
        {
            return Err(EngineError(format!(
                "relation {} must define unique valid CWE-N candidates",
                relation.id
            )));
        }
        if let Some(protection) = &relation.protection {
            if protection.relation_role.trim().is_empty()
                || protection.value_roles.is_empty()
                || has_empty_or_duplicate(&protection.value_roles)
            {
                return Err(EngineError(format!(
                    "relation {} must define non-empty protection roles",
                    relation.id
                )));
            }
            if !relation
                .sink
                .input_roles
                .contains(&protection.relation_role)
            {
                return Err(EngineError(format!(
                    "relation {} protection role {} is not a sink input role",
                    relation.id, protection.relation_role
                )));
            }
            let mut required = protection.value_roles.clone();
            if protection.application == ProtectionApplication::RelatedCapture {
                required.push(protection.relation_role.clone());
            }
            require_protection_capture_roles(
                relation,
                protection.capability,
                &required,
                &capture_roles,
            )?;
        }
        let selector = (
            relation.source.capabilities.clone(),
            relation.sink.capability,
            relation.strategy,
            relation.sink.input_roles.clone(),
        );
        if !selectors.insert(selector) {
            return Err(EngineError(format!(
                "relation {} duplicates a source, sink, and strategy selector",
                relation.id
            )));
        }
        if relation.strategy == RelationStrategy::StoredSubtitleFile
            && (relation.source.capabilities != [Capability::StoredUserContent]
                || relation.sink.capability != Capability::HtmlOutput)
        {
            return Err(EngineError(format!(
                "relation {} uses stored_subtitle_file with incompatible capabilities",
                relation.id
            )));
        }
    }
    Ok(())
}

fn capture_roles_by_kind_and_capability(
    rules: &[Rule],
) -> BTreeMap<(EvidenceKind, Capability), BTreeSet<String>> {
    let mut roles = BTreeMap::<(EvidenceKind, Capability), BTreeSet<String>>::new();
    for rule in rules {
        let entry = roles.entry((rule.kind, rule.capability)).or_default();
        for pattern in &rule.match_spec.any {
            entry.extend(pattern.captures.keys().cloned());
        }
        for symbol in &rule.symbols {
            entry.extend(symbol.captures.keys().cloned());
        }
    }
    roles.insert(
        (
            EvidenceKind::Validation,
            Capability::BufferCapacityValidation,
        ),
        ["destination", "size", "capacity"]
            .into_iter()
            .map(str::to_string)
            .collect(),
    );
    roles
}

fn require_capture_roles(
    relation: &RelationContract,
    kind: EvidenceKind,
    capability: Capability,
    required: &[String],
    roles: &BTreeMap<(EvidenceKind, Capability), BTreeSet<String>>,
    label: &str,
) -> Result<(), EngineError> {
    let available = roles.get(&(kind, capability)).ok_or_else(|| {
        EngineError(format!(
            "relation {} references {label} capability {capability:?} without matcher rules",
            relation.id
        ))
    })?;
    for role in required {
        if !available.contains(role) {
            return Err(EngineError(format!(
                "relation {} references unknown {label} capture role {role}",
                relation.id
            )));
        }
    }
    Ok(())
}

fn require_protection_capture_roles(
    relation: &RelationContract,
    capability: Capability,
    required: &[String],
    roles: &BTreeMap<(EvidenceKind, Capability), BTreeSet<String>>,
) -> Result<(), EngineError> {
    let mut available = BTreeSet::new();
    for kind in [EvidenceKind::Sanitizer, EvidenceKind::Validation] {
        if let Some(kind_roles) = roles.get(&(kind, capability)) {
            available.extend(kind_roles.iter().cloned());
        }
    }
    if available.is_empty() {
        return Err(EngineError(format!(
            "relation {} references protection capability {capability:?} without matcher or semantic evidence rules",
            relation.id
        )));
    }
    for role in required {
        if !available.contains(role) {
            return Err(EngineError(format!(
                "relation {} references unknown protection capture role {role}",
                relation.id
            )));
        }
    }
    Ok(())
}

fn has_empty_or_duplicate(values: &[String]) -> bool {
    let mut seen = BTreeSet::new();
    values
        .iter()
        .any(|value| value.trim().is_empty() || !seen.insert(value.as_str()))
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && !id.ends_with('-')
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_cwe(cwe: &str) -> bool {
    cwe.strip_prefix("CWE-").is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn built_in_relations_validate_against_matcher_roles() {
        let rules = super::super::load_builtin_rules().expect("rules should load");
        let relations = load_builtin_relations(&rules).expect("relations should validate");
        assert_eq!(relations.len(), 52);
        assert_eq!(
            relations
                .iter()
                .filter(|relation| relation.strategy == RelationStrategy::StoredSubtitleFile)
                .count(),
            1
        );
    }

    #[test]
    fn relation_schema_rejects_unknown_fields() {
        let error = serde_yaml::from_str::<Vec<RelationContract>>(
            r#"
- id: invalid-relation
  version: 1
  source: { capability: http_request_data }
  sink: { capability: database_query, input_roles: [query] }
  cwe_candidates: [CWE-89]
  strategy: bounded_local_value
  typo: true
"#,
        )
        .expect_err("unknown fields must fail closed");
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn relation_source_accepts_legacy_single_and_compact_multiple_capabilities() {
        let legacy: RelationContract = serde_yaml::from_str(
            r#"
id: legacy-source
version: 1
source: { capability: http_request_data }
sink: { capability: database_query, input_roles: [query] }
cwe_candidates: [CWE-89]
strategy: bounded_local_value
"#,
        )
        .expect("legacy single source should parse");
        assert_eq!(legacy.source.capabilities, [Capability::HttpRequestData]);

        let multiple: RelationContract = serde_yaml::from_str(
            r#"
id: multiple-sources
version: 1
source: { capabilities: [http_request_data, rpc_request_data] }
sink: { capability: database_query, input_roles: [query] }
cwe_candidates: [CWE-89]
strategy: bounded_local_value
"#,
        )
        .expect("multiple sources should parse");
        assert!(multiple.source.accepts(Capability::HttpRequestData));
        assert!(multiple.source.accepts(Capability::RpcRequestData));
    }

    #[test]
    fn relation_source_rejects_ambiguous_empty_and_duplicate_selectors() {
        for source in [
            "{ capability: http_request_data, capabilities: [rpc_request_data] }",
            "{ capabilities: [] }",
            "{ capabilities: [http_request_data, http_request_data] }",
        ] {
            let yaml = format!(
                r#"
id: invalid-source
version: 1
source: {source}
sink: {{ capability: database_query, input_roles: [query] }}
cwe_candidates: [CWE-89]
strategy: bounded_local_value
"#
            );
            serde_yaml::from_str::<RelationContract>(&yaml)
                .expect_err("invalid source selector must fail closed");
        }
    }

    #[test]
    fn relation_validation_rejects_capture_role_drift() {
        let rules = super::super::load_builtin_rules().expect("rules should load");
        let mut relations: Vec<RelationContract> =
            serde_yaml::from_str(SECURITY_PATH_RELATIONS).expect("built-in YAML should parse");
        relations[0].sink.input_roles = vec!["missing_query_role".to_string()];
        let error = validate_relations(&relations, &rules).expect_err("drift must fail closed");
        assert!(error.0.contains("unknown sink capture role"));
    }

    #[test]
    fn relation_validation_rejects_duplicate_ids() {
        let rules = super::super::load_builtin_rules().expect("rules should load");
        let mut relations: Vec<RelationContract> =
            serde_yaml::from_str(SECURITY_PATH_RELATIONS).expect("built-in YAML should parse");
        relations[1].id = relations[0].id.clone();
        let error =
            validate_relations(&relations, &rules).expect_err("duplicates must fail closed");
        assert!(error.0.contains("unique lowercase ASCII kebab-case"));
    }
}
