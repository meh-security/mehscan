//! Admission is an impact filter, not a safety verdict. Raw evidence stays in
//! the scan and remains available to investigation queries in either mode.
use super::*;

pub(super) fn carry_dispatch_contracts(evidence: &mut [Evidence]) {
    // Carry shared-question identity only, never a safety/closed-operand fact.
    // The field/hook contract came from the optional compiler's URI producer;
    // the new dispatch still requires its own actor, hook and effect checks.
    let contracts = evidence
        .iter()
        .filter(|e| e.rule_id == "csharp-http-request-uri")
        .map(|e| {
            (
                e.id.clone(),
                e.context
                    .operand_facts
                    .iter()
                    .filter(|f| f.kind == mehscan_core::OperandFactKind::SharedOutboundDestination)
                    .cloned()
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    for dispatch in evidence
        .iter_mut()
        .filter(|e| e.rule_id == "csharp-http-request-dispatch")
    {
        if dispatch
            .tags
            .iter()
            .any(|tag| tag == "request-authority-after-hook-unresolved")
        {
            continue;
        }
        for id in &dispatch.related_evidence {
            for fact in contracts.get(id).into_iter().flatten() {
                if !dispatch.context.operand_facts.contains(fact) {
                    dispatch.context.operand_facts.push(fact.clone());
                }
            }
        }
    }
}

pub(super) fn inventory_only(
    item: &Evidence,
    sources: &RepositorySources,
    connected: bool,
    evidence: &[Evidence],
    written_code_targets: &BTreeSet<String>,
) -> bool {
    if crate::code::closed_query(item) {
        return true;
    }
    if matches!(
        item.rule_id.as_str(),
        "php-html-output" | "php-file-inclusion"
    ) {
        // Let the existing exact numeric proof record its closed-operand audit.
        if closed_output_operand(item).is_some() {
            return false;
        }
        let consequential = item.tags.iter().any(|tag| {
            matches!(
                tag.as_str(),
                "review-origin:decision-critical"
                    | "review-origin:runtime-code-selection"
                    | "review-origin:bound-output-producer"
            )
        });
        let interpretation = item.rule_id == "php-html-output"
            && item.context.operand_facts.iter().any(|fact| {
                fact.kind == mehscan_core::OperandFactKind::OutputContext
                    && (matches!(
                        fact.value.as_str(),
                        "embedded_context:script"
                            | "embedded_context:style"
                            | "html_unquoted_or_tag"
                    ) || fact.value.starts_with("active_attribute:"))
            });
        let writable_code = item.rule_id == "php-file-inclusion"
            && item.context.operand_facts.iter().any(|fact| {
                matches!(
                    fact.kind,
                    mehscan_core::OperandFactKind::FixedCodeRelativePath
                        | mehscan_core::OperandFactKind::RepositoryCodeTarget
                ) && written_code_targets.contains(&if cfg!(windows) {
                    fact.value.to_ascii_lowercase()
                } else {
                    fact.value.clone()
                })
            });
        return !connected && !consequential && !interpretation && !writable_code;
    }
    if ordinary_decoder(item, evidence, sources) {
        return true;
    }
    if known_data_only_yaml(item, sources) {
        return true;
    }
    if routine_builder(item, sources) {
        return true;
    }
    if matches!(
        item.rule_id.as_str(),
        "go-gob-deserialization" | "python-marshal-deserialization"
    ) {
        return !connected;
    }
    if item.capability == Capability::Logging {
        if item
            .captures
            .get("sensitive_value")
            .is_some_and(|capture| expiry_metadata(&capture.text))
        {
            return true;
        }
        if item.rule_id.ends_with("rendered-log-message")
            || item.rule_id.ends_with("unencoded-log-message")
        {
            // Co-location with a request is not evidence that its text reaches
            // the log. Keep actual bounded input/log relationships separately.
            return !connected;
        }
    }
    if positive_cookie_control(item) {
        return true;
    }
    if positive_tls_control(item) || ordinary_xml_control(item) {
        return true;
    }
    if item.rule_id == "php-curl-tls-validation"
        && item
            .captures
            .get("value")
            .is_some_and(|v| matches!(v.text.trim(), "true" | "TRUE" | "1" | "2"))
    {
        return true;
    }
    if item.rule_id.ends_with("http-listener-deployment-review")
        || item.rule_id.ends_with("public-metrics-route-review")
    {
        // A route name or plaintext listener says nothing about sensitive
        // payloads, public deployment or effective proxy protection.
        return true;
    }
    if item.cwe_candidates == ["CWE-942"] {
        // Header/credentialed-policy detectors can emit a connected origin
        // relationship rather than repeating a credentials tag on the sink.
        if connected {
            return false;
        }
        let text = anchor_text(item, sources).to_ascii_lowercase();
        return !item.tags.iter().any(|tag| {
            matches!(
                tag.as_str(),
                "credentials" | "credentials-enabled" | "credentialed" | "sensitive-response"
            )
        }) && !text.contains("very_permissive")
            && !text.contains("allow_credentials(true)");
    }
    if item.kind == EvidenceKind::SecurityConfiguration
        && item.capability == Capability::CryptographicHash
    {
        return !connected
            && (!security_purpose(item, sources) || suitable_digest_selection(item, sources));
    }
    false
}

fn routine_builder(item: &Evidence, sources: &RepositorySources) -> bool {
    let text = anchor_text(item, sources);
    match item.rule_id.as_str() {
        "csharp-http-request-uri" => true,
        "python-dynamic-code" => text.starts_with("compile("),
        _ => false,
    }
}

fn expiry_metadata(text: &str) -> bool {
    let text = text.trim();
    // Only exact value expressions, never a whole interpolated message that
    // might also contain the token. DOBs, PINs and dates are not globally safe.
    if text.contains(['"', '\'', '{', '}', '+', ',', '(']) {
        return false;
    }
    let text = text.to_ascii_lowercase();
    [
        "expiresat",
        "expiry",
        "expiration",
        "expirationtime",
        "expires_in",
    ]
    .iter()
    .any(|suffix| {
        text.ends_with(suffix)
            || text
                .strip_suffix(".utcdatetime")
                .is_some_and(|v| v.ends_with(suffix))
    })
}

fn positive_cookie_control(item: &Evidence) -> bool {
    if item.capability != Capability::CookieConfiguration {
        return false;
    }
    let controls = ["secure", "http_only", "httponly", "value"]
        .iter()
        .filter(|role| item.captures.contains_key(**role))
        .copied()
        .collect::<Vec<_>>();
    !controls.is_empty()
        && controls.iter().all(|role| {
            boolean_control(item, role) == Some(true)
                || item.captures[*role].text.trim() == "CookieSecurePolicy.Always"
        })
}

fn suitable_digest_selection(item: &Evidence, sources: &RepositorySources) -> bool {
    // This closes digest selection only; password cost, keys, IVs/nonces and
    // signature policy remain separate boundaries. Fast SHA-2 is not a KDF.
    if !item.rule_id.ends_with("hash-algorithm-selection")
        && !matches!(
            item.rule_id.as_str(),
            "c-openssl-hash-selection" | "cpp-openssl-hash-selection"
        )
    {
        return false;
    }
    let local = format!(
        "{} {}",
        item.enclosing_symbol.as_deref().unwrap_or(""),
        anchor_line(item, sources)
    )
    .to_ascii_lowercase();
    if ["password", "passwd"]
        .iter()
        .any(|word| local.contains(word))
    {
        return false;
    }
    let algorithm = item
        .context
        .literals
        .get("algorithm")
        .filter(|l| l.state == LiteralState::Known)
        .and_then(|l| match &l.value {
            Some(LiteralValue::String(value)) => Some(value.as_str()),
            _ => None,
        })
        .or_else(|| {
            item.captures.get("algorithm").and_then(|c| {
                let text = c.text.trim();
                if text.len() >= 2
                    && (text.starts_with('"') && text.ends_with('"')
                        || text.starts_with('\'') && text.ends_with('\''))
                {
                    Some(&text[1..text.len() - 1])
                } else {
                    None
                }
            })
        });
    algorithm.is_some_and(|algorithm| {
        matches!(
            algorithm.to_ascii_lowercase().replace('-', "").as_str(),
            "sha256"
                | "sha384"
                | "sha512"
                | "sha3256"
                | "sha3384"
                | "sha3512"
                | "blake2b"
                | "blake2s"
        )
    })
}

fn boolean_control(item: &Evidence, role: &str) -> Option<bool> {
    if let Some(literal) = item.context.literals.get(role) {
        if literal.state == LiteralState::Known {
            if let Some(LiteralValue::Boolean(value)) = literal.value {
                return Some(value);
            }
        }
    }
    match item.captures.get(role)?.text.trim() {
        "true" | "True" | "TRUE" => Some(true),
        "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

fn positive_tls_control(item: &Evidence) -> bool {
    if item.capability != Capability::TlsConfiguration {
        return false;
    }
    match item.rule_id.as_str() {
        "go-tls-insecure-skip-verify" | "rust-reqwest-tls-verification" => {
            boolean_control(item, "verification") == Some(false)
        }
        "javascript-tls-reject-unauthorized"
        | "typescript-tls-reject-unauthorized"
        | "tsx-tls-reject-unauthorized"
        | "python-tls-verification" => boolean_control(item, "verification") == Some(true),
        "csharp-tls-certificate-validation" | "java-tls-hostname-verifier" => {
            boolean_control(item, "decision") == Some(false)
        }
        "kotlin-tls-hostname-verifier" => boolean_control(item, "callback") == Some(false),
        "kotlin-tls-trust-context" => item
            .captures
            .get("trust_managers")
            .is_some_and(|c| c.text.trim() == "null"),
        _ => false,
    }
}

fn ordinary_xml_control(item: &Evidence) -> bool {
    if item.rule_id != "kotlin-xml-configuration" {
        return false;
    }
    let feature = item
        .captures
        .get("feature")
        .map(|c| c.text.trim().trim_matches(['\'', '"']));
    match feature {
        Some(
            "http://xml.org/sax/features/external-general-entities"
            | "http://xml.org/sax/features/external-parameter-entities"
            | "http://apache.org/xml/features/nonvalidating/load-external-dtd",
        ) => boolean_control(item, "value") == Some(false),
        Some(
            "http://apache.org/xml/features/disallow-doctype-decl"
            | "http://javax.xml.XMLConstants/feature/secure-processing"
            | "XMLConstants.FEATURE_SECURE_PROCESSING",
        ) => boolean_control(item, "value") == Some(true),
        Some(
            "XMLConstants.ACCESS_EXTERNAL_DTD"
            | "XMLConstants.ACCESS_EXTERNAL_SCHEMA"
            | "http://javax.xml.XMLConstants/property/accessExternalDTD"
            | "http://javax.xml.XMLConstants/property/accessExternalSchema",
        ) => item
            .captures
            .get("value")
            .is_some_and(|c| c.text.trim() == "\"\""),
        None => boolean_control(item, "value") == Some(false),
        _ => false,
    }
}

fn known_data_only_yaml(item: &Evidence, sources: &RepositorySources) -> bool {
    if !matches!(
        item.rule_id.as_str(),
        "javascript-yaml-deserialization"
            | "typescript-yaml-deserialization"
            | "tsx-yaml-deserialization"
    ) || item
        .symbol_resolution
        .as_ref()
        .is_none_or(|s| s.canonical != "js-yaml.load")
        || item.captures.contains_key("type")
    {
        return false;
    }
    // Package policy is shared, not a hypothetical custom-loader audit at each
    // normal call. Only the established v4 default data schema is closed here;
    // unknown/old versions and custom schema options retain their question.
    let mut directory = Path::new(&item.location.path).parent();
    while let Some(parent) = directory {
        let manifest = parent
            .join("package.json")
            .to_string_lossy()
            .replace('\\', "/");
        if let Ok(file) = sources.file(&manifest) {
            let Ok(package) = serde_json::from_str::<serde_json::Value>(&file.source) else {
                return false;
            };
            return ["dependencies", "devDependencies", "optionalDependencies"]
                .iter()
                .filter_map(|section| package[*section]["js-yaml"].as_str())
                .any(|version| {
                    version
                        .trim_start_matches(['^', '~', '='])
                        .starts_with("4.")
                });
        }
        directory = parent.parent();
    }
    false
}

fn ordinary_decoder(item: &Evidence, evidence: &[Evidence], sources: &RepositorySources) -> bool {
    if item.capability != Capability::Deserialization || executable_deserializer(item) {
        return false;
    }
    match item.rule_id.as_str() {
        "rust-data-deserialization" => true,
        "java-jackson-object-deserialization" | "kotlin-jackson-deserialization" => {
            // Policy often lives in a separate configuration or DTO file.
            // Conservatively retain loaders when project-visible class-name
            // polymorphism/default typing exists; no whole-program binding.
            let policy_evidence = evidence.iter().any(|other| {
                matches!(
                    other.rule_id.as_str(),
                    "java-jackson-default-typing-enabled"
                        | "java-jackson-class-name-polymorphism"
                        | "java-jackson-broad-polymorphic-type-permission"
                )
            });
            // Kotlin can configure the same Java mapper without a dedicated
            // policy emitter. Such explicit policy syntax vetoes the ordinary
            // decoder cut; it is a lead, not a bound mapper/safety conclusion.
            let policy_syntax = sources.files.iter().any(|(path, file)| {
                (path.ends_with(".java") || path.ends_with(".kt"))
                    && [
                        ".activateDefaultTyping",
                        ".enableDefaultTyping",
                        "Id.CLASS",
                        "Id.MINIMAL_CLASS",
                    ]
                    .iter()
                    .any(|marker| file.source.contains(marker))
            });
            !policy_evidence && !policy_syntax
        }
        _ => false,
    }
}

fn security_purpose(item: &Evidence, sources: &RepositorySources) -> bool {
    if item.tags.iter().any(|tag| {
        matches!(
            tag.as_str(),
            "password"
                | "password-storage"
                | "credential"
                | "security-purpose"
                | "authentication"
                | "signature"
        )
    }) {
        return true;
    }
    // Bounded consumer/purpose clues: preserve plausible security helpers and
    // operands, not every unrelated security word anywhere in a large file.
    let local = format!(
        "{} {} {}",
        item.enclosing_symbol.as_deref().unwrap_or(""),
        item.captures
            .values()
            .map(|c| c.text.as_str())
            .collect::<Vec<_>>()
            .join(" "),
        anchor_line(item, sources)
    )
    .to_ascii_lowercase();
    [
        "password",
        "passwd",
        "secret",
        "token",
        "nonce",
        "signature",
        "signing",
        "authenticate",
        "verify",
        "integrity",
        "hmac",
        "credential",
    ]
    .iter()
    .any(|word| local.contains(word))
}

fn anchor_text<'a>(item: &Evidence, sources: &'a RepositorySources) -> &'a str {
    sources
        .file(&item.location.path)
        .ok()
        .and_then(|file| {
            file.source
                .get(item.location.start.byte_offset..item.location.end.byte_offset)
        })
        .unwrap_or("")
        .trim()
}

fn anchor_line<'a>(item: &Evidence, sources: &'a RepositorySources) -> &'a str {
    sources
        .file(&item.location.path)
        .ok()
        .and_then(|file| {
            let start = item.location.start.byte_offset.min(file.source.len());
            let end = item.location.end.byte_offset.min(file.source.len());
            let from = file
                .source
                .get(..start)?
                .rfind(['\n', ';', '{', '}'])
                .map_or(0, |i| i + 1);
            let to = file
                .source
                .get(end..)?
                .find(['\n', ';', '{', '}'])
                .map_or(file.source.len(), |i| end + i);
            file.source.get(from..to)
        })
        .unwrap_or("")
}

pub(super) fn filesystem_research_hint(item: &Evidence) -> Option<ValueReviewHint> {
    let recursive = item.rule_id == "java-filesystem-read" && item.tags.iter().any(|t| t == "walk")
        || item.rule_id == "csharp-filesystem-read"
            && item.symbol_resolution.as_ref().is_some_and(|s| {
                matches!(
                    s.canonical.as_str(),
                    "System.IO.Directory.GetFiles"
                        | "System.IO.Directory.GetDirectories"
                        | "System.IO.Directory.EnumerateFiles"
                )
            });
    recursive.then(|| ValueReviewHint {
        reason: "recursive_filesystem_root_research".into(),
        target: item.location.path.clone(),
        assumption: "Unconnected recursive/option-selected enumeration retains a Comprehensive root/export question. Review an actual content, export or sensitive disclosure consumer; no root containment or safe verdict is inferred.".into(),
        depends_on: None,
    })
}

pub(super) fn comprehensive_hint(item: &Evidence) -> Option<ValueReviewHint> {
    // An origin can decide the redirect verdict without making ordinary
    // navigation high-value. Keep the question and exact Comprehensive ID.
    if item
        .tags
        .iter()
        .any(|tag| tag == "review-origin:decision-critical")
        && item.cwe_candidates != ["CWE-601"]
    {
        return None;
    }
    if matches!(
        item.rule_id.as_str(),
        "php-html-output" | "php-file-inclusion"
    ) {
        return Some(ValueReviewHint {
            reason: "php_relationship_research".into(), target: item.location.path.clone(),
            assumption: "Research input authority, reaching producer, protection and interpretation for this retained PHP relationship. No weakness or safe verdict is established; promote a demonstrated mechanism or consequential reviewer-origin lead to Value.".into(),
            depends_on: None,
        });
    }
    if item.cwe_candidates.iter().all(|cwe| {
        matches!(
            cwe.as_str(),
            "CWE-117" | "CWE-601" | "CWE-614" | "CWE-1004" | "CWE-942" | "CWE-352"
        )
    }) && !item.cwe_candidates.is_empty()
        || matches!(
            item.rule_id.as_str(),
            "go-gob-deserialization" | "python-marshal-deserialization"
        )
    {
        return Some(ValueReviewHint {
            reason: "medium_impact_relationship".into(),
            target: item.location.path.clone(),
            assumption: "Plausible medium-impact relationship retained in Comprehensive. Promote to Value when stronger evidence, a clearly justified fix or a consequential high-impact chain warrants it; this is not a safe verdict.".into(),
            depends_on: None,
        });
    }
    None
}
