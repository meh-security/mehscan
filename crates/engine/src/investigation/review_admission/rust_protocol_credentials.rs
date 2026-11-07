//! Typed HTTP framing, default credential headers and generated-token output.
use super::*;
use rust_allocation::{method, receiver_type};
use rust_shared_state::AstNode as N;
fn named<'a>(n: &N<'a>) -> Vec<N<'a>> {
    n.children()
        .filter(|n| n.is_named() && !n.kind().contains("comment"))
        .collect()
}
fn strip<'a>(n: &N<'a>) -> Option<N<'a>> {
    let mut n = n.clone();
    for _ in 0..8 {
        if !matches!(
            n.kind().as_ref(),
            "try_expression" | "reference_expression" | "parenthesized_expression"
        ) {
            return Some(n);
        }
        n = n.field("value").or_else(|| named(&n).into_iter().next())?;
    }
    None
}
fn binding<'a>(value: &N<'a>, function: &N<'a>) -> Option<N<'a>> {
    if value.kind().as_ref() != "identifier" {
        return None;
    }
    let name = value.text();
    for scope in value
        .ancestors()
        .take_while(|n| n.range() != function.range())
    {
        if scope.kind().as_ref() == "block" {
            if let Some(b) = scope
                .children()
                .filter(|n| {
                    n.kind().as_ref() == "let_declaration"
                        && n.range().end <= value.range().start
                        && n.field("pattern").is_some_and(|p| {
                            p.dfs()
                                .any(|n| n.kind().as_ref() == "identifier" && n.text() == name)
                        })
                })
                .last()
            {
                if b.field("pattern")?.kind().as_ref() != "identifier" {
                    return None;
                }
                if function.dfs().any(|n| {
                    n.kind().as_ref() == "assignment_expression"
                        && n.range().start > b.range().end
                        && n.range().start < value.range().start
                        && n.field("left").is_some_and(|n| n.text() == name)
                }) {
                    return None;
                }
                return Some(b);
            }
        } else if scope.kind().as_ref() != "let_declaration"
            && scope
                .field("pattern")
                .or_else(|| scope.field("condition").and_then(|c| c.field("pattern")))
                .is_some_and(|p| p.dfs().any(|n| n.text() == name))
        {
            return None;
        }
    }
    function.field("parameters")?.children().find(|p| {
        p.kind().as_ref() == "parameter"
            && p.field("pattern")
                .is_some_and(|p| p.kind().as_ref() == "identifier" && p.text() == name)
    })
}
fn map_binding<'a>(root: &N<'a>, value: &N<'a>, function: &N<'a>, depth: usize) -> Option<N<'a>> {
    if depth > 8 {
        return None;
    }
    let value = strip(value)?;
    let b = binding(&value, function)?;
    if receiver_type(root, &value, function, 0)
        .is_some_and(|s| matches!(s.as_str(), "http::HeaderMap" | "reqwest::header::HeaderMap"))
    {
        return Some(b);
    }
    let initializer = strip(&b.field("value")?)?;
    if rust_raw_memory::api(root, &initializer).is_some_and(|s| {
        matches!(
            s.as_str(),
            "http::HeaderMap::new" | "reqwest::header::HeaderMap::new"
        )
    }) {
        return Some(b);
    }
    map_binding(root, &initializer, function, depth + 1)
}
fn header_key<'a>(root: &N<'a>, key: &N<'a>) -> Option<&'static str> {
    let text = key.text();
    if key.kind().as_ref() == "string_literal" {
        match text.trim_matches('"').to_ascii_lowercase().as_str() {
            "content-length" => return Some("length"),
            "transfer-encoding" => return Some("transfer"),
            "authorization" | "proxy-authorization" | "x-api-key" | "x-auth-token" => {
                return Some("credential");
            }
            _ => return None,
        }
    }
    let canonical = rust_raw_memory::canonical(root, key, &text)?;
    match canonical.as_str() {
        "http::header::CONTENT_LENGTH" | "reqwest::header::CONTENT_LENGTH" => Some("length"),
        "http::header::TRANSFER_ENCODING" | "reqwest::header::TRANSFER_ENCODING" => {
            Some("transfer")
        }
        "http::header::AUTHORIZATION"
        | "http::header::PROXY_AUTHORIZATION"
        | "reqwest::header::AUTHORIZATION"
        | "reqwest::header::PROXY_AUTHORIZATION" => Some("credential"),
        _ => None,
    }
}
fn builder<'a>(root: &N<'a>, value: &N<'a>, function: &N<'a>, depth: usize) -> bool {
    if depth > 8 {
        return false;
    }
    let Some(v) = strip(value) else {
        return false;
    };
    if matches!(
        rust_raw_memory::api(root, &v).as_deref(),
        Some("reqwest::Client::builder" | "reqwest::blocking::Client::builder")
    ) {
        return true;
    }
    if matches!(
        receiver_type(root, &v, function, 0).as_deref(),
        Some("reqwest::ClientBuilder" | "reqwest::blocking::ClientBuilder")
    ) {
        return true;
    }
    if v.kind().as_ref() == "identifier" {
        return binding(&v, function)
            .and_then(|b| b.field("value"))
            .is_some_and(|n| builder(root, &n, function, depth + 1));
    }
    if let Some((receiver, name)) = method(&v)
        && matches!(
            name.as_str(),
            "redirect"
                | "timeout"
                | "connect_timeout"
                | "https_only"
                | "user_agent"
                | "cookie_store"
                | "default_headers"
                | "pool_idle_timeout"
        )
    {
        return builder(root, &receiver, function, depth + 1);
    }
    false
}
fn token_source<'a>(root: &N<'a>, value: &N<'a>, function: &N<'a>, depth: usize) -> Option<N<'a>> {
    if depth > 8 {
        return None;
    }
    let value = strip(value)?;
    if rust_raw_memory::api(root, &value).as_deref() == Some("jsonwebtoken::encode") {
        return Some(value);
    }
    if let Some((receiver, name)) = method(&value)
        && matches!(name.as_str(), "unwrap" | "expect")
    {
        return token_source(root, &receiver, function, depth + 1);
    }
    token_source(
        root,
        &binding(&value, function)?.field("value")?,
        function,
        depth + 1,
    )
}
fn output_macro<'a>(root: &N<'a>, call: &N<'a>) -> bool {
    let Some(name) = call.field("macro") else {
        return false;
    };
    let Some(identity) = rust_raw_memory::canonical(root, &name, &name.text()) else {
        return false;
    };
    if matches!(
        identity.as_str(),
        "std::println"
            | "std::eprintln"
            | "std::dbg"
            | "tracing::info"
            | "tracing::warn"
            | "tracing::error"
            | "tracing::debug"
            | "tracing::trace"
    ) {
        return true;
    }
    if !matches!(identity.as_str(), "println" | "eprintln" | "dbg") {
        return false;
    }
    !root.children().any(|n| {
        n.kind().as_ref() == "inner_attribute_item" && n.text().contains("no_implicit_prelude")
    }) && !call
        .ancestors()
        .filter(|n| {
            matches!(
                n.kind().as_ref(),
                "block" | "source_file" | "declaration_list"
            )
        })
        .flat_map(|n| n.children().collect::<Vec<_>>())
        .any(|n| {
            (n.kind().as_ref() == "macro_definition"
                && n.field("name").is_some_and(|n| n.text() == identity))
                || (n.kind().as_ref() == "use_declaration"
                    && n.dfs().any(|n| n.kind().as_ref() == "use_wildcard"))
        })
}
#[allow(clippy::too_many_arguments)]
fn emit(
    file: &SourceFile,
    function: &N<'_>,
    operation: &N<'_>,
    rule: &str,
    capability: Capability,
    cwe: &str,
    mut captures: BTreeMap<String, Capture>,
    scope: Option<&mehscan_core::ImpactScanScope>,
    groups: &mut Vec<ObservationGroup>,
) {
    let location = rust_dependencies::capture(file, operation).location;
    if scope.is_some_and(|s| {
        s.result_policy == "changed_locations"
            && !crate::impact::location_is_changed(&location, &s.changed_files)
    }) {
        return;
    }
    let id = review_admission_marker_id(
        &file.path,
        rule,
        operation.range().start,
        operation.range().end,
    );
    let symbol = function
        .field("name")
        .map(|n| n.text().into_owned())
        .unwrap_or_default();
    captures.insert(
        "policy_operation".into(),
        rust_dependencies::capture(file, operation),
    );
    captures.insert(
        "policy_definition".into(),
        rust_dependencies::capture(file, function),
    );
    groups.push(ObservationGroup {
        path: file.path.clone(),
        symbol: symbol.clone(),
        anchor_evidence_ids: vec![id.clone()],
        priority: 1,
        review_material: is_review_material_path(&file.path),
        evidence: vec![Evidence {
            id,
            rule_id: rule.into(),
            kind: EvidenceKind::SensitiveOperation,
            capability,
            location,
            enclosing_symbol: Some(symbol),
            captures,
            cwe_candidates: vec![cwe.into()],
            tags: vec![
                "review-admission-marker".into(),
                "rust-protocol-credential-obligation".into(),
            ],
            confidence: Confidence::Medium,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: "bounded Rust protocol and credential policy relationship".into(),
                rule_version: 1,
            },
            context: EvidenceContext::default(),
            symbol_resolution: None,
            related_evidence: vec![],
        }],
    });
}
fn validation_binding<'a>(
    root: &N<'a>,
    value: &N<'a>,
    function: &N<'a>,
    depth: usize,
) -> Option<N<'a>> {
    if depth > 8 {
        return None;
    }
    let value = strip(value)?;
    let b = binding(&value, function)?;
    if receiver_type(root, &value, function, 0).as_deref() == Some("jsonwebtoken::Validation") {
        return Some(b);
    }
    let initializer = strip(&b.field("value")?)?;
    if matches!(
        rust_raw_memory::api(root, &initializer).as_deref(),
        Some("jsonwebtoken::Validation::new" | "jsonwebtoken::Validation::default")
    ) {
        return Some(b);
    }
    validation_binding(root, &initializer, function, depth + 1)
}

pub(super) fn groups(
    sources: &RepositorySources,
    scope: Option<&mehscan_core::ImpactScanScope>,
    selection: &rust_configuration::Selection,
    parsed: &rust_dependencies::RustSources,
) -> Vec<ObservationGroup> {
    let mut groups = Vec::new();
    for file in sources
        .files
        .values()
        .filter(|f| f.language == Some(Language::Rust))
    {
        let Some(root) = parsed.root(&file.path) else {
            continue;
        };
        for function in root.dfs().filter(|n| {
            n.kind().as_ref() == "function_item" && !selection.excluded(&file.path, n.range())
        }) {
            if function.range().len() > 32768
                || function.dfs().any(|n| n.is_error() || n.is_missing())
            {
                continue;
            }
            let calls = function
                .dfs()
                .filter(|n| {
                    n.kind().as_ref() == "call_expression"
                        && rust_shared_state::owns(n, &function)
                        && !selection.excluded(&file.path, n.range())
                        && rust_buffer_initialization::runtime_path(n, &function)
                })
                .collect::<Vec<_>>();
            let mut framing = BTreeMap::<usize, (Option<N<'_>>, Option<N<'_>>)>::new();
            for call in &calls {
                if rust_raw_memory::api(&root, call).as_deref() == Some("jsonwebtoken::decode") {
                    let arguments = call
                        .field("arguments")
                        .map(|n| named(&n))
                        .unwrap_or_default();
                    if let Some(validation) = arguments
                        .get(2)
                        .and_then(|v| validation_binding(&root, v, &function, 0))
                    {
                        let disabling = calls.iter().find(|c| {
                            c.range().start < call.range().start
                                && method(c).is_some_and(|(v, name)| {
                                    name == "insecure_disable_signature_validation"
                                        && validation_binding(&root, &v, &function, 0)
                                            .is_some_and(|b| b.range() == validation.range())
                                })
                        });
                        if let Some(disabling) = disabling {
                            emit(
                                file,
                                &function,
                                call,
                                "rust-jwt-verification-policy-review",
                                Capability::CredentialMaterial,
                                "CWE-347",
                                BTreeMap::from([
                                    (
                                        "verification_policy_disable".into(),
                                        rust_dependencies::capture(file, disabling),
                                    ),
                                    (
                                        "verification_policy_binding".into(),
                                        rust_dependencies::capture(file, &validation),
                                    ),
                                ]),
                                scope,
                                &mut groups,
                            );
                        }
                    }
                }
                let Some((receiver, name)) = method(call) else {
                    continue;
                };
                let args = call
                    .field("arguments")
                    .map(|n| named(&n))
                    .unwrap_or_default();
                if name == "get"
                    && let Some(key) = args.first()
                    && let Some(kind) = header_key(&root, key)
                    && matches!(kind, "length" | "transfer")
                {
                    let owner = map_binding(&root, &receiver, &function, 0).or_else(|| {
                        let (request, name) = method(&receiver)?;
                        (name == "headers"
                            && receiver_type(&root, &request, &function, 0)
                                .is_some_and(|s| s == "http::Request"))
                        .then(|| binding(&request, &function))
                        .flatten()
                    });
                    if let Some(owner) = owner {
                        let pair = framing.entry(owner.range().start).or_default();
                        if kind == "length" {
                            pair.0 = Some(call.clone());
                        } else {
                            pair.1 = Some(call.clone());
                        }
                    }
                }
                if name == "default_headers"
                    && builder(&root, &receiver, &function, 0)
                    && let Some(headers) = args.first()
                    && let Some(map) = map_binding(&root, headers, &function, 0)
                {
                    let insertion = calls.iter().find(|insert| {
                        let Some((receiver, name)) = method(insert) else {
                            return false;
                        };
                        if name != "insert" || insert.range().start >= call.range().start {
                            return false;
                        }
                        map_binding(&root, &receiver, &function, 0)
                            .is_some_and(|b| b.range() == map.range())
                            && insert
                                .field("arguments")
                                .and_then(|n| named(&n).into_iter().next())
                                .is_some_and(|key| header_key(&root, &key) == Some("credential"))
                    });
                    if let Some(insert) = insertion {
                        emit(
                            file,
                            &function,
                            call,
                            "rust-default-credential-header-review",
                            Capability::CredentialMaterial,
                            "CWE-201",
                            BTreeMap::from([
                                (
                                    "credential_header_insert".into(),
                                    rust_dependencies::capture(file, insert),
                                ),
                                (
                                    "header_map_binding".into(),
                                    rust_dependencies::capture(file, &map),
                                ),
                            ]),
                            scope,
                            &mut groups,
                        );
                    }
                }
            }
            for call in &calls {
                if let Some((receiver, name)) = method(call)
                    && name == "write_all"
                    && receiver_type(&root, &receiver, &function, 0).is_some_and(|s| {
                        matches!(s.as_str(), "std::net::TcpStream" | "tokio::net::TcpStream")
                    })
                {
                    let Some(bytes) = call
                        .field("arguments")
                        .and_then(|n| named(&n).into_iter().next())
                    else {
                        continue;
                    };
                    let Some(input) = rust_memory_boundaries::byte_input(&root, &bytes, &function)
                    else {
                        continue;
                    };
                    for (length, transfer) in framing.values() {
                        if let (Some(length), Some(transfer)) = (length, transfer) {
                            emit(
                                file,
                                &function,
                                call,
                                "rust-http-framing-forward-review",
                                Capability::ResourceAccess,
                                "CWE-444",
                                BTreeMap::from([
                                    (
                                        "content_length_read".into(),
                                        rust_dependencies::capture(file, length),
                                    ),
                                    (
                                        "transfer_encoding_read".into(),
                                        rust_dependencies::capture(file, transfer),
                                    ),
                                    (
                                        "forwarded_input".into(),
                                        rust_dependencies::capture(file, &input),
                                    ),
                                ]),
                                scope,
                                &mut groups,
                            );
                            break;
                        }
                    }
                }
            }
            for call in function.dfs().filter(|n| {
                n.kind().as_ref() == "macro_invocation"
                    && rust_shared_state::owns(n, &function)
                    && !selection.excluded(&file.path, n.range())
                    && rust_buffer_initialization::runtime_path(n, &function)
            }) {
                if !output_macro(&root, &call) {
                    continue;
                }
                let Some(tokens) = call.children().find(|n| n.kind().as_ref() == "token_tree")
                else {
                    continue;
                };
                let tokens = tokens.children().collect::<Vec<_>>();
                for (i, value) in tokens.iter().enumerate() {
                    if value.kind().as_ref() != "identifier" || i == 0 {
                        continue;
                    }
                    let before = tokens[i - 1].text();
                    let after = tokens
                        .get(i + 1)
                        .map(|n| n.text().into_owned())
                        .unwrap_or_default();
                    if !matches!(before.as_ref(), "," | "(" | "[" | "{")
                        || !matches!(after.as_str(), "," | ")" | "]" | "}")
                    {
                        continue;
                    }
                    if let Some(producer) = token_source(&root, value, &function, 0) {
                        emit(
                            file,
                            &function,
                            &call,
                            "rust-generated-credential-output-review",
                            Capability::CredentialMaterial,
                            "CWE-532",
                            BTreeMap::from([
                                (
                                    "token_producer".into(),
                                    rust_dependencies::capture(file, &producer),
                                ),
                                (
                                    "output_argument".into(),
                                    rust_dependencies::capture(file, value),
                                ),
                            ]),
                            scope,
                            &mut groups,
                        );
                        break;
                    }
                }
            }
        }
    }
    groups
}
