use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "ast-grep 0.45.1 + bounded-node-identity-boundary";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_identity_boundary_observations<'tree>(
    path: &str,
    source: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !is_node_language(language) || is_non_runtime_example_path(path) {
        return;
    }
    let lower = source.to_ascii_lowercase();
    if lower.contains(".sign(") || lower.contains(".verify(") || lower.contains(".decode(") {
        add_jwt_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    if lower.contains("tokenmap") {
        add_session_map_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    if lower.contains(".cookie(") {
        add_cookie_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    if lower.contains("req.cookies") && lower.contains("req.body") {
        add_csrf_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    if lower.contains("cors(") || lower.contains("access-control-allow-origin") {
        add_cors_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    if lower.contains("x-forwarded-for") && lower.contains("trust proxy") {
        add_proxy_rate_limit_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    if lower.contains("reset") && lower.contains("token") && lower.contains("password") {
        add_reset_token_observations(
            path,
            root,
            language,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_jwt_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for node in root.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        if comments.is_in_comment(call.node.range()) {
            continue;
        }
        let callee = compact(&call.callee).to_ascii_lowercase();
        if callee.ends_with("jwt.sign") || callee == "jwt.sign" {
            if let Some(key) = call.arguments.get(1) {
                let options = call
                    .arguments
                    .get(2)
                    .map(|node| compact(node.text().as_ref()));
                let has_expiry = options
                    .as_deref()
                    .is_some_and(|text| text.to_ascii_lowercase().contains("expiresin:"));
                let has_algorithm = options
                    .as_deref()
                    .is_some_and(|text| text.to_ascii_lowercase().contains("algorithm:"));
                if !has_expiry {
                    push_pair(
                        path,
                        language,
                        "jwt-signing-key",
                        "jwt-without-expiry",
                        key,
                        &call.node,
                        Capability::CredentialMaterial,
                        Capability::TokenGeneration,
                        "expiry_key",
                        "CWE-613",
                        vec!["jwt".into(), "signing".into(), "missing-expiry".into()],
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                } else {
                    push_control(
                        path,
                        language,
                        "jwt-expiry",
                        &call.node,
                        Capability::TokenGeneration,
                        "CWE-613",
                        vec!["jwt".into(), "signing".into(), "expiry-configured".into()],
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
                if has_algorithm {
                    push_control(
                        path,
                        language,
                        "jwt-signing-algorithm",
                        &call.node,
                        Capability::TokenGeneration,
                        "CWE-347",
                        vec!["jwt".into(), "signing".into(), "algorithm-explicit".into()],
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
                if is_hardcoded_signing_key(root, key) {
                    push_pair(
                        path,
                        language,
                        "hardcoded-jwt-key",
                        "jwt-hardcoded-signing-key",
                        key,
                        &call.node,
                        Capability::CredentialMaterial,
                        Capability::TokenGeneration,
                        "signing_key",
                        "CWE-321",
                        vec!["jwt".into(), "signing".into(), "hardcoded-key".into()],
                        comments,
                        conditional,
                        literals,
                        evidence,
                    );
                }
            }
        } else if callee.ends_with("jwt.verify") || callee == "jwt.verify" {
            let Some(token) = call.arguments.first() else {
                continue;
            };
            let algorithms = call.arguments.iter().skip(2).any(|argument| {
                compact(argument.text().as_ref())
                    .to_ascii_lowercase()
                    .contains("algorithms:")
            });
            if algorithms {
                push_control(
                    path,
                    language,
                    "jwt-algorithm-allowlist",
                    &call.node,
                    Capability::Authentication,
                    "CWE-347",
                    vec![
                        "jwt".into(),
                        "verification".into(),
                        "algorithm-allowlist".into(),
                    ],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            } else {
                push_pair(
                    path,
                    language,
                    "jwt-token-input",
                    "jwt-verify-without-algorithm-allowlist",
                    token,
                    &call.node,
                    Capability::HttpRequestData,
                    Capability::Authentication,
                    "token",
                    "CWE-347",
                    vec![
                        "jwt".into(),
                        "verification".into(),
                        "missing-algorithm-allowlist".into(),
                    ],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        } else if callee.ends_with("jwt.decode")
            || callee == "jwt.decode"
            || callee.ends_with("security.decode")
        {
            let Some(token) = call.arguments.first() else {
                continue;
            };
            let scope = function_ancestor(&call.node).unwrap_or_else(|| root.clone());
            let scope_text = compact(scope.text().as_ref()).to_ascii_lowercase();
            let has_verification = scope_text.contains("jwt.verify(")
                || scope_text.contains("security.verify(")
                || scope_text.contains("jws.verify(");
            let returns_identity = scope_text.contains("returndecoded?.data?.")
                || scope_text.contains("returndecoded.data.");
            if !has_verification && returns_identity {
                push_pair(
                    path,
                    language,
                    "unverified-jwt-token",
                    "jwt-decode-as-identity",
                    token,
                    &call.node,
                    Capability::HttpRequestData,
                    Capability::Authentication,
                    "unverified_token",
                    "CWE-345",
                    vec![
                        "jwt".into(),
                        "decode".into(),
                        "identity-without-verification".into(),
                    ],
                    comments,
                    conditional,
                    literals,
                    evidence,
                );
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_session_map_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let root_text = compact(root.text().as_ref()).to_ascii_lowercase();
    if !root_text.contains("tokenmap:{}")
        || !root_text.contains("this.tokenmap[")
        || root_text.contains("deletethis.tokenmap[")
        || root_text.contains("this.tokenmap.delete(")
    {
        return;
    }
    for node in root.dfs() {
        if node.kind().as_ref() != "return_statement" || comments.is_in_comment(node.range()) {
            continue;
        }
        let text = compact(node.text().as_ref()).to_ascii_lowercase();
        if !text.contains("this.tokenmap[") {
            continue;
        }
        let source = node
            .dfs()
            .find(|candidate| {
                candidate.kind().as_ref() == "identifier"
                    && candidate.text().trim().eq_ignore_ascii_case("token")
            })
            .unwrap_or_else(|| node.clone());
        push_pair(
            path,
            language,
            "session-token",
            "session-map-without-invalidation",
            &source,
            &node,
            Capability::CredentialMaterial,
            Capability::Authentication,
            "session_token",
            "CWE-613",
            vec![
                "session".into(),
                "server-token-map".into(),
                "no-invalidation".into(),
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
        break;
    }
}

#[allow(clippy::too_many_arguments)]
fn add_cookie_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for node in root.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        if comments.is_in_comment(call.node.range())
            || !terminal_symbol(&call.callee).eq_ignore_ascii_case("cookie")
            || call.arguments.len() < 2
        {
            continue;
        }
        let name = call.arguments[0]
            .text()
            .trim()
            .trim_matches(['\'', '"'])
            .to_ascii_lowercase();
        if !["token", "session", "sessionid", "jwt", "auth"].contains(&name.as_str()) {
            continue;
        }
        let payload = &call.arguments[1];
        let options = call
            .arguments
            .get(2)
            .map(|node| compact(node.text().as_ref()).to_ascii_lowercase())
            .unwrap_or_default();
        let secure = options.contains("secure:true");
        let http_only = options.contains("httponly:true");
        let same_site = options.contains("samesite:")
            && !options.contains("samesite:'none'")
            && !options.contains("samesite:\"none\"");
        if !secure {
            push_pair(
                path,
                language,
                "cookie-credential",
                "auth-cookie-missing-secure",
                payload,
                &call.node,
                Capability::CredentialMaterial,
                Capability::CookieConfiguration,
                "secure_payload",
                "CWE-614",
                vec![
                    "cookie".into(),
                    "authentication".into(),
                    "missing-secure".into(),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if !http_only {
            push_pair(
                path,
                language,
                "cookie-credential",
                "auth-cookie-missing-http-only",
                payload,
                &call.node,
                Capability::CredentialMaterial,
                Capability::CookieConfiguration,
                "http_only_payload",
                "CWE-1004",
                vec![
                    "cookie".into(),
                    "authentication".into(),
                    "missing-http-only".into(),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if !same_site {
            push_configuration(
                path,
                language,
                "auth-cookie-missing-same-site",
                &call.node,
                Capability::CookieConfiguration,
                "CWE-1275",
                vec![
                    "cookie".into(),
                    "authentication".into(),
                    "missing-same-site".into(),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if secure && http_only && same_site {
            push_control(
                path,
                language,
                "auth-cookie-hardened",
                &call.node,
                Capability::CookieConfiguration,
                "CWE-614",
                vec!["cookie".into(), "authentication".into(), "hardened".into()],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_csrf_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for node in root.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        let operation = terminal_symbol(&call.callee).to_ascii_lowercase();
        if !matches!(operation.as_str(), "update" | "create" | "destroy" | "save")
            || comments.is_in_comment(call.node.range())
        {
            continue;
        }
        let scope = function_ancestor(&call.node).unwrap_or_else(|| root.clone());
        let text = compact(scope.text().as_ref()).to_ascii_lowercase();
        if !text.contains("req.cookies") || !text.contains("req.body") {
            continue;
        }
        let protected = [
            "csrfprotection",
            "verifycsrftoken",
            "doublecsrf",
            "x-csrf-token",
            "x-xsrf-token",
        ]
        .iter()
        .any(|needle| text.contains(needle));
        if protected {
            push_control(
                path,
                language,
                "csrf-protection",
                &call.node,
                Capability::ResourceAccess,
                "CWE-352",
                vec![
                    "csrf".into(),
                    "state-change".into(),
                    "token-validated".into(),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        }
        let Some(cookie) = scope.dfs().find(|candidate| {
            compact(candidate.text().as_ref())
                .to_ascii_lowercase()
                .starts_with("req.cookies.")
        }) else {
            continue;
        };
        push_pair(
            path,
            language,
            "cookie-authentication",
            "cookie-authenticated-state-change",
            &cookie,
            &call.node,
            Capability::HttpRequestData,
            Capability::ResourceAccess,
            "operation",
            "CWE-352",
            vec![
                "csrf".into(),
                "cookie-authentication".into(),
                "state-change".into(),
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_cors_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for origin in root.dfs().filter_map(call_site) {
        if !is_response_header(&origin, "access-control-allow-origin", "*")
            || comments.is_in_comment(origin.node.range())
        {
            continue;
        }
        let scope = function_scope_range(&origin.node, root);
        let credentials = root.dfs().filter_map(call_site).find(|candidate| {
            candidate.node.range().start >= scope.0
                && candidate.node.range().end <= scope.1
                && is_response_header(candidate, "access-control-allow-credentials", "true")
        });
        let Some(credentials) = credentials else {
            continue;
        };
        push_pair(
            path,
            language,
            "request-origin",
            "permissive-cors-policy",
            &origin.node,
            &credentials.node,
            Capability::HttpRequestData,
            Capability::HttpRequestHandling,
            "policy",
            "CWE-942",
            vec![
                "cors".into(),
                "permissive-origin".into(),
                "credentials-enabled".into(),
                "manual-response-headers".into(),
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
    }
    for node in root.dfs() {
        let Some(call) = call_site(node) else {
            continue;
        };
        if !terminal_symbol(&call.callee).eq_ignore_ascii_case("cors")
            || comments.is_in_comment(call.node.range())
        {
            continue;
        }
        let options = call
            .arguments
            .first()
            .map(|node| compact(node.text().as_ref()).to_ascii_lowercase());
        let permissive = options.as_deref().is_some_and(|text| {
            text.contains("credentials:true")
                && (text.contains("origin:'*'")
                    || text.contains("origin:\"*\"")
                    || text.contains("origin:true"))
        });
        if permissive {
            push_pair(
                path,
                language,
                "request-origin",
                "permissive-cors-policy",
                &call.node,
                &call.node,
                Capability::HttpRequestData,
                Capability::HttpRequestHandling,
                "policy",
                "CWE-942",
                vec!["cors".into(), "permissive-origin".into()],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else if options.is_some() {
            push_control(
                path,
                language,
                "cors-origin-allowlist",
                &call.node,
                Capability::HttpRequestHandling,
                "CWE-942",
                vec!["cors".into(), "origin-restricted".into()],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else {
            push_configuration(
                path,
                language,
                "cors-wildcard-without-credentials",
                &call.node,
                Capability::HttpRequestHandling,
                "CWE-942",
                vec![
                    "cors".into(),
                    "wildcard".into(),
                    "credentials-disabled".into(),
                ],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn is_response_header(call: &CallSite<'_>, expected_name: &str, expected_value: &str) -> bool {
    matches!(terminal_symbol(&call.callee), "header" | "set")
        && call.arguments.len() >= 2
        && call.arguments[0]
            .text()
            .trim()
            .trim_matches(['\'', '"'])
            .eq_ignore_ascii_case(expected_name)
        && call.arguments[1]
            .text()
            .trim()
            .trim_matches(['\'', '"'])
            .eq_ignore_ascii_case(expected_value)
}

fn function_scope_range(
    node: &Node<'_, StrDoc<SupportLang>>,
    root: &Node<'_, StrDoc<SupportLang>>,
) -> (usize, usize) {
    node.ancestors()
        .find(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
            )
        })
        .map(|function| (function.range().start, function.range().end))
        .unwrap_or((root.range().start, root.range().end))
}

#[allow(clippy::too_many_arguments)]
fn add_proxy_rate_limit_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let root_text = compact(root.text().as_ref()).to_ascii_lowercase();
    let broad_trust = root_text.contains("enable('trustproxy')")
        || root_text.contains("enable(\"trustproxy\")")
        || root_text.contains("set('trustproxy',true)")
        || root_text.contains("set(\"trustproxy\",true)");
    if !broad_trust {
        return;
    }
    for node in root.dfs() {
        let text = compact(node.text().as_ref()).to_ascii_lowercase();
        if comments.is_in_comment(node.range())
            || text.len() > 96
            || !(text.contains("headers['x-forwarded-for']")
                || text.contains("headers[\"x-forwarded-for\"]"))
        {
            continue;
        }
        let sink = node
            .ancestors()
            .filter(|ancestor| {
                compact(ancestor.text().as_ref())
                    .to_ascii_lowercase()
                    .contains("keygenerator")
            })
            .min_by_key(|ancestor| ancestor.range().end - ancestor.range().start)
            .unwrap_or_else(|| node.clone());
        if !compact(sink.text().as_ref())
            .to_ascii_lowercase()
            .contains("keygenerator")
        {
            continue;
        }
        push_pair(
            path,
            language,
            "forwarded-client-address",
            "spoofable-rate-limit-key",
            &node,
            &sink,
            Capability::HttpRequestData,
            Capability::Authentication,
            "client_key",
            "CWE-307",
            vec![
                "rate-limit".into(),
                "trust-proxy".into(),
                "forwarded-for".into(),
            ],
            comments,
            conditional,
            literals,
            evidence,
        );
        break;
    }
}

#[allow(clippy::too_many_arguments)]
fn add_reset_token_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for node in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        )
    }) {
        let text = compact(node.text().as_ref()).to_ascii_lowercase();
        if !(text.contains("reset")
            && text.contains("token")
            && text.contains("password")
            && (text.contains("verifyresettoken(") || text.contains("validateresettoken(")))
        {
            continue;
        }
        let consumed = [
            "deleteresettoken(",
            "invalidateresettoken(",
            "consumeresettoken(",
            ".destroy(",
            ".delete(",
        ]
        .iter()
        .any(|needle| text.contains(needle));
        if consumed {
            push_control(
                path,
                language,
                "reset-token-consumed",
                &node,
                Capability::Authentication,
                "CWE-640",
                vec!["password-reset".into(), "one-time-token".into()],
                comments,
                conditional,
                literals,
                evidence,
            );
        } else {
            let source = node
                .dfs()
                .find(|candidate| {
                    compact(candidate.text().as_ref())
                        .to_ascii_lowercase()
                        .contains("body.token")
                })
                .unwrap_or_else(|| node.clone());
            push_pair(
                path,
                language,
                "reset-token",
                "reusable-reset-token",
                &source,
                &node,
                Capability::CredentialMaterial,
                Capability::Authentication,
                "reset_token",
                "CWE-640",
                vec!["password-reset".into(), "token-not-consumed".into()],
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn push_pair<'tree>(
    path: &str,
    language: Language,
    source_suffix: &str,
    sink_suffix: &str,
    source_node: &Node<'tree, StrDoc<SupportLang>>,
    sink_node: &Node<'tree, StrDoc<SupportLang>>,
    source_capability: Capability,
    sink_capability: Capability,
    sink_role: &str,
    cwe: &str,
    tags: Vec<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let source_rule = language_rule(language, source_suffix);
    let source_id = evidence_id(
        path,
        &source_rule,
        source_node.range().start,
        source_node.range().end,
    );
    if !evidence.iter().any(|item| item.id == source_id) {
        evidence.push(Evidence {
            id: source_id.clone(),
            kind: EvidenceKind::Source,
            capability: source_capability,
            location: location(path, source_node),
            enclosing_symbol: enclosing_symbol(sink_node),
            captures: BTreeMap::from([("value".into(), capture(path, source_node))]),
            cwe_candidates: vec![],
            tags: vec!["bounded-identity-boundary".into()],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(source_node, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: source_rule,
            related_evidence: vec![],
        });
    }
    let sink_rule = language_rule(language, sink_suffix);
    let sink_id = evidence_id(
        path,
        &sink_rule,
        sink_node.range().start,
        sink_node.range().end,
    );
    if evidence.iter().any(|item| item.id == sink_id) {
        return;
    }
    evidence.push(Evidence {
        id: sink_id,
        kind: EvidenceKind::Sink,
        capability: sink_capability,
        location: location(path, sink_node),
        enclosing_symbol: enclosing_symbol(sink_node),
        captures: BTreeMap::from([(sink_role.into(), capture(path, source_node))]),
        cwe_candidates: vec![cwe.into()],
        tags,
        confidence: Confidence::Medium,
        provenance: provenance(),
        context: evidence_context(sink_node, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: sink_rule,
        related_evidence: vec![source_id],
    });
}

#[allow(clippy::too_many_arguments)]
fn push_control<'tree>(
    path: &str,
    language: Language,
    suffix: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    capability: Capability,
    cwe: &str,
    tags: Vec<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let rule_id = language_rule(language, suffix);
    let id = evidence_id(path, &rule_id, node.range().start, node.range().end);
    if evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(Evidence {
        id,
        kind: EvidenceKind::Guard,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures: BTreeMap::new(),
        cwe_candidates: vec![cwe.into()],
        tags,
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(node, comments, conditional, literals),
        symbol_resolution: None,
        rule_id,
        related_evidence: vec![],
    });
}

#[allow(clippy::too_many_arguments)]
fn push_configuration<'tree>(
    path: &str,
    language: Language,
    suffix: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    capability: Capability,
    cwe: &str,
    tags: Vec<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let rule_id = language_rule(language, suffix);
    let id = evidence_id(path, &rule_id, node.range().start, node.range().end);
    if evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(Evidence {
        id,
        kind: EvidenceKind::SecurityConfiguration,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures: BTreeMap::new(),
        cwe_candidates: vec![cwe.into()],
        tags,
        confidence: Confidence::Medium,
        provenance: provenance(),
        context: evidence_context(node, comments, conditional, literals),
        symbol_resolution: None,
        rule_id,
        related_evidence: vec![],
    });
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    callee: String,
    arguments: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

fn call_site<'tree>(node: Node<'tree, StrDoc<SupportLang>>) -> Option<CallSite<'tree>> {
    if node.kind().as_ref() != "call_expression" {
        return None;
    }
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let callee = node.text().get(..callee_length)?.trim().to_string();
    Some(CallSite {
        node,
        callee,
        arguments: arguments
            .children()
            .filter(|child| child.is_named())
            .collect(),
    })
}

fn is_hardcoded_signing_key(
    root: &Node<'_, StrDoc<SupportLang>>,
    key: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let key_text = key.text();
    if looks_like_key_literal(key_text.as_ref()) || looks_like_secret_literal(key_text.as_ref(), "")
    {
        return true;
    }
    let Some(name) = simple_identifier(key_text.trim()) else {
        return false;
    };
    root.dfs().any(|node| {
        node.kind().as_ref() == "variable_declarator"
            && node
                .field("name")
                .is_some_and(|declared| declared.text().trim() == name)
            && node.field("value").is_some_and(|value| {
                looks_like_key_literal(value.text().as_ref())
                    || looks_like_secret_literal(value.text().as_ref(), name)
            })
    })
}

fn looks_like_key_literal(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    lower.contains("begin rsa private key") || lower.contains("begin private key")
}

fn looks_like_secret_literal(text: &str, name: &str) -> bool {
    let text = text.trim();
    if text.len() < 2 {
        return false;
    }
    let quoted = ((text.starts_with('\'') && text.ends_with('\''))
        || (text.starts_with('"') && text.ends_with('"'))
        || (text.starts_with('`') && text.ends_with('`')))
    .then(|| &text[1..text.len() - 1]);
    let Some(value) = quoted else { return false };
    let sensitive_name = name.is_empty()
        || ["secret", "key", "token", "signing"]
            .iter()
            .any(|marker| name.to_ascii_lowercase().contains(marker));
    sensitive_name && value.len() >= 12 && !value.contains("${")
}

fn function_ancestor<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.ancestors().find(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        )
    })
}

fn evidence_context<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> EvidenceContext {
    EvidenceContext {
        comment: comments.is_in_comment(node.range()),
        reachability: Some(reachability::classify(node, literals)),
        availability: Some(conditional.availability_for(node.range())),
        ..EvidenceContext::default()
    }
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}
fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.into(),
        start: Position {
            line: start.line() + 1,
            column: start.column(node) + 1,
            byte_offset: node.range().start,
        },
        end: Position {
            line: end.line() + 1,
            column: end.column(node) + 1,
            byte_offset: node.range().end,
        },
    }
}
fn provenance() -> Provenance {
    Provenance {
        resolution: Resolution::Ast,
        engine: ENGINE.into(),
        rule_version: 1,
    }
}
fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
fn language_rule(language: Language, suffix: &str) -> String {
    format!(
        "{}-{suffix}",
        match language {
            Language::Javascript => "javascript",
            Language::Typescript => "typescript",
            Language::Tsx => "tsx",
            _ => unreachable!(),
        }
    )
}
fn terminal_symbol(symbol: &str) -> &str {
    symbol.rsplit('.').next().unwrap_or(symbol)
}
fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}
fn simple_identifier(text: &str) -> Option<&str> {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        .then_some(())?;
    chars
        .all(|c| c == '_' || c.is_ascii_alphanumeric())
        .then_some(text)
}
fn is_node_language(language: Language) -> bool {
    matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    )
}
fn is_non_runtime_example_path(path: &str) -> bool {
    let p = path.replace('\\', "/").to_ascii_lowercase();
    p.contains("/test/")
        || p.starts_with("test/")
        || p.contains("/tests/")
        || p.starts_with("tests/")
        || p.contains("/data/static/codefixes/")
        || p.starts_with("data/static/codefixes/")
}
