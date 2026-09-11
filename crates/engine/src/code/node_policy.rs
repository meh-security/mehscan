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

const ENGINE: &str = "ast-grep 0.45.1 + bounded-node-policy";

type SensitiveAssignment<'tree> = (String, Node<'tree, StrDoc<SupportLang>>, bool);

pub(crate) fn add_node_policy_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(
        language,
        Language::Javascript | Language::Typescript | Language::Tsx
    ) || is_ui_code_example(path)
    {
        return;
    }
    add_plaintext_totp_storage(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_unbounded_coupon_tool(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_route_policy_reviews(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_request_log_relations(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_credential_response_policy(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_sensitive_record_persistence(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_http_listener_policy(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_administrative_route_reviews(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
    add_sensitive_response_reviews(
        path,
        root,
        language,
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn add_administrative_route_reviews<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for route in root.dfs().filter_map(call_site) {
        let operation = route.callee.rsplit('.').next().unwrap_or_default();
        if !matches!(operation, "delete" | "post" | "put" | "patch")
            || route.arguments.len() < 2
            || comments.is_in_comment(route.node.range())
        {
            continue;
        }
        let route_path_text = route.arguments[0].text();
        let Some(route_path) = exact_quoted(route_path_text.trim()) else {
            continue;
        };
        let route_path_lower = route_path.to_ascii_lowercase();
        if !["/admin", "/manage", "/privilege"]
            .iter()
            .any(|marker| route_path_lower.contains(marker))
        {
            continue;
        }
        let Some(handler) = route.arguments.last() else {
            continue;
        };
        if !matches!(
            handler.kind().as_ref(),
            "function" | "function_expression" | "arrow_function"
        ) || ![".splice(", ".delete(", ".destroy(", ".remove("]
            .iter()
            .any(|mutation| handler.text().contains(mutation))
        {
            continue;
        }
        let has_route_guard = route.arguments[1..route.arguments.len() - 1]
            .iter()
            .any(|guard| {
                let guard = compact(guard.text().as_ref()).to_ascii_lowercase();
                ["auth", "admin", "role", "permission", "authorize", "deny"]
                    .iter()
                    .any(|marker| guard.contains(marker))
            });
        if has_route_guard {
            continue;
        }
        push_policy_evidence(
            path,
            language,
            "administrative-route-authorization-review",
            &route.node,
            EvidenceKind::SensitiveOperation,
            Capability::Authorization,
            vec!["CWE-862".to_string()],
            vec![
                "authorization".to_string(),
                "administrative-route".to_string(),
                "mutating-operation".to_string(),
                "no-route-local-guard".to_string(),
                "verify-parent-router-or-gateway-policy".to_string(),
                "recommendation:review-then-fix-application".to_string(),
            ],
            Confidence::Medium,
            BTreeMap::from([
                ("route".to_string(), capture(path, &route.arguments[0])),
                ("operation".to_string(), capture(path, handler)),
            ]),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_sensitive_response_reviews<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for response in root.dfs().filter_map(call_site) {
        let method = response.callee.rsplit('.').next().unwrap_or_default();
        if !matches!(method, "json" | "send")
            || response.arguments.is_empty()
            || comments.is_in_comment(response.node.range())
        {
            continue;
        }
        let payload = &response.arguments[0];
        let compact_payload = compact(payload.text().as_ref()).to_ascii_lowercase();
        if compact_payload.contains("process.env") {
            push_policy_evidence(
                path,
                language,
                "environment-response-disclosure",
                &response.node,
                EvidenceKind::SensitiveOperation,
                Capability::HttpRequestHandling,
                vec!["CWE-200".to_string()],
                vec![
                    "sensitive-response".to_string(),
                    "process-environment".to_string(),
                    "recommendation:fix-application".to_string(),
                ],
                Confidence::High,
                BTreeMap::from([("response".to_string(), capture(path, payload))]),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
        if compact_payload.contains(".stack") {
            push_policy_evidence(
                path,
                language,
                "stack-trace-response-disclosure",
                &response.node,
                EvidenceKind::SensitiveOperation,
                Capability::HttpRequestHandling,
                vec!["CWE-209".to_string()],
                vec![
                    "sensitive-response".to_string(),
                    "stack-trace".to_string(),
                    "recommendation:fix-application".to_string(),
                ],
                Confidence::High,
                BTreeMap::from([("response".to_string(), capture(path, payload))]),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn add_request_log_relations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(call.node.range()) || !is_log_call(&call.callee) {
            continue;
        }
        let Some((message, _origin)) = call.arguments.iter().find_map(|argument| {
            if exact_quoted(argument.text().trim()).is_some() {
                return None;
            }
            request_derived_log_argument(argument, root).map(|source| (argument, source))
        }) else {
            continue;
        };
        let normalized = compact(message.text().as_ref()).to_ascii_lowercase();
        if normalized.contains("encodefor")
            || normalized.contains("sanitize")
            || (normalized.contains(".replace(")
                && (normalized.contains("\\r") || normalized.contains("\\n")))
        {
            continue;
        }

        let source_rule = language_rule(language, "request-log-source");
        let source_id = evidence_id(
            path,
            source_rule,
            message.range().start,
            message.range().end,
        );
        if !evidence.iter().any(|item| item.id == source_id) {
            evidence.push(Evidence {
                id: source_id.clone(),
                kind: EvidenceKind::Source,
                capability: Capability::HttpRequestData,
                location: location(path, message),
                enclosing_symbol: enclosing_symbol(&call.node),
                captures: BTreeMap::from([("value".to_string(), capture(path, message))]),
                cwe_candidates: Vec::new(),
                tags: vec!["request-data".to_string(), "log-argument".to_string()],
                confidence: Confidence::High,
                provenance: provenance(),
                context: evidence_context(message, comments, conditional, literals),
                symbol_resolution: None,
                rule_id: source_rule.to_string(),
                related_evidence: Vec::new(),
            });
        }
        let sink_rule = language_rule(language, "unencoded-log-message");
        evidence.push(Evidence {
            id: evidence_id(
                path,
                sink_rule,
                call.node.range().start,
                call.node.range().end,
            ),
            kind: EvidenceKind::Sink,
            capability: Capability::Logging,
            location: location(path, &call.node),
            enclosing_symbol: enclosing_symbol(&call.node),
            captures: BTreeMap::from([("message".to_string(), capture(path, message))]),
            cwe_candidates: vec!["CWE-117".to_string()],
            tags: vec![
                "logging".to_string(),
                "request-derived".to_string(),
                "line-break-encoding-not-observed".to_string(),
            ],
            confidence: Confidence::High,
            provenance: provenance(),
            context: evidence_context(&call.node, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: sink_rule.to_string(),
            related_evidence: vec![source_id],
        });
    }
}

fn is_log_call(callee: &str) -> bool {
    let compact = compact(callee).to_ascii_lowercase();
    [".log", ".info", ".warn", ".error"].iter().any(|suffix| {
        compact.ends_with(suffix)
            && (compact.starts_with("console.")
                || compact.starts_with("logger.")
                || compact.starts_with("log."))
    })
}

fn request_derived_log_argument<'tree>(
    argument: &Node<'tree, StrDoc<SupportLang>>,
    root: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let text = compact(argument.text().as_ref());
    if ["req.", "request.", "ctx.request.", "event."]
        .iter()
        .any(|prefix| text.starts_with(prefix))
    {
        return Some(argument.clone());
    }
    let binding = simple_identifier(text.as_str())?;
    let declared_from_request = argument
        .ancestors()
        .filter(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "function_declaration"
                    | "function_expression"
                    | "arrow_function"
                    | "method_definition"
            )
        })
        .find_map(|function| {
            function.dfs().find_map(|node| {
                if node.kind().as_ref() != "variable_declarator"
                    || node.range().start >= argument.range().start
                {
                    return None;
                }
                let (Some(name), Some(value)) = (node.field("name"), node.field("value")) else {
                    return None;
                };
                let origin = compact(value.text().as_ref()).to_ascii_lowercase();
                let request_origin = [
                    "req.body",
                    "req.query",
                    "req.params",
                    "req.headers",
                    "request.body",
                    "request.query",
                    "request.params",
                    "request.headers",
                    "ctx.request.body",
                    "event.body",
                    "event.querystringparameters",
                    "event.pathparameters",
                ]
                .iter()
                .any(|candidate| {
                    origin == *candidate || origin.starts_with(&format!("{candidate}."))
                });
                request_origin
                    .then(|| {
                        name.dfs().find(|part| {
                            part.kind().as_ref().contains("identifier")
                                && part.text().trim() == binding
                        })
                    })
                    .flatten()
            })
        });
    declared_from_request.or_else(|| {
        root.dfs().find_map(|node| {
            (node.kind().as_ref() == "variable_declarator"
                && node.range().start < argument.range().start
                && node
                    .field("name")
                    .is_some_and(|name| name.text().trim() == binding)
                && node.field("value").is_some_and(|value| {
                    let value = compact(value.text().as_ref()).to_ascii_lowercase();
                    value.starts_with("req.") || value.starts_with("request.")
                }))
            .then(|| node.field("name"))
            .flatten()
        })
    })
}

#[allow(clippy::too_many_arguments)]
fn add_credential_response_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for function in root.dfs().filter(|node| {
        matches!(
            node.kind().as_ref(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        )
    }) {
        let function_text = compact(function.text().as_ref()).to_ascii_lowercase();
        if !(function_text.contains("nosuchuser") && function_text.contains("invalidpassword")) {
            continue;
        }
        let mut responses = Vec::new();
        for property in function.dfs().filter(|node| {
            node.field("key").is_some_and(|key| {
                matches!(
                    normalize_name(key.text().as_ref()).as_str(),
                    "loginerror" | "autherror" | "authenticationerror"
                )
            })
        }) {
            if comments.is_in_comment(property.range())
                || nearest_function(&property).as_ref().map(Node::range) != Some(function.range())
            {
                continue;
            }
            let Some(value) = property.field("value") else {
                continue;
            };
            let Some(message) = resolve_exact_string(&function, &value, property.range().start)
            else {
                continue;
            };
            responses.push((property, value, message));
        }
        if responses.len() < 2 {
            continue;
        }
        let distinct = responses
            .iter()
            .map(|(_, _, message)| message.as_str())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            > 1;
        let (kind, suffix, tags) = if distinct {
            (
                EvidenceKind::SecurityConfiguration,
                "credential-response-enumeration-risk",
                vec![
                    "authentication".to_string(),
                    "distinct-credential-errors".to_string(),
                    "recommendation:fix-application".to_string(),
                ],
            )
        } else {
            (
                EvidenceKind::Guard,
                "uniform-credential-response-control",
                vec![
                    "authentication".to_string(),
                    "uniform-credential-error".to_string(),
                    "control".to_string(),
                ],
            )
        };
        let anchor = &responses[0].0;
        let captures = responses
            .iter()
            .take(3)
            .enumerate()
            .map(|(index, (_, value, message))| {
                let mut response = capture(path, value);
                response.text = message.clone();
                (format!("response_{}", index + 1), response)
            })
            .collect();
        push_policy_evidence(
            path,
            language,
            suffix,
            anchor,
            kind,
            Capability::Authentication,
            vec!["CWE-203".to_string()],
            tags,
            Confidence::High,
            captures,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn resolve_exact_string(
    function: &Node<'_, StrDoc<SupportLang>>,
    value: &Node<'_, StrDoc<SupportLang>>,
    before: usize,
) -> Option<String> {
    if let Some(value) = exact_quoted(value.text().trim()) {
        return Some(value.to_string());
    }
    let text = value.text();
    let binding = simple_identifier(text.trim())?;
    function
        .dfs()
        .filter(|node| node.kind().as_ref() == "variable_declarator" && node.range().start < before)
        .filter(|node| {
            node.field("name")
                .is_some_and(|name| name.text().trim() == binding)
        })
        .filter_map(|node| node.field("value"))
        .filter_map(|node| exact_quoted(node.text().trim()).map(str::to_string))
        .last()
}

#[allow(clippy::too_many_arguments)]
fn add_sensitive_record_persistence<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for persistence in root.dfs().filter_map(call_site).filter(|call| {
        matches!(
            call.callee.rsplit('.').next(),
            Some("update" | "updateOne" | "insertOne" | "replaceOne" | "create" | "save")
        ) && !comments.is_in_comment(call.node.range())
    }) {
        let Some(function) = nearest_function(&persistence.node) else {
            continue;
        };
        let persistence_text = compact(persistence.node.text().as_ref());
        let mut groups: BTreeMap<String, Vec<SensitiveAssignment<'_>>> = BTreeMap::new();
        for assignment in function.dfs().filter(|node| {
            node.kind().as_ref() == "assignment_expression"
                && node.range().start < persistence.node.range().start
        }) {
            if comments.is_in_comment(assignment.range()) {
                continue;
            }
            let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
            else {
                continue;
            };
            let left_text = compact(left.text().as_ref());
            let Some((base, field)) = left_text.rsplit_once('.') else {
                continue;
            };
            let field = normalize_name(field);
            if !is_sensitive_record_field(&field)
                || simple_identifier(base).is_none()
                || !persistence_text.contains(base)
            {
                continue;
            }
            groups.entry(base.to_string()).or_default().push((
                field,
                assignment,
                is_confidentiality_transform(&right),
            ));
        }
        for (record, assignments) in groups {
            let fields = assignments
                .iter()
                .map(|(field, _, _)| field.as_str())
                .collect::<std::collections::BTreeSet<_>>();
            if fields.len() < 2 {
                continue;
            }
            let protected = assignments.iter().all(|(_, _, protected)| *protected);
            let (kind, suffix, cwes, tags, confidence) = if protected {
                (
                    EvidenceKind::Guard,
                    "sensitive-record-protection-control",
                    Vec::new(),
                    vec![
                        "sensitive-data".to_string(),
                        "persistence".to_string(),
                        "confidentiality-transform".to_string(),
                        "control".to_string(),
                    ],
                    Confidence::High,
                )
            } else {
                (
                    EvidenceKind::SecurityConfiguration,
                    "sensitive-record-persistence-risk",
                    vec!["CWE-312".to_string()],
                    vec![
                        "sensitive-data".to_string(),
                        "persistence".to_string(),
                        "plaintext-fields-observed".to_string(),
                        "recommendation:fix-application".to_string(),
                    ],
                    Confidence::High,
                )
            };
            let anchor = assignments
                .iter()
                .find(|(_, _, protected)| !protected)
                .unwrap_or(&assignments[0]);
            let mut field_capture = capture(path, &anchor.1);
            field_capture.text = fields.into_iter().collect::<Vec<_>>().join(", ");
            let mut record_capture = capture(path, &anchor.1);
            record_capture.text = record;
            push_policy_evidence(
                path,
                language,
                suffix,
                &anchor.1,
                kind,
                Capability::ResourceAccess,
                cwes,
                tags,
                confidence,
                BTreeMap::from([
                    ("fields".to_string(), field_capture),
                    ("persistence".to_string(), capture(path, &persistence.node)),
                    ("record".to_string(), record_capture),
                ]),
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn is_sensitive_record_field(field: &str) -> bool {
    matches!(
        field,
        "ssn"
            | "socialsecuritynumber"
            | "dob"
            | "dateofbirth"
            | "bankaccount"
            | "bankacc"
            | "bankrouting"
            | "routingnumber"
            | "creditcard"
            | "cardnumber"
            | "taxid"
    )
}

fn is_confidentiality_transform(value: &Node<'_, StrDoc<SupportLang>>) -> bool {
    value.dfs().filter_map(call_site).any(|call| {
        matches!(
            normalize_name(call.callee.rsplit('.').next().unwrap_or_default()).as_str(),
            "encrypt" | "encryptsync" | "protect" | "seal" | "tokenize" | "tokenise"
        )
    })
}

#[allow(clippy::too_many_arguments)]
fn add_http_listener_policy<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for listener in root.dfs().filter_map(call_site).filter(|call| {
        call.callee.ends_with(".listen") && !comments.is_in_comment(call.node.range())
    }) {
        let callee = compact(&listener.callee).to_ascii_lowercase();
        let (kind, suffix, cwes, tags, confidence) = if callee.contains("https.createserver(") {
            (
                EvidenceKind::Guard,
                "https-listener-control",
                Vec::new(),
                vec![
                    "transport".to_string(),
                    "tls-listener".to_string(),
                    "control".to_string(),
                ],
                Confidence::High,
            )
        } else if callee.contains("http.createserver(") {
            (
                EvidenceKind::SecurityConfiguration,
                "http-listener-deployment-review",
                vec!["CWE-319".to_string()],
                vec![
                    "transport".to_string(),
                    "plaintext-listener".to_string(),
                    "deployment-sensitive".to_string(),
                    "proxy-or-gateway-may-own-tls".to_string(),
                    "recommendation:review-deployment".to_string(),
                ],
                Confidence::Medium,
            )
        } else {
            continue;
        };
        push_policy_evidence(
            path,
            language,
            suffix,
            &listener.node,
            kind,
            Capability::HttpRequestHandling,
            cwes,
            tags,
            confidence,
            BTreeMap::from([("listener".to_string(), capture(path, &listener.node))]),
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn push_policy_evidence<'tree>(
    path: &str,
    language: Language,
    suffix: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    capability: Capability,
    cwe_candidates: Vec<String>,
    tags: Vec<String>,
    confidence: Confidence,
    captures: BTreeMap<String, Capture>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let rule = language_rule(language, suffix);
    let id = evidence_id(path, rule, node.range().start, node.range().end);
    if evidence.iter().any(|item| item.id == id) {
        return;
    }
    evidence.push(Evidence {
        id,
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates,
        tags,
        confidence,
        provenance: provenance(),
        context: evidence_context(node, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: rule.to_string(),
        related_evidence: Vec::new(),
    });
}

#[allow(clippy::too_many_arguments)]
fn add_plaintext_totp_storage<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
    {
        let (Some(left), Some(value)) = (assignment.field("left"), assignment.field("right"))
        else {
            continue;
        };
        let left_text = compact(left.text().as_ref());
        if !left_text.ends_with(".totpSecret")
            || value.text().trim() != "secret"
            || comments.is_in_comment(assignment.range())
        {
            continue;
        }
        let Some(model) = left_text.strip_suffix(".totpSecret") else {
            continue;
        };
        if simple_identifier(model).is_none() {
            continue;
        }
        let Some(function) = nearest_function(&assignment) else {
            continue;
        };
        let Some(save_call) = function.dfs().find_map(|node| {
            let call = call_site(node)?;
            (call.callee == format!("{model}.save")
                && call.node.range().start > assignment.range().end)
                .then_some(call.node)
        }) else {
            continue;
        };

        let source_rule = language_rule(language, "totp-secret-source");
        let source_id = evidence_id(path, source_rule, value.range().start, value.range().end);
        evidence.push(Evidence {
            id: source_id.clone(),
            kind: EvidenceKind::Source,
            capability: Capability::CredentialMaterial,
            location: location(path, &value),
            enclosing_symbol: enclosing_symbol(&assignment),
            captures: BTreeMap::from([("secret".to_string(), capture(path, &value))]),
            cwe_candidates: vec!["CWE-312".to_string()],
            tags: vec![
                "authentication".to_string(),
                "totp".to_string(),
                "credential-material".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&value, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: source_rule.to_string(),
            related_evidence: Vec::new(),
        });

        let sink_rule = language_rule(language, "plaintext-totp-storage");
        evidence.push(Evidence {
            id: evidence_id(
                path,
                sink_rule,
                assignment.range().start,
                assignment.range().end,
            ),
            kind: EvidenceKind::Sink,
            capability: Capability::ResourceAccess,
            location: location(path, &assignment),
            enclosing_symbol: enclosing_symbol(&assignment),
            captures: BTreeMap::from([
                ("stored_value".to_string(), capture(path, &value)),
                ("field".to_string(), capture(path, &left)),
                ("persistence".to_string(), capture(path, &save_call)),
            ]),
            cwe_candidates: vec!["CWE-312".to_string()],
            tags: vec![
                "authentication".to_string(),
                "totp".to_string(),
                "model-field".to_string(),
                "plaintext-storage".to_string(),
                "sequelize-save".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&assignment, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: sink_rule.to_string(),
            related_evidence: vec![source_id],
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn add_unbounded_coupon_tool<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for tool_call in root.dfs().filter_map(call_site).filter(|call| {
        call.callee == "tool"
            && call.arguments.len() == 1
            && !comments.is_in_comment(call.node.range())
    }) {
        let specification = tool_call.arguments[0].clone();
        let compact_specification = compact(specification.text().as_ref());
        if !compact_specification.contains("discount:z.number().describe(")
            || !compact_specification.contains("execute:async({discount})")
            || compact_specification.contains("discount:z.number().max(")
            || compact_specification.contains("discount:z.number().lte(")
        {
            continue;
        }
        let Some((operation, operation_input)) = specification.dfs().find_map(|node| {
            let call = call_site(node)?;
            (call.callee.ends_with(".generateCoupon")
                && call.arguments.len() == 1
                && call.arguments[0].text().trim() == "discount")
                .then(|| (call.node, call.arguments[0].clone()))
        }) else {
            continue;
        };
        let Some(execute) = nearest_function(&operation) else {
            continue;
        };
        if has_rejecting_numeric_bound(&execute, &operation) {
            continue;
        }
        let Some(parameter) = execute.dfs().find(|node| {
            node.kind().as_ref().contains("identifier")
                && node.text().trim() == "discount"
                && node.range().start < operation_input.range().start
        }) else {
            continue;
        };
        let policy = specification.dfs().find(|node| {
            node.kind().as_ref() == "call_expression"
                && compact(node.text().as_ref()).contains(".describe(")
                && node.text().to_ascii_lowercase().contains("maximum")
        });

        let source_rule = language_rule(language, "model-tool-input");
        let source_id = evidence_id(
            path,
            source_rule,
            parameter.range().start,
            parameter.range().end,
        );
        evidence.push(Evidence {
            id: source_id.clone(),
            kind: EvidenceKind::Source,
            capability: Capability::ModelToolInput,
            location: location(path, &parameter),
            enclosing_symbol: enclosing_symbol(&parameter),
            captures: BTreeMap::from([("name".to_string(), capture(path, &parameter))]),
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "ai".to_string(),
                "llm".to_string(),
                "tool-input".to_string(),
                "model-controlled".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&parameter, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: source_rule.to_string(),
            related_evidence: Vec::new(),
        });

        let sink_rule = language_rule(language, "unbounded-coupon-operation");
        let mut captures = BTreeMap::from([
            ("operation".to_string(), capture(path, &operation_input)),
            ("tool_call".to_string(), capture(path, &tool_call.node)),
        ]);
        if let Some(policy) = policy {
            captures.insert("prose_limit".to_string(), capture(path, &policy));
        }
        evidence.push(Evidence {
            id: evidence_id(
                path,
                sink_rule,
                operation.range().start,
                operation.range().end,
            ),
            kind: EvidenceKind::Sink,
            capability: Capability::ResourceAccess,
            location: location(path, &operation),
            enclosing_symbol: enclosing_symbol(&operation),
            captures,
            cwe_candidates: vec!["CWE-20".to_string()],
            tags: vec![
                "ai".to_string(),
                "llm".to_string(),
                "privileged-tool".to_string(),
                "prose-only-limit".to_string(),
                "missing-executable-bound".to_string(),
            ],
            confidence: Confidence::Medium,
            provenance: provenance(),
            context: evidence_context(&operation, comments, conditional, literals),
            symbol_resolution: None,
            rule_id: sink_rule.to_string(),
            related_evidence: vec![source_id],
        });
    }
}

fn has_rejecting_numeric_bound(
    execute: &Node<'_, StrDoc<SupportLang>>,
    operation: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    execute.dfs().any(|node| {
        if node.kind().as_ref() != "if_statement" || node.range().start >= operation.range().start {
            return false;
        }
        let Some(condition) = node.field("condition") else {
            return false;
        };
        let condition = compact(condition.text().as_ref());
        let bounded = condition.contains("discount>")
            || condition.contains("discount>=")
            || condition.contains("discount<")
            || condition.contains("discount<=");
        bounded
            && node.field("consequence").is_some_and(|consequence| {
                consequence.dfs().any(|descendant| {
                    matches!(
                        descendant.kind().as_ref(),
                        "throw_statement" | "return_statement"
                    )
                })
            })
    })
}

#[allow(clippy::too_many_arguments)]
fn add_route_policy_reviews<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for call in root.dfs().filter_map(call_site) {
        if comments.is_in_comment(call.node.range()) {
            continue;
        }
        if matches!(call.callee.as_str(), "app.use" | "app.get")
            && call.arguments.len() >= 2
            && !has_server_guard(&call)
        {
            let route_text = call.arguments[0].text();
            let Some(route) = exact_quoted(route_text.trim()) else {
                continue;
            };
            let is_index =
                call.callee == "app.use"
                    && call.arguments.iter().skip(1).any(|argument| {
                        compact(argument.text().as_ref()).starts_with("serveIndex(")
                    });
            let is_metrics = call.callee == "app.get" && route == "/metrics";
            if is_index || is_metrics {
                let rule = language_rule(
                    language,
                    if is_index {
                        "public-directory-index"
                    } else {
                        "public-metrics-route"
                    },
                );
                evidence.push(Evidence {
                    id: evidence_id(path, rule, call.node.range().start, call.node.range().end),
                    kind: EvidenceKind::SecurityConfiguration,
                    capability: Capability::HttpRequestHandling,
                    location: location(path, &call.node),
                    enclosing_symbol: enclosing_symbol(&call.node),
                    captures: BTreeMap::from([
                        ("route".to_string(), capture(path, &call.arguments[0])),
                        ("registration".to_string(), capture(path, &call.node)),
                    ]),
                    cwe_candidates: vec![if is_index { "CWE-548" } else { "CWE-200" }.to_string()],
                    tags: vec![
                        "route-policy".to_string(),
                        "public-exposure".to_string(),
                        "needs-verification".to_string(),
                        if is_index {
                            "directory-index"
                        } else {
                            "metrics"
                        }
                        .to_string(),
                    ],
                    confidence: Confidence::Medium,
                    provenance: provenance(),
                    context: evidence_context(&call.node, comments, conditional, literals),
                    symbol_resolution: None,
                    rule_id: rule.to_string(),
                    related_evidence: Vec::new(),
                });
            }
        }
        if call.callee == "finale.resource" && call.arguments.len() == 1 {
            let rule = language_rule(language, "generated-crud-review");
            evidence.push(Evidence {
                id: evidence_id(path, rule, call.node.range().start, call.node.range().end),
                kind: EvidenceKind::SecurityConfiguration,
                capability: Capability::Authorization,
                location: location(path, &call.node),
                enclosing_symbol: enclosing_symbol(&call.node),
                captures: BTreeMap::from([(
                    "resource_configuration".to_string(),
                    capture(path, &call.arguments[0]),
                )]),
                cwe_candidates: vec!["CWE-862".to_string()],
                tags: vec![
                    "route-policy".to_string(),
                    "generated-crud".to_string(),
                    "needs-verification".to_string(),
                ],
                confidence: Confidence::Medium,
                provenance: provenance(),
                context: evidence_context(&call.node, comments, conditional, literals),
                symbol_resolution: None,
                rule_id: rule.to_string(),
                related_evidence: Vec::new(),
            });
        }
    }
}

fn has_server_guard(call: &CallSite<'_>) -> bool {
    call.arguments.iter().skip(1).any(|argument| {
        let text = compact(argument.text().as_ref());
        text.contains("security.isAuthorized(")
            || text.contains("security.isAdmin(")
            || text.contains("security.isAccounting(")
    })
}

struct CallSite<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    callee: String,
    arguments: Vec<Node<'tree, StrDoc<SupportLang>>>,
}

fn call_site(node: Node<'_, StrDoc<SupportLang>>) -> Option<CallSite<'_>> {
    if !matches!(
        node.kind().as_ref(),
        "call_expression" | "invocation_expression"
    ) {
        return None;
    }
    let arguments = node.field("arguments")?;
    let callee_length = arguments.range().start.checked_sub(node.range().start)?;
    let text = node.text();
    Some(CallSite {
        node,
        callee: text.get(..callee_length)?.trim().to_string(),
        arguments: arguments
            .children()
            .filter(|child| child.is_named())
            .collect(),
    })
}

fn nearest_function<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.ancestors().find(|ancestor| {
        matches!(
            ancestor.kind().as_ref(),
            "function_declaration" | "function_expression" | "arrow_function" | "method_definition"
        )
    })
}

fn language_rule(language: Language, suffix: &str) -> &'static str {
    match (language, suffix) {
        (Language::Javascript, "totp-secret-source") => "javascript-totp-secret-source",
        (Language::Typescript, "totp-secret-source") => "typescript-totp-secret-source",
        (Language::Tsx, "totp-secret-source") => "tsx-totp-secret-source",
        (Language::Javascript, "plaintext-totp-storage") => "javascript-plaintext-totp-storage",
        (Language::Typescript, "plaintext-totp-storage") => "typescript-plaintext-totp-storage",
        (Language::Tsx, "plaintext-totp-storage") => "tsx-plaintext-totp-storage",
        (Language::Javascript, "model-tool-input") => "javascript-model-tool-input",
        (Language::Typescript, "model-tool-input") => "typescript-model-tool-input",
        (Language::Tsx, "model-tool-input") => "tsx-model-tool-input",
        (Language::Javascript, "unbounded-coupon-operation") => {
            "javascript-unbounded-coupon-operation"
        }
        (Language::Typescript, "unbounded-coupon-operation") => {
            "typescript-unbounded-coupon-operation"
        }
        (Language::Tsx, "unbounded-coupon-operation") => "tsx-unbounded-coupon-operation",
        (Language::Javascript, "public-directory-index") => {
            "javascript-public-directory-index-review"
        }
        (Language::Typescript, "public-directory-index") => {
            "typescript-public-directory-index-review"
        }
        (Language::Tsx, "public-directory-index") => "tsx-public-directory-index-review",
        (Language::Javascript, "public-metrics-route") => "javascript-public-metrics-route-review",
        (Language::Typescript, "public-metrics-route") => "typescript-public-metrics-route-review",
        (Language::Tsx, "public-metrics-route") => "tsx-public-metrics-route-review",
        (Language::Javascript, "generated-crud-review") => "javascript-generated-crud-review",
        (Language::Typescript, "generated-crud-review") => "typescript-generated-crud-review",
        (Language::Tsx, "generated-crud-review") => "tsx-generated-crud-review",
        (Language::Javascript, "request-log-source") => "javascript-request-log-source",
        (Language::Typescript, "request-log-source") => "typescript-request-log-source",
        (Language::Tsx, "request-log-source") => "tsx-request-log-source",
        (Language::Javascript, "unencoded-log-message") => "javascript-unencoded-log-message",
        (Language::Typescript, "unencoded-log-message") => "typescript-unencoded-log-message",
        (Language::Tsx, "unencoded-log-message") => "tsx-unencoded-log-message",
        (Language::Javascript, "credential-response-enumeration-risk") => {
            "javascript-credential-response-enumeration-risk"
        }
        (Language::Typescript, "credential-response-enumeration-risk") => {
            "typescript-credential-response-enumeration-risk"
        }
        (Language::Tsx, "credential-response-enumeration-risk") => {
            "tsx-credential-response-enumeration-risk"
        }
        (Language::Javascript, "uniform-credential-response-control") => {
            "javascript-uniform-credential-response-control"
        }
        (Language::Typescript, "uniform-credential-response-control") => {
            "typescript-uniform-credential-response-control"
        }
        (Language::Tsx, "uniform-credential-response-control") => {
            "tsx-uniform-credential-response-control"
        }
        (Language::Javascript, "sensitive-record-persistence-risk") => {
            "javascript-sensitive-record-persistence-risk"
        }
        (Language::Typescript, "sensitive-record-persistence-risk") => {
            "typescript-sensitive-record-persistence-risk"
        }
        (Language::Tsx, "sensitive-record-persistence-risk") => {
            "tsx-sensitive-record-persistence-risk"
        }
        (Language::Javascript, "sensitive-record-protection-control") => {
            "javascript-sensitive-record-protection-control"
        }
        (Language::Typescript, "sensitive-record-protection-control") => {
            "typescript-sensitive-record-protection-control"
        }
        (Language::Tsx, "sensitive-record-protection-control") => {
            "tsx-sensitive-record-protection-control"
        }
        (Language::Javascript, "http-listener-deployment-review") => {
            "javascript-http-listener-deployment-review"
        }
        (Language::Typescript, "http-listener-deployment-review") => {
            "typescript-http-listener-deployment-review"
        }
        (Language::Tsx, "http-listener-deployment-review") => "tsx-http-listener-deployment-review",
        (Language::Javascript, "https-listener-control") => "javascript-https-listener-control",
        (Language::Typescript, "https-listener-control") => "typescript-https-listener-control",
        (Language::Tsx, "https-listener-control") => "tsx-https-listener-control",
        (Language::Javascript, "administrative-route-authorization-review") => {
            "javascript-administrative-route-authorization-review"
        }
        (Language::Typescript, "administrative-route-authorization-review") => {
            "typescript-administrative-route-authorization-review"
        }
        (Language::Tsx, "administrative-route-authorization-review") => {
            "tsx-administrative-route-authorization-review"
        }
        (Language::Javascript, "environment-response-disclosure") => {
            "javascript-environment-response-disclosure"
        }
        (Language::Typescript, "environment-response-disclosure") => {
            "typescript-environment-response-disclosure"
        }
        (Language::Tsx, "environment-response-disclosure") => "tsx-environment-response-disclosure",
        (Language::Javascript, "stack-trace-response-disclosure") => {
            "javascript-stack-trace-response-disclosure"
        }
        (Language::Typescript, "stack-trace-response-disclosure") => {
            "typescript-stack-trace-response-disclosure"
        }
        (Language::Tsx, "stack-trace-response-disclosure") => "tsx-stack-trace-response-disclosure",
        _ => unreachable!(),
    }
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

fn provenance() -> Provenance {
    Provenance {
        resolution: Resolution::Ast,
        engine: ENGINE.to_string(),
        rule_version: 1,
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
        path: path.to_string(),
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

fn evidence_id(path: &str, rule_id: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn normalize_name(text: &str) -> String {
    text.trim_matches(['\'', '"', '`'])
        .chars()
        .filter(|character| *character != '_')
        .flat_map(char::to_lowercase)
        .collect()
}

fn simple_identifier(text: &str) -> Option<&str> {
    let mut characters = text.chars();
    let first = characters.next()?;
    ((first == '_' || first.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric()))
    .then_some(text)
}

fn exact_quoted(text: &str) -> Option<&str> {
    let bytes = text.as_bytes();
    let quote = *bytes.first()?;
    (bytes.len() >= 2
        && matches!(quote, b'\'' | b'"')
        && bytes.last().copied() == Some(quote)
        && !text[1..text.len() - 1].contains('\\'))
    .then(|| &text[1..text.len() - 1])
}

fn is_ui_code_example(path: &str) -> bool {
    let path = path.replace('\\', "/").to_ascii_lowercase();
    path.contains("/data/static/codefixes/") || path.starts_with("data/static/codefixes/")
}
