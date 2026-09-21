use std::collections::{BTreeMap, BTreeSet};

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, HttpRouteContext,
    Language, Location, Position, Provenance, Resolution,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENGINE: &str = "mehscan csharp bounded business policy 1";

#[derive(Clone)]
struct RegisteredHandler {
    evidence_id: String,
    name: String,
    resource: Capture,
    routes: Vec<HttpRouteContext>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_business_policy_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Csharp {
        return;
    }
    let handlers = registered_handlers(path, evidence);
    if handlers.is_empty() {
        return;
    }
    for method in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_declaration")
    {
        let Some(name) = method.field("name") else {
            continue;
        };
        let Some(handler) = handlers.get(name.text().trim()) else {
            continue;
        };
        let request_parameters = request_parameter_names(&method);
        if request_parameters.is_empty() {
            continue;
        }
        for assignment in method
            .dfs()
            .filter(|node| node.kind().as_ref() == "assignment_expression")
        {
            let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
            else {
                continue;
            };
            let Some((target, field)) = member_parts(&left) else {
                continue;
            };
            if !is_state_field(&field) {
                continue;
            }
            let Some((request_field, next_state)) =
                request_state_member(&right, &request_parameters)
            else {
                continue;
            };
            let Some(persistence) = persistence_after(&method, &assignment, Some(&target)) else {
                continue;
            };
            push_transition_review(
                path,
                &assignment,
                &next_state,
                &request_field,
                &handler.resource,
                Some((&left, &persistence)),
                None,
                handler,
                comments,
                conditional,
                literals,
                evidence,
            );
        }

        for invocation in method
            .dfs()
            .filter(|node| node.kind().as_ref() == "invocation_expression")
        {
            let Some(function) = invocation.field("function") else {
                continue;
            };
            let function_text = compact(function.text().as_ref());
            let Some(helper) = function_text.rsplit('.').next() else {
                continue;
            };
            if !is_transition_helper(helper) {
                continue;
            }
            let Some((request_field, next_state)) = arguments(&invocation)
                .into_iter()
                .find_map(|argument| request_state_member(&argument, &request_parameters))
            else {
                continue;
            };
            let mut helper_capture = capture(path, &invocation);
            helper_capture.text = helper.to_string();
            push_transition_review(
                path,
                &invocation,
                &next_state,
                &request_field,
                &handler.resource,
                None,
                Some(helper_capture),
                handler,
                comments,
                conditional,
                literals,
                evidence,
            );
        }
    }
}

fn registered_handlers(path: &str, evidence: &[Evidence]) -> BTreeMap<String, RegisteredHandler> {
    evidence
        .iter()
        .filter(|item| {
            item.location.path == path
                && item.kind == EvidenceKind::Entrypoint
                && item.rule_id == "csharp-http-entrypoint"
        })
        .filter_map(|item| {
            let handler = item.captures.get("handler")?;
            let route = item.captures.get("route")?.clone();
            Some((
                handler.text.clone(),
                RegisteredHandler {
                    evidence_id: item.id.clone(),
                    name: handler.text.clone(),
                    resource: route,
                    routes: item.context.http_routes.clone(),
                },
            ))
        })
        .collect()
}

fn request_parameter_names(method: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    let Some(parameters) = method.field("parameters") else {
        return BTreeSet::new();
    };
    parameters
        .children()
        .filter(|node| node.kind().as_ref() == "parameter")
        .filter_map(|parameter| {
            let name = parameter.field("name")?.text().trim().to_string();
            let type_name = parameter
                .field("type")
                .map(|node| compact(node.text().as_ref()))
                .unwrap_or_default();
            let lower_name = name.to_ascii_lowercase();
            let lower_type = type_name.to_ascii_lowercase();
            (matches!(
                lower_name.as_str(),
                "request" | "command" | "input" | "model" | "dto"
            ) || ["request", "command", "input", "dto"]
                .iter()
                .any(|suffix| lower_type.trim_end_matches('?').ends_with(suffix)))
            .then_some(name)
        })
        .collect()
}

fn request_state_member<'tree>(
    expression: &Node<'tree, StrDoc<SupportLang>>,
    request_parameters: &BTreeSet<String>,
) -> Option<(Capture, Node<'tree, StrDoc<SupportLang>>)> {
    expression.dfs().find_map(|member| {
        let (target, field) = member_parts(&member)?;
        if !request_parameters.contains(&target) || !is_requested_state_field(&field) {
            return None;
        }
        let field_node = member.field("name")?;
        Some((
            Capture {
                text: field,
                location: location("", &field_node),
            },
            member,
        ))
    })
}

fn is_state_field(field: &str) -> bool {
    matches!(field.to_ascii_lowercase().as_str(), "state" | "status")
}

fn is_requested_state_field(field: &str) -> bool {
    matches!(
        field.to_ascii_lowercase().as_str(),
        "state" | "status" | "targetstate" | "targetstatus" | "nextstate" | "nextstatus"
    )
}

fn is_transition_helper(name: &str) -> bool {
    let name = name.trim_end_matches("Async").to_ascii_lowercase();
    name.contains("transition")
        || name.contains("advance")
        || matches!(
            name.as_str(),
            "changestate"
                | "changestatus"
                | "setstate"
                | "setstatus"
                | "updatestate"
                | "updatestatus"
        )
}

fn persistence_after<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
    operation: &Node<'tree, StrDoc<SupportLang>>,
    target: Option<&str>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    method
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "invocation_expression"
                && node.range().start > operation.range().end
        })
        .find(|invocation| {
            let Some(function) = invocation.field("function") else {
                return false;
            };
            let text = compact(function.text().as_ref());
            let lower = text.to_ascii_lowercase();
            let owned_receiver = ["db", "context", "repository", "repo", "unitofwork"]
                .iter()
                .any(|marker| lower.contains(marker));
            let save = lower.ends_with(".savechanges") || lower.ends_with(".savechangesasync");
            let update = target.is_some_and(|target| {
                [".Update", ".UpdateAsync", ".Save", ".SaveAsync"]
                    .iter()
                    .any(|method| {
                        compact(invocation.text().as_ref()).contains(&format!("{method}({target}"))
                    })
            });
            owned_receiver && (save || update)
        })
}

#[allow(clippy::too_many_arguments)]
fn push_transition_review<'tree>(
    path: &str,
    operation: &Node<'tree, StrDoc<SupportLang>>,
    next_state: &Node<'tree, StrDoc<SupportLang>>,
    request_field: &Capture,
    resource: &Capture,
    assignment: Option<(
        &Node<'tree, StrDoc<SupportLang>>,
        &Node<'tree, StrDoc<SupportLang>>,
    )>,
    helper: Option<Capture>,
    handler: &RegisteredHandler,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let mut request_field = request_field.clone();
    request_field.location.path = path.to_string();
    let mut captures = BTreeMap::from([
        ("transition_effect".to_string(), capture(path, operation)),
        ("next_state".to_string(), capture(path, next_state)),
        ("request_field".to_string(), request_field),
        ("state_resource".to_string(), resource.clone()),
    ]);
    if let Some((field, persistence)) = assignment {
        captures.insert("state_field".to_string(), capture(path, field));
        captures.insert("persistence_effect".to_string(), capture(path, persistence));
    }
    if let Some(helper) = helper {
        captures.insert("transition_helper".to_string(), helper);
    }
    let rule_id = "csharp-client-controlled-state-transition-review";
    evidence.push(Evidence {
        id: evidence_id(
            rule_id,
            path,
            operation.range().start,
            operation.range().end,
        ),
        kind: EvidenceKind::SensitiveOperation,
        capability: Capability::ResourceAccess,
        location: location(path, operation),
        enclosing_symbol: Some(handler.name.clone()),
        captures,
        cwe_candidates: vec!["CWE-841".to_string()],
        tags: vec![
            "aspnet-core".to_string(),
            "business-logic".to_string(),
            "state-transition".to_string(),
            "client-controlled-next-state".to_string(),
            "review-invariant:state-transition-enforcement".to_string(),
            "recommendation:review-then-fix-application".to_string(),
        ],
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(operation.range()),
            reachability: Some(reachability::classify(operation, literals)),
            availability: Some(conditional.availability_for(operation.range())),
            http_routes: handler.routes.clone(),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: vec![handler.evidence_id.clone()],
    });
}

fn member_parts(node: &Node<'_, StrDoc<SupportLang>>) -> Option<(String, String)> {
    if node.kind().as_ref() != "member_access_expression" {
        return None;
    }
    Some((
        node.field("expression")?.text().trim().to_string(),
        node.field("name")?.text().trim().to_string(),
    ))
}

fn arguments<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    node.field("arguments")
        .map(|arguments| {
            arguments
                .children()
                .filter(|child| child.is_named())
                .filter_map(|argument| {
                    (argument.kind().as_ref() == "argument")
                        .then(|| argument.children().find(|child| child.is_named()))
                        .flatten()
                        .or(Some(argument))
                })
                .collect()
        })
        .unwrap_or_default()
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

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn evidence_id(rule_id: &str, path: &str, start: usize, end: usize) -> String {
    let input = format!("{path}\0{rule_id}\0{start}\0{end}");
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("ev-{hash:016x}")
}
