use std::collections::{BTreeMap, BTreeSet};

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

const ENGINE: &str = "mehscan csharp bounded privilege assignment 1";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_privilege_assignment_observations<'tree>(
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
    add_persisted_role_property_assignments(path, root, comments, conditional, literals, evidence);
    let user_managers = identity_user_manager_names(root);
    if user_managers.is_empty() {
        return;
    }

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "invocation_expression")
    {
        let Some(function) = invocation.field("function") else {
            continue;
        };
        let function_text = compact(function.text().as_ref());
        let Some(receiver) = function_text.strip_suffix(".AddToRoleAsync") else {
            continue;
        };
        let receiver = receiver.trim_start_matches("this.");
        if !user_managers.contains(receiver) || comments.is_in_comment(invocation.range()) {
            continue;
        }
        let Some(method) = invocation
            .ancestors()
            .find(|node| node.kind().as_ref() == "method_declaration")
        else {
            continue;
        };
        let arguments = arguments(&invocation);
        if arguments.len() < 2 {
            continue;
        }
        let role = arguments[1].clone();

        if let Some(control) = server_owned_role_control(&method, &invocation) {
            push_control(
                path,
                &control,
                &invocation,
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        }

        let Some(decision) = enclosing_bound_decision(&method, &invocation, evidence) else {
            push_sensitive_operation(
                path,
                &invocation,
                &role,
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        };
        let Some(source) = bound_source_for(&method, &decision, evidence) else {
            continue;
        };
        let source_id = source.id.clone();
        let client_guard = preceding_client_owned_guard(&method, &invocation, &decision, evidence);
        push_request_controlled_assignment(
            path,
            &invocation,
            &decision,
            &role,
            client_guard.as_ref(),
            &source_id,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn add_persisted_role_property_assignments<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
    {
        if comments.is_in_comment(assignment.range()) {
            continue;
        }
        let (Some(left), Some(right)) = (assignment.field("left"), assignment.field("right"))
        else {
            continue;
        };
        let Some((target, property)) = member_parts(&left) else {
            continue;
        };
        if !is_privilege_property(&property) {
            continue;
        }
        let Some(method) = assignment
            .ancestors()
            .find(|node| node.kind().as_ref() == "method_declaration")
        else {
            continue;
        };
        let Some(source) = bound_source_for(&method, &right, evidence) else {
            continue;
        };
        let source_id = source.id.clone();
        if !target_is_persisted_after(&method, &assignment, &target) {
            continue;
        }
        if let Some(control) = server_owned_role_control(&method, &assignment) {
            push_control(
                path,
                &control,
                &assignment,
                comments,
                conditional,
                literals,
                evidence,
            );
            continue;
        }
        push_request_controlled_property_assignment(
            path,
            &assignment,
            &left,
            &right,
            &source_id,
            comments,
            conditional,
            literals,
            evidence,
        );
    }
}

fn member_parts(node: &Node<'_, StrDoc<SupportLang>>) -> Option<(String, String)> {
    if node.kind().as_ref() != "member_access_expression" {
        return None;
    }
    let target = node.field("expression")?.text().trim().to_string();
    let property = node.field("name")?.text().trim().to_string();
    simple_identifier(&target).map(|target| (target.to_string(), property))
}

fn is_privilege_property(property: &str) -> bool {
    matches!(
        property.to_ascii_lowercase().as_str(),
        "role"
            | "roles"
            | "isadmin"
            | "isadministrator"
            | "permission"
            | "permissions"
            | "privilege"
            | "privileges"
    )
}

fn target_is_persisted_after(
    method: &Node<'_, StrDoc<SupportLang>>,
    assignment: &Node<'_, StrDoc<SupportLang>>,
    target: &str,
) -> bool {
    method
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "invocation_expression"
                && node.range().start > assignment.range().end
        })
        .any(|invocation| {
            let text = compact(invocation.text().as_ref());
            [".Update(", ".UpdateAsync(", ".UpdateRange("]
                .iter()
                .any(|method| text.contains(&format!("{method}{target}")))
        })
}

#[allow(clippy::too_many_arguments)]
fn push_request_controlled_property_assignment<'tree>(
    path: &str,
    assignment: &Node<'tree, StrDoc<SupportLang>>,
    assigned_field: &Node<'tree, StrDoc<SupportLang>>,
    role: &Node<'tree, StrDoc<SupportLang>>,
    source_id: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_evidence(
        path,
        assignment,
        EvidenceKind::Sink,
        "csharp-request-controlled-role-assignment",
        &[
            "identity",
            "role-assignment",
            "request-controlled-value",
            "persisted-privilege-property",
            "needs-verification",
            "verify-server-owned-caller-privilege",
        ],
        BTreeMap::from([
            ("assigned_fields".to_string(), capture(path, assigned_field)),
            ("assignment".to_string(), capture(path, assignment)),
            ("operation".to_string(), capture(path, assignment)),
            ("role".to_string(), capture(path, role)),
        ]),
        vec![source_id.to_string()],
        comments,
        conditional,
        literals,
        evidence,
    );
}

fn identity_user_manager_names(root: &Node<'_, StrDoc<SupportLang>>) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    let file_text = compact(root.text().as_ref());
    if !file_text.contains("usingMicrosoft.AspNetCore.Identity;")
        && !file_text.contains("Microsoft.AspNetCore.Identity.UserManager<")
    {
        return names;
    }
    for declaration in root.dfs().filter(|node| {
        matches!(node.kind().as_ref(), "variable_declaration" | "parameter")
            && compact(node.text().as_ref()).contains("UserManager<")
    }) {
        for declarator in declaration
            .dfs()
            .filter(|node| matches!(node.kind().as_ref(), "variable_declarator" | "parameter"))
        {
            if let Some(name) = declarator.field("name") {
                names.insert(
                    compact(name.text().as_ref())
                        .trim_start_matches("this.")
                        .to_string(),
                );
            }
        }
    }
    names
}

fn server_owned_role_control<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if let Some(attribute) = authorization_attributes(method)
        .into_iter()
        .find(|attribute| {
            let text = compact(attribute.text().as_ref());
            text.starts_with("Authorize(") && text.contains("Roles=")
        })
    {
        return Some(attribute);
    }

    method
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .find_map(|guard| {
            let condition = guard.field("condition")?;
            let text = compact(condition.text().as_ref());
            if !text.contains("User.IsInRole(") {
                return None;
            }
            let wraps_operation = guard
                .field("consequence")
                .is_some_and(|branch| contains(branch.range(), invocation.range()));
            let rejecting_guard = guard.range().end < invocation.range().start
                && text.trim_start_matches('(').starts_with('!')
                && guard.field("consequence").is_some_and(|branch| {
                    branch.dfs().any(|node| is_terminator(node.kind().as_ref()))
                });
            (wraps_operation || rejecting_guard).then_some(condition)
        })
}

fn authorization_attributes<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    let mut attributes = method
        .dfs()
        .filter(|node| node.kind().as_ref() == "attribute")
        .collect::<Vec<_>>();
    if let Some(class) = method
        .ancestors()
        .find(|node| node.kind().as_ref() == "class_declaration")
    {
        let body_start = class
            .field("body")
            .map_or(class.range().end, |body| body.range().start);
        attributes.extend(
            class.dfs().filter(|node| {
                node.kind().as_ref() == "attribute" && node.range().end <= body_start
            }),
        );
    }
    attributes
}

fn enclosing_bound_decision<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    evidence: &[Evidence],
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    invocation
        .ancestors()
        .take_while(|ancestor| ancestor.range() != method.range())
        .find_map(|ancestor| {
            (ancestor.kind().as_ref() == "if_statement")
                .then(|| ancestor.field("condition"))
                .flatten()
                .filter(|condition| bound_source_for(method, condition, evidence).is_some())
        })
}

fn bound_source_for<'a>(
    method: &Node<'_, StrDoc<SupportLang>>,
    expression: &Node<'_, StrDoc<SupportLang>>,
    evidence: &'a [Evidence],
) -> Option<&'a Evidence> {
    let symbol = method.field("name").map(|name| name.text().into_owned())?;
    let expression = compact(expression.text().as_ref());
    evidence.iter().find(|item| {
        item.kind == EvidenceKind::Source
            && item.capability == Capability::HttpRequestData
            && item.enclosing_symbol.as_deref() == Some(symbol.as_str())
            && item.captures.get("parameter").is_some_and(|parameter| {
                let parameter = compact(&parameter.text);
                expression == parameter || expression.contains(&format!("{parameter}."))
            })
    })
}

fn preceding_client_owned_guard<'tree>(
    method: &Node<'tree, StrDoc<SupportLang>>,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    decision: &Node<'tree, StrDoc<SupportLang>>,
    evidence: &[Evidence],
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let source = bound_source_for(method, decision, evidence)?;
    let parameter = compact(&source.captures.get("parameter")?.text);
    method
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "if_statement" && node.range().end < invocation.range().start
        })
        .find_map(|guard| {
            let condition = guard.field("condition")?;
            let text = compact(condition.text().as_ref());
            let reads_client_policy = text.contains(&format!("{parameter}."))
                && ["admin", "role", "privilege"]
                    .iter()
                    .any(|word| text.to_ascii_lowercase().contains(word));
            let terminates = guard
                .field("consequence")
                .is_some_and(|branch| branch.dfs().any(|node| is_terminator(node.kind().as_ref())));
            (reads_client_policy && terminates).then_some(condition)
        })
}

#[allow(clippy::too_many_arguments)]
fn push_request_controlled_assignment<'tree>(
    path: &str,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    decision: &Node<'tree, StrDoc<SupportLang>>,
    role: &Node<'tree, StrDoc<SupportLang>>,
    client_guard: Option<&Node<'tree, StrDoc<SupportLang>>>,
    source_id: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let mut captures = BTreeMap::from([
        ("assigned_fields".to_string(), capture(path, decision)),
        ("operation".to_string(), capture(path, invocation)),
        ("role".to_string(), capture(path, role)),
    ]);
    if let Some(client_guard) = client_guard {
        captures.insert(
            "client_authorization_guard".to_string(),
            capture(path, client_guard),
        );
    }
    push_evidence(
        path,
        invocation,
        EvidenceKind::Sink,
        "csharp-request-controlled-role-assignment",
        &[
            "identity",
            "role-assignment",
            "request-controlled-decision",
            "client-controlled-authorization",
            "needs-verification",
            "verify-server-owned-caller-privilege",
        ],
        captures,
        vec![source_id.to_string()],
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_sensitive_operation<'tree>(
    path: &str,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    role: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_evidence(
        path,
        invocation,
        EvidenceKind::SensitiveOperation,
        "csharp-identity-role-assignment-review",
        &[
            "identity",
            "role-assignment",
            "needs-verification",
            "verify-server-owned-caller-privilege",
        ],
        BTreeMap::from([
            ("operation".to_string(), capture(path, invocation)),
            ("role".to_string(), capture(path, role)),
        ]),
        Vec::new(),
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_control<'tree>(
    path: &str,
    control: &Node<'tree, StrDoc<SupportLang>>,
    invocation: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    push_evidence(
        path,
        control,
        EvidenceKind::Guard,
        "csharp-role-assignment-caller-control",
        &[
            "identity",
            "role-assignment",
            "server-owned-caller-authorization",
        ],
        BTreeMap::from([
            ("caller_policy".to_string(), capture(path, control)),
            ("operation".to_string(), capture(path, invocation)),
        ]),
        Vec::new(),
        comments,
        conditional,
        literals,
        evidence,
    );
}

#[allow(clippy::too_many_arguments)]
fn push_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    kind: EvidenceKind,
    rule_id: &str,
    tags: &[&str],
    captures: BTreeMap<String, Capture>,
    related_evidence: Vec<String>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if comments.is_in_comment(node.range()) {
        return;
    }
    evidence.push(Evidence {
        id: evidence_id(rule_id, path, node.range().start, node.range().end),
        kind,
        capability: if rule_id == "csharp-request-controlled-role-assignment" {
            Capability::ResourceAccess
        } else {
            Capability::Authorization
        },
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: vec!["CWE-862".to_string(), "CWE-915".to_string()],
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        confidence: Confidence::Medium,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: false,
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence,
    });
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

fn contains(outer: std::ops::Range<usize>, inner: std::ops::Range<usize>) -> bool {
    outer.start <= inner.start && inner.end <= outer.end
}

fn is_terminator(kind: &str) -> bool {
    matches!(kind, "return_statement" | "throw_statement")
}

fn compact(text: &str) -> String {
    text.chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn simple_identifier(text: &str) -> Option<&str> {
    let mut characters = text.chars();
    let first = characters.next()?;
    ((first == '_' || first.is_alphabetic())
        && characters.all(|character| character == '_' || character.is_alphanumeric()))
    .then_some(text)
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
