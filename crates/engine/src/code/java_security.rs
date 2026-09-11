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

const RULE_ID: &str = "java-spring-security-route-policy";
const ENGINE: &str = "mehscan java-spring-security-policy 1";

pub(crate) fn add_spring_security_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Java || !imports_http_security(root) {
        return;
    }
    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
    {
        let Some(name) = invocation.field("name") else {
            continue;
        };
        if !matches!(name.text().as_ref(), "requestMatchers" | "anyRequest")
            || comments.is_in_comment(invocation.range())
            || !inside_http_security_method(&invocation)
        {
            continue;
        }
        let route = if name.text().as_ref() == "anyRequest" {
            "*".to_string()
        } else {
            let Some(argument) = invocation
                .field("arguments")
                .and_then(|arguments| arguments.children().find(|child| child.is_named()))
            else {
                continue;
            };
            let text = argument.text();
            let Some(literal) = string_literal(text.as_ref()) else {
                continue;
            };
            literal.to_string()
        };
        let Some((policy, policy_node)) = chained_policy(&invocation) else {
            continue;
        };
        let policy_location = location(path, &invocation);
        evidence.push(Evidence {
            id: format!(
                "{}:{}:{}:{}",
                path,
                invocation.range().start,
                invocation.range().end,
                RULE_ID
            ),
            kind: EvidenceKind::SecurityConfiguration,
            capability: Capability::Authorization,
            location: policy_location,
            enclosing_symbol: enclosing_symbol(&invocation),
            captures: BTreeMap::from([
                (
                    "route".to_string(),
                    Capture {
                        text: route.clone(),
                        location: location(path, &invocation),
                    },
                ),
                (
                    "policy".to_string(),
                    Capture {
                        text: policy.clone(),
                        location: location(path, &policy_node),
                    },
                ),
            ]),
            cwe_candidates: vec!["CWE-306".to_string(), "CWE-862".to_string()],
            tags: vec![
                "spring-security".to_string(),
                "route-policy".to_string(),
                format!("access:{policy}"),
                format!("route:{route}"),
            ],
            confidence: Confidence::High,
            provenance: Provenance {
                resolution: Resolution::Ast,
                engine: ENGINE.to_string(),
                rule_version: 1,
            },
            context: EvidenceContext {
                comment: false,
                reachability: Some(reachability::classify(&invocation, literals)),
                availability: Some(conditional.availability_for(invocation.range())),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: RULE_ID.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn imports_http_security(root: &Node<'_, StrDoc<SupportLang>>) -> bool {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "import_declaration")
        .any(|import| {
            import.text().trim()
                == "import org.springframework.security.config.annotation.web.builders.HttpSecurity;"
        })
}

fn inside_http_security_method(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "method_declaration")
        .and_then(|method| method.field("parameters"))
        .is_some_and(|parameters| {
            parameters
                .children()
                .filter(|parameter| parameter.kind().as_ref() == "formal_parameter")
                .any(|parameter| {
                    parameter
                        .field("type")
                        .is_some_and(|kind| kind.text().as_ref() == "HttpSecurity")
                })
        })
}

fn chained_policy<'tree>(
    invocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(String, Node<'tree, StrDoc<SupportLang>>)> {
    for ancestor in invocation
        .ancestors()
        .take_while(|node| node.kind().as_ref() != "method_declaration")
        .filter(|node| node.kind().as_ref() == "method_invocation")
    {
        let name = ancestor.field("name")?;
        match name.text().as_ref() {
            "permitAll" => return Some(("permit_all".to_string(), ancestor)),
            "authenticated" => return Some(("authenticated".to_string(), ancestor)),
            "hasRole" | "hasAuthority" => {
                let value = ancestor
                    .field("arguments")
                    .and_then(|arguments| arguments.children().find(|child| child.is_named()))
                    .map(|argument| argument.text().trim().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                return Some((format!("{}:{value}", name.text()), ancestor));
            }
            _ => {}
        }
    }
    None
}

fn string_literal(text: &str) -> Option<&str> {
    let text = text.trim();
    text.strip_prefix('"')?.strip_suffix('"')
}

fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    let range = node.range();
    let start = node.start_pos();
    let end = node.end_pos();
    Location {
        path: path.to_string(),
        start: Position {
            byte_offset: range.start,
            line: start.line() + 1,
            column: start.column(node) + 1,
        },
        end: Position {
            byte_offset: range.end,
            line: end.line() + 1,
            column: end.column(node) + 1,
        },
    }
}
