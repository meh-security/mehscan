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

const PROCESS_RULE_ID: &str = "java-process-execution";
const OUTBOUND_RULE_ID: &str = "java-outbound-http";
const ENGINE: &str = "mehscan java-exact-framework-sinks 1";

pub(crate) fn add_typed_process_sinks<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Java {
        return;
    }
    add_process_builder_mutations(path, root, comments, conditional, literals, evidence);
    if declares_type(root, "Runtime") {
        return;
    }
    let runtime_variables = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "local_variable_declaration")
        .filter(|declaration| {
            declaration
                .field("type")
                .is_some_and(|kind| matches!(kind.text().as_ref(), "Runtime" | "java.lang.Runtime"))
        })
        .flat_map(|declaration| {
            declaration
                .children()
                .filter(|node| node.kind().as_ref() == "variable_declarator")
                .filter(|variable| {
                    variable.field("value").is_some_and(|value| {
                        matches!(
                            value.text().trim(),
                            "Runtime.getRuntime()" | "java.lang.Runtime.getRuntime()"
                        )
                    })
                })
                .filter_map(|variable| variable.field("name"))
                .map(|name| name.text().into_owned())
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();
    if runtime_variables.is_empty() {
        return;
    }

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
    {
        if comments.is_in_comment(invocation.range())
            || invocation
                .field("name")
                .is_none_or(|name| name.text().as_ref() != "exec")
            || invocation
                .field("object")
                .is_none_or(|object| !runtime_variables.contains(object.text().trim()))
        {
            continue;
        }
        let Some(command) = invocation
            .field("arguments")
            .and_then(|arguments| arguments.children().find(|child| child.is_named()))
        else {
            continue;
        };
        let sink_location = location(path, &invocation);
        if evidence.iter().any(|item| {
            item.rule_id == PROCESS_RULE_ID
                && item.location.start.byte_offset == sink_location.start.byte_offset
                && item.location.path == sink_location.path
        }) {
            continue;
        }
        evidence.push(Evidence {
            id: evidence_id(path, invocation.range().start, invocation.range().end),
            kind: EvidenceKind::Sink,
            capability: Capability::ProcessExecution,
            location: sink_location,
            enclosing_symbol: enclosing_symbol(&invocation),
            captures: BTreeMap::from([(
                "command".to_string(),
                Capture {
                    text: command.text().into_owned(),
                    location: location(path, &command),
                },
            )]),
            cwe_candidates: vec!["CWE-78".to_string()],
            tags: vec![
                "command".to_string(),
                "process".to_string(),
                "java".to_string(),
                "exact-runtime-receiver".to_string(),
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
                literals: BTreeMap::from([("command".to_string(), literals.evaluate(&command))]),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: PROCESS_RULE_ID.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn add_process_builder_mutations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if declares_type(root, "ProcessBuilder") {
        return;
    }
    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
    {
        if comments.is_in_comment(invocation.range())
            || invocation
                .field("name")
                .is_none_or(|name| name.text().as_ref() != "command")
        {
            continue;
        }
        let Some(receiver) = invocation.field("object") else {
            continue;
        };
        if !super::java_persistence::typed_database_receiver(root, &receiver, "ProcessBuilder", 8)
            && !super::java_persistence::typed_database_receiver(
                root,
                &receiver,
                "java.lang.ProcessBuilder",
                8,
            )
        {
            continue;
        }
        let Some(command) = invocation
            .field("arguments")
            .and_then(|arguments| arguments.children().find(|child| child.is_named()))
        else {
            continue;
        };
        let sink_location = location(path, &invocation);
        if evidence.iter().any(|item| {
            item.rule_id == PROCESS_RULE_ID
                && item.location.path == sink_location.path
                && item.location.start.byte_offset == sink_location.start.byte_offset
        }) {
            continue;
        }
        evidence.push(Evidence {
            id: evidence_id(path, invocation.range().start, invocation.range().end),
            kind: EvidenceKind::Sink,
            capability: Capability::ProcessExecution,
            location: sink_location,
            enclosing_symbol: enclosing_symbol(&invocation),
            captures: BTreeMap::from([(
                "command".to_string(),
                Capture {
                    text: command.text().into_owned(),
                    location: location(path, &command),
                },
            )]),
            cwe_candidates: vec!["CWE-78".to_string()],
            tags: vec![
                "command".to_string(),
                "process".to_string(),
                "java".to_string(),
                "process-builder-command-mutation".to_string(),
                "typed-receiver".to_string(),
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
                literals: BTreeMap::from([("command".to_string(), literals.evaluate(&command))]),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: PROCESS_RULE_ID.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

pub(crate) fn add_typed_outbound_sinks<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if language != Language::Java
        || declares_type(root, "URI")
        || !root.dfs().any(|node| {
            node.kind().as_ref() == "import_declaration"
                && node.text().trim() == "import java.net.URI;"
        })
    {
        return;
    }
    let uri_variables = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "local_variable_declaration")
        .filter(|declaration| {
            declaration
                .field("type")
                .is_some_and(|kind| matches!(kind.text().as_ref(), "URI" | "java.net.URI"))
        })
        .flat_map(|declaration| {
            declaration
                .children()
                .filter(|node| node.kind().as_ref() == "variable_declarator")
                .filter_map(|variable| variable.field("name"))
                .map(|name| name.text().into_owned())
                .collect::<Vec<_>>()
        })
        .collect::<BTreeSet<_>>();

    for invocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "method_invocation")
    {
        if comments.is_in_comment(invocation.range())
            || invocation
                .field("name")
                .is_none_or(|name| name.text().as_ref() != "openConnection")
        {
            continue;
        }
        let Some(to_url) = invocation
            .field("object")
            .filter(|object| object.kind().as_ref() == "method_invocation")
            .filter(|object| {
                object
                    .field("name")
                    .is_some_and(|name| name.text().as_ref() == "toURL")
            })
        else {
            continue;
        };
        let Some(endpoint) = to_url
            .field("object")
            .filter(|object| uri_variables.contains(object.text().trim()))
        else {
            continue;
        };
        let sink_location = location(path, &invocation);
        if evidence.iter().any(|item| {
            item.rule_id == OUTBOUND_RULE_ID
                && item.location.start.byte_offset == sink_location.start.byte_offset
                && item.location.path == sink_location.path
        }) {
            continue;
        }
        evidence.push(Evidence {
            id: format!(
                "{}:{}:{}:{}",
                path,
                invocation.range().start,
                invocation.range().end,
                OUTBOUND_RULE_ID
            ),
            kind: EvidenceKind::Sink,
            capability: Capability::OutboundNetworkRequest,
            location: sink_location,
            enclosing_symbol: enclosing_symbol(&invocation),
            captures: BTreeMap::from([(
                "endpoint".to_string(),
                Capture {
                    text: endpoint.text().into_owned(),
                    location: location(path, &endpoint),
                },
            )]),
            cwe_candidates: vec!["CWE-918".to_string()],
            tags: vec![
                "http".to_string(),
                "network".to_string(),
                "ssrf".to_string(),
                "java-uri-url-connection".to_string(),
                "exact-uri-receiver".to_string(),
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
                literals: BTreeMap::from([("endpoint".to_string(), literals.evaluate(&endpoint))]),
                ..EvidenceContext::default()
            },
            symbol_resolution: None,
            rule_id: OUTBOUND_RULE_ID.to_string(),
            related_evidence: Vec::new(),
        });
    }
}

fn declares_type(root: &Node<'_, StrDoc<SupportLang>>, name: &str) -> bool {
    root.dfs()
        .filter(|node| {
            matches!(
                node.kind().as_ref(),
                "class_declaration"
                    | "interface_declaration"
                    | "record_declaration"
                    | "enum_declaration"
            )
        })
        .filter_map(|node| node.field("name"))
        .any(|declared| declared.text().as_ref() == name)
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

fn evidence_id(path: &str, start: usize, end: usize) -> String {
    format!("{path}:{start}:{end}:{PROCESS_RULE_ID}")
}
