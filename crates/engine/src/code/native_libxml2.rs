use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    AvailabilityState, Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind,
    Language, Location, Position, Provenance, Resolution, SecurityPath, SecurityPathProvenance,
    SecurityPathState, SecurityPathStep, SecurityPathStepKind,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const ENABLE_RULE_ID: &str = "native-libxml2-external-entity-enablement";
const PARSE_RULE_ID: &str = "native-libxml2-xml-parse";
const NO_XXE_RULE_ID: &str = "native-libxml2-no-xxe-control";
const NONET_RULE_ID: &str = "native-libxml2-network-only-control";
const ENGINE: &str = "tree-sitter c-family libxml2 parser-options relationship";
const ENABLE_FLAGS: [&str; 4] = [
    "XML_PARSE_NOENT",
    "XML_PARSE_DTDLOAD",
    "XML_PARSE_DTDATTR",
    "XML_PARSE_DTDVALID",
];

pub(crate) fn add_native_libxml2_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) -> Vec<SecurityPath> {
    if !matches!(language, Language::C | Language::Cpp) {
        return Vec::new();
    }

    let mut additions = Vec::new();
    let mut paths = Vec::new();
    for call in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        let Some((api, option_index)) = parser_api(&call) else {
            continue;
        };
        let arguments = named_arguments(&call);
        let Some(options) = arguments.get(option_index) else {
            continue;
        };
        let option_node = resolve_local_options(&call, options).unwrap_or_else(|| options.clone());
        if !availability_compatible(&option_node, &call, conditional) {
            continue;
        }
        let option_text = option_node.text().into_owned();
        let enabled = ENABLE_FLAGS
            .into_iter()
            .filter(|flag| contains_identifier(&option_text, flag))
            .collect::<Vec<_>>();
        if enabled.is_empty() {
            continue;
        }

        let source = evidence_item(
            path,
            &option_node,
            ENABLE_RULE_ID,
            EvidenceKind::SecurityConfiguration,
            BTreeMap::from([
                ("parser_api".to_string(), text_capture(path, &call, api)),
                (
                    "entity_enabling_flags".to_string(),
                    text_capture(path, &option_node, &enabled.join("|")),
                ),
                ("options".to_string(), capture(path, &option_node)),
            ]),
            vec!["native", "libxml2", "external-entity-enablement"],
            comments,
            conditional,
            literals,
            Vec::new(),
        );
        if excluded(&source) {
            continue;
        }
        let sink = evidence_item(
            path,
            &call,
            PARSE_RULE_ID,
            EvidenceKind::Sink,
            BTreeMap::from([
                ("parser_api".to_string(), text_capture(path, &call, api)),
                ("parse_call".to_string(), capture(path, &call)),
            ]),
            vec!["native", "libxml2", "xml-parse"],
            comments,
            conditional,
            literals,
            vec![source.id.clone()],
        );
        let no_xxe = contains_identifier(&option_text, "XML_PARSE_NO_XXE").then(|| {
            evidence_item(
                path,
                &option_node,
                NO_XXE_RULE_ID,
                EvidenceKind::Guard,
                BTreeMap::from([(
                    "control".to_string(),
                    text_capture(path, &option_node, "XML_PARSE_NO_XXE"),
                )]),
                vec!["native", "libxml2", "external-entity-disabled"],
                comments,
                conditional,
                literals,
                vec![sink.id.clone()],
            )
        });
        let nonet = contains_identifier(&option_text, "XML_PARSE_NONET").then(|| {
            evidence_item(
                path,
                &option_node,
                NONET_RULE_ID,
                EvidenceKind::SecurityConfiguration,
                BTreeMap::from([(
                    "partial_control".to_string(),
                    text_capture(path, &option_node, "XML_PARSE_NONET"),
                )]),
                vec!["native", "libxml2", "network-only-not-xxe-proof"],
                comments,
                conditional,
                literals,
                vec![sink.id.clone()],
            )
        });
        paths.push(xml_path(&source, &sink, no_xxe.as_ref(), nonet.as_ref()));
        additions.push(source);
        if let Some(item) = nonet {
            additions.push(item);
        }
        if let Some(item) = no_xxe {
            additions.push(item);
        }
        additions.push(sink);
    }
    evidence.extend(additions);
    paths
}

fn parser_api(call: &Node<'_, StrDoc<SupportLang>>) -> Option<(&'static str, usize)> {
    let function = call.field("function")?.text().trim().to_string();
    let function = function.strip_prefix("::").unwrap_or(&function);
    match function {
        "xmlReadMemory" | "xmlReaderForMemory" => Some(("memory", 4)),
        "xmlReadFile" | "xmlReaderForFile" => Some(("file", 2)),
        "xmlReadFd" | "xmlReaderForFd" => Some(("file-descriptor", 3)),
        "xmlReadDoc" | "xmlReaderForDoc" => Some(("document", 3)),
        "xmlCtxtReadMemory" => Some(("context-memory", 5)),
        "xmlCtxtReadFile" => Some(("context-file", 3)),
        "xmlCtxtReadFd" => Some(("context-file-descriptor", 4)),
        "xmlCtxtReadDoc" => Some(("context-document", 4)),
        "xmlReaderForIO" => Some(("reader-io", 5)),
        _ => None,
    }
}

fn named_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.field("arguments")
        .map(|args| args.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
}

fn resolve_local_options<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
    options: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let option_text = options.text();
    let local = simple_identifier(option_text.trim())?;
    let scope = call
        .ancestors()
        .find(|node| node.kind().as_ref() == "function_definition")?;
    let initializer = scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "init_declarator")
        .filter(|node| node.range().end < call.range().start)
        .filter(|node| {
            node.ancestors()
                .find(|ancestor| ancestor.kind().as_ref() == "compound_statement")
                .is_some_and(|block| {
                    block.range().start <= call.range().start
                        && call.range().end <= block.range().end
                })
        })
        .filter(|node| {
            node.field("declarator").is_some_and(|declarator| {
                declarator
                    .dfs()
                    .filter(|child| child.kind().as_ref() == "identifier")
                    .last()
                    .is_some_and(|identifier| identifier.text().trim() == local)
            })
        })
        .last()?;
    let value = initializer.field("value")?;
    let reassigned = scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| initializer.range().end < node.range().start)
        .filter(|node| node.range().end < call.range().start)
        .any(|node| {
            node.field("left")
                .is_some_and(|left| left.text().trim() == local)
        });
    (!reassigned).then_some(value)
}

fn contains_identifier(text: &str, expected: &str) -> bool {
    text.split(|character: char| character != '_' && !character.is_ascii_alphanumeric())
        .any(|token| token == expected)
}

fn availability_compatible(
    configuration: &Node<'_, StrDoc<SupportLang>>,
    operation: &Node<'_, StrDoc<SupportLang>>,
    conditional: &ConditionalRegions,
) -> bool {
    let configuration = conditional.availability_for(configuration.range());
    let operation = conditional.availability_for(operation.range());
    match configuration.state {
        AvailabilityState::Always => operation.state != AvailabilityState::Excluded,
        AvailabilityState::Conditional | AvailabilityState::Unknown => configuration == operation,
        AvailabilityState::Excluded => false,
    }
}

fn simple_identifier(value: &str) -> Option<&str> {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        .then_some(())?;
    characters
        .all(|character| character == '_' || character.is_ascii_alphanumeric())
        .then_some(value)
}

#[allow(clippy::too_many_arguments)]
fn evidence_item<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    captures: BTreeMap<String, Capture>,
    tags: Vec<&str>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    related_evidence: Vec<String>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, rule_id, node),
        kind,
        capability: Capability::XmlParsing,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: vec!["CWE-611".to_string()],
        tags: tags
            .into_iter()
            .map(str::to_string)
            .chain(std::iter::once(
                "parse-recovery:locally-complete".to_string(),
            ))
            .collect(),
        confidence: Confidence::High,
        provenance: Provenance {
            resolution: Resolution::Ast,
            engine: ENGINE.to_string(),
            rule_version: 1,
        },
        context: EvidenceContext {
            comment: comments.is_in_comment(node.range()),
            reachability: Some(reachability::classify(node, literals)),
            availability: Some(conditional.availability_for(node.range())),
            ..EvidenceContext::default()
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence,
    }
}

fn xml_path(
    source: &Evidence,
    sink: &Evidence,
    no_xxe: Option<&Evidence>,
    nonet: Option<&Evidence>,
) -> SecurityPath {
    let state = if no_xxe.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![step(SecurityPathStepKind::Source, source)];
    if let Some(item) = nonet {
        steps.push(step(SecurityPathStepKind::IneffectiveProtection, item));
    }
    if let Some(item) = no_xxe {
        steps.push(step(SecurityPathStepKind::Protection, item));
    }
    steps.push(step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: path_id(source, sink, state),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::XmlParsing,
        cwe_candidates: vec!["CWE-611".to_string()],
        state,
        steps,
        protection_evidence_ids: no_xxe.map(|item| vec![item.id.clone()]).unwrap_or_default(),
        uncertainty_reasons: no_xxe
            .is_none()
            .then_some("external_entity_loading_enabled_without_exact_no_xxe_control".to_string())
            .into_iter()
            .collect(),
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family libxml2 parser-options relationship 1".to_string(),
            maximum_propagation_depth: 0,
        },
    }
}

fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    Capture {
        text: node.text().into_owned(),
        location: location(path, node),
    }
}

fn text_capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>, text: &str) -> Capture {
    Capture {
        text: text.to_string(),
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

fn evidence_id(path: &str, rule: &str, node: &Node<'_, StrDoc<SupportLang>>) -> String {
    stable_id(
        "ev",
        &format!(
            "{path}\0{rule}\0{}\0{}",
            node.range().start,
            node.range().end
        ),
    )
}

fn path_id(source: &Evidence, sink: &Evidence, state: SecurityPathState) -> String {
    stable_id("path", &format!("{}\0{}\0{state:?}", source.id, sink.id))
}

fn stable_id(prefix: &str, input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}

fn step(kind: SecurityPathStepKind, item: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: item.location.clone(),
        evidence_id: Some(item.id.clone()),
        symbol: None,
    }
}

fn excluded(item: &Evidence) -> bool {
    item.context
        .availability
        .as_ref()
        .is_some_and(|value| value.state == AvailabilityState::Excluded)
}
