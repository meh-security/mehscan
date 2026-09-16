use std::collections::BTreeMap;

use ast_grep_core::Node;
use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_language::SupportLang;
use mehscan_core::{
    Capability, Capture, Confidence, Evidence, EvidenceContext, EvidenceKind, Language, Location,
    Position, Provenance, Resolution, SecurityPath, SecurityPathProvenance, SecurityPathState,
    SecurityPathStep, SecurityPathStepKind,
};

use super::comments::CommentRanges;
use super::conditional::ConditionalRegions;
use super::context::enclosing_symbol;
use super::literals::LiteralEnvironment;
use super::reachability;

const LOAD_RULE_ID: &str = "c-family-serialized-blob-load";
const COPY_RULE_ID: &str = "c-family-fixed-layout-blob-copy";
const LENGTH_RULE_ID: &str = "c-family-serialized-blob-length-validation";
const ENGINE: &str = "tree-sitter c-family serialized-blob extent relationship";
const PATH_ENGINE: &str = "mehscan c-family serialized-blob extent relationship 1";

type SyntaxNode<'tree> = Node<'tree, StrDoc<SupportLang>>;
type ExtentDeclaration<'tree> = (SyntaxNode<'tree>, SyntaxNode<'tree>);
type BlobLoad<'tree> = (SyntaxNode<'tree>, SyntaxNode<'tree>, Option<String>);

pub(crate) fn add_native_serialized_blob_observations<'tree>(
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
    for copy in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| !comments.is_in_comment(node.range()))
        .filter(|node| is_memcpy(node))
    {
        let arguments = named_arguments(&copy);
        if arguments.len() != 3 {
            continue;
        }
        let destination = compact(arguments[0].text().as_ref());
        let blob_text = arguments[1].text();
        let Some(blob) = simple_identifier(blob_text.trim()) else {
            continue;
        };
        let extent_text = arguments[2].text();
        let Some(extent) = simple_identifier(extent_text.trim()) else {
            continue;
        };
        let Some(scope) = copy
            .ancestors()
            .find(|node| node.kind().as_ref() == "function_definition")
        else {
            continue;
        };
        let Some((extent_declaration, extent_expression)) =
            fixed_layout_extent(&scope, extent, copy.range().start)
        else {
            continue;
        };
        let Some((load_binding, load, length)) =
            blob_load(&scope, blob, copy.range().start, comments)
        else {
            continue;
        };
        let Some(allocation) = destination_allocation(
            &scope,
            &destination,
            extent,
            extent_declaration.range().end,
            copy.range().start,
        ) else {
            continue;
        };
        if reassigned_between(&scope, blob, load_binding.range().end, copy.range().start)
            || reassigned_between(
                &scope,
                extent,
                extent_declaration.range().end,
                copy.range().start,
            )
        {
            continue;
        }
        let guard = length.as_deref().and_then(|length| {
            length_guard(&scope, length, extent, load.range().end, copy.range().start)
        });

        let source = make_evidence(
            path,
            &load,
            LOAD_RULE_ID,
            EvidenceKind::Source,
            Capability::SerializedBlobLoad,
            BTreeMap::from([
                ("blob".to_string(), text_capture(path, &load_binding, blob)),
                ("loader".to_string(), capture(path, &load)),
                (
                    "loaded_length".to_string(),
                    text_capture(path, &load, length.as_deref().unwrap_or("unavailable")),
                ),
            ]),
            vec![
                "native",
                "serialized-buffer-loader",
                if length.is_some() {
                    "loader-length:captured"
                } else {
                    "loader-length:discarded"
                },
                "parse-recovery:locally-complete",
            ],
            comments,
            conditional,
            literals,
            Vec::new(),
        );
        let mut sink = make_evidence(
            path,
            &copy,
            COPY_RULE_ID,
            EvidenceKind::Sink,
            Capability::SerializedBlobCopy,
            BTreeMap::from([
                ("blob".to_string(), text_capture(path, &copy, blob)),
                (
                    "expected_extent".to_string(),
                    text_capture(path, &copy, extent),
                ),
                (
                    "extent_computation".to_string(),
                    capture(path, &extent_expression),
                ),
                (
                    "destination_allocation".to_string(),
                    capture(path, &allocation),
                ),
                ("copy".to_string(), capture(path, &copy)),
            ]),
            vec![
                "native",
                "fixed-layout-serialized-copy",
                "same-extent-allocation-and-copy",
                "parse-recovery:locally-complete",
            ],
            comments,
            conditional,
            literals,
            vec![source.id.clone()],
        );
        let protection = guard.as_ref().map(|guard| {
            make_evidence(
                path,
                guard,
                LENGTH_RULE_ID,
                EvidenceKind::Validation,
                Capability::SerializedBlobLengthValidation,
                BTreeMap::from([
                    (
                        "loaded_length".to_string(),
                        text_capture(path, guard, length.as_deref().unwrap_or_default()),
                    ),
                    (
                        "expected_extent".to_string(),
                        text_capture(path, guard, extent),
                    ),
                    ("mismatch_rejection".to_string(), capture(path, guard)),
                ]),
                vec![
                    "native",
                    "exact-loaded-length-mismatch-rejection",
                    "pre-copy-validation",
                    "parse-recovery:locally-complete",
                ],
                comments,
                conditional,
                literals,
                vec![source.id.clone()],
            )
        });
        if let Some(protection) = &protection {
            sink.related_evidence.push(protection.id.clone());
            sink.tags.push("blob-length:validated".to_string());
        } else {
            sink.tags.push("blob-length:unproven".to_string());
        }
        paths.push(blob_path(&source, &sink, protection.as_ref()));
        additions.push(source);
        additions.push(sink);
        additions.extend(protection);
    }
    evidence.extend(additions);
    paths
}

fn fixed_layout_extent<'tree>(
    scope: &Node<'tree, StrDoc<SupportLang>>,
    extent: &str,
    before: usize,
) -> Option<ExtentDeclaration<'tree>> {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "init_declarator")
        .filter(|node| node.range().start < before)
        .find_map(|declaration| {
            let declarator = declaration.field("declarator")?;
            (declarator.text().trim() == extent).then_some(())?;
            let value = declaration.field("value")?;
            let text = value.text();
            (text.contains("sizeof")
                && text.chars().filter(|character| *character == '*').count() >= 2)
                .then_some((declaration, value))
        })
}

fn blob_load<'tree>(
    scope: &Node<'tree, StrDoc<SupportLang>>,
    blob: &str,
    before: usize,
    comments: &CommentRanges,
) -> Option<BlobLoad<'tree>> {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "init_declarator")
        .filter(|node| node.range().start < before)
        .filter(|node| !comments.is_in_comment(node.range()))
        .find_map(|binding| {
            let declared = binding
                .field("declarator")?
                .dfs()
                .filter(|node| node.kind().as_ref() == "identifier")
                .last()?
                .text()
                .into_owned();
            (declared == blob).then_some(())?;
            let value = binding.field("value")?;
            let call = value
                .dfs()
                .find(|node| node.kind().as_ref() == "call_expression")?;
            let callee = call.field("function")?.text().into_owned();
            is_buffer_loader(&callee).then_some(())?;
            let arguments = named_arguments(&call);
            let length = arguments.iter().find_map(|argument| {
                let value = compact(argument.text().as_ref());
                value
                    .strip_prefix('&')
                    .and_then(simple_identifier)
                    .map(str::to_string)
            });
            (length.is_some()
                || arguments
                    .iter()
                    .any(|argument| matches!(argument.text().trim(), "NULL" | "nullptr" | "0")))
            .then_some((binding, call, length))
        })
}

fn is_buffer_loader(callee: &str) -> bool {
    let terminal = callee
        .rsplit(['.', ':'])
        .find(|part| !part.is_empty())
        .unwrap_or(callee)
        .to_ascii_lowercase();
    ["load", "read", "decode", "deserialize"]
        .iter()
        .any(|part| terminal.contains(part))
        && ["buffer", "blob", "string", "bytes", "data"]
            .iter()
            .any(|part| terminal.contains(part))
}

fn destination_allocation<'tree>(
    scope: &Node<'tree, StrDoc<SupportLang>>,
    destination: &str,
    extent: &str,
    after: usize,
    before: usize,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| after < node.range().start && node.range().end < before)
        .find_map(|assignment| {
            let left = compact(assignment.field("left")?.text().as_ref());
            (left == destination).then_some(())?;
            let right = assignment.field("right")?;
            let call = right
                .dfs()
                .find(|node| node.kind().as_ref() == "call_expression")?;
            let callee = call.field("function")?.text().to_ascii_lowercase();
            (callee.contains("alloc")
                && named_arguments(&call)
                    .iter()
                    .any(|argument| argument.text().trim() == extent))
            .then_some(call)
        })
}

fn length_guard<'tree>(
    scope: &Node<'tree, StrDoc<SupportLang>>,
    length: &str,
    extent: &str,
    after: usize,
    before: usize,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| after < node.range().start && node.range().end < before)
        .find(|statement| {
            statement.field("condition").is_some_and(|condition| {
                let condition = trim_outer_parentheses(compact(condition.text().as_ref()));
                condition == format!("{length}!={extent}")
                    || condition == format!("{extent}!={length}")
            }) && statement
                .field("consequence")
                .is_some_and(|branch| branch_terminates(&branch))
        })
}

fn branch_terminates(branch: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let terminal = if branch.kind().as_ref() == "compound_statement" {
        let Some(terminal) = branch.children().filter(|node| node.is_named()).last() else {
            return false;
        };
        terminal
    } else {
        branch.clone()
    };
    matches!(
        terminal.kind().as_ref(),
        "return_statement" | "goto_statement" | "continue_statement" | "break_statement"
    )
}

fn reassigned_between(
    scope: &Node<'_, StrDoc<SupportLang>>,
    local: &str,
    after: usize,
    before: usize,
) -> bool {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| after < node.range().start && node.range().end < before)
        .any(|node| {
            node.field("left")
                .is_some_and(|left| left.text().trim() == local)
        })
}

fn is_memcpy(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    call.field("function")
        .is_some_and(|function| function.text().trim() == "memcpy")
}

fn blob_path(source: &Evidence, sink: &Evidence, protection: Option<&Evidence>) -> SecurityPath {
    let state = if protection.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
    if let Some(protection) = protection {
        steps.push(evidence_step(SecurityPathStepKind::Protection, protection));
    } else {
        steps.push(SecurityPathStep {
            kind: SecurityPathStepKind::IneffectiveProtection,
            location: source.location.clone(),
            evidence_id: None,
            symbol: Some(
                "loader does not prove the serialized blob matches the fixed copy extent"
                    .to_string(),
            ),
        });
    }
    steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: stable_id(
            "path",
            &format!("{}\0{}\0{state:?}\0CWE-125", source.id, sink.id),
        ),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::SerializedBlobCopy,
        cwe_candidates: cwes(),
        state,
        steps,
        protection_evidence_ids: protection
            .map(|item| vec![item.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: protection
            .is_none()
            .then(|| "serialized_blob_length_not_matched_to_fixed_layout_extent".to_string())
            .into_iter()
            .collect(),
        provenance: SecurityPathProvenance {
            engine: PATH_ENGINE.to_string(),
            maximum_propagation_depth: 1,
        },
    }
}

#[allow(clippy::too_many_arguments)]
fn make_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    tags: Vec<&str>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    related_evidence: Vec<String>,
) -> Evidence {
    Evidence {
        id: stable_id(
            "ev",
            &format!(
                "{path}\0{rule_id}\0{}\0{}",
                node.range().start,
                node.range().end
            ),
        ),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes(),
        tags: tags.into_iter().map(str::to_string).collect(),
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

fn named_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.field("arguments")
        .map(|arguments| {
            arguments
                .children()
                .filter(|node| node.is_named())
                .collect()
        })
        .unwrap_or_default()
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
}

fn trim_outer_parentheses(mut value: String) -> String {
    while value.starts_with('(') && value.ends_with(')') {
        value = value[1..value.len() - 1].to_string();
    }
    value
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

fn evidence_step(kind: SecurityPathStepKind, item: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: item.location.clone(),
        evidence_id: Some(item.id.clone()),
        symbol: None,
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

fn cwes() -> Vec<String> {
    vec!["CWE-20".to_string(), "CWE-125".to_string()]
}

fn stable_id(prefix: &str, value: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}_{hash:016x}")
}
