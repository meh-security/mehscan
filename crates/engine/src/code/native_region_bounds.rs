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

const SOURCE_RULE: &str = "c-family-image-copy-region-quantity";
const LIMIT_RULE: &str = "c-family-image-copy-destination-region";
const VALIDATION_RULE: &str = "c-family-image-copy-region-validation";
const SINK_RULE: &str = "c-family-image-copy-operation";
const ENGINE: &str = "tree-sitter c-family destination-region relationship";
const CALLEE: &str = "freerdp_image_copy_no_overlap";

#[derive(Clone)]
struct Axis<'tree> {
    offset: Node<'tree, StrDoc<SupportLang>>,
    original_extent: Node<'tree, StrDoc<SupportLang>>,
    destination_extent: Node<'tree, StrDoc<SupportLang>>,
    applied_extent: Node<'tree, StrDoc<SupportLang>>,
}

#[derive(Clone)]
struct AxisClamp<'tree> {
    condition: Node<'tree, StrDoc<SupportLang>>,
    assignment: Node<'tree, StrDoc<SupportLang>>,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_native_region_bound_observations<'tree>(
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

    let mut paths = Vec::new();
    for call in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
    {
        if comments.is_in_comment(call.range()) || terminal_callee(&call).as_deref() != Some(CALLEE)
        {
            continue;
        }
        let Some(function) = call
            .ancestors()
            .find(|node| node.kind().as_ref() == "function_definition")
        else {
            continue;
        };
        let arguments = call_arguments(&call);
        if arguments.len() < 7 {
            continue;
        }
        let Some(x_destination) = guarded_destination_extent(&function, &call, &arguments[3])
        else {
            continue;
        };
        let Some(y_destination) = guarded_destination_extent(&function, &call, &arguments[4])
        else {
            continue;
        };
        let x_axis = Axis {
            offset: arguments[3].clone(),
            original_extent: original_extent(&function, &call, &arguments[5]),
            destination_extent: x_destination,
            applied_extent: arguments[5].clone(),
        };
        let y_axis = Axis {
            offset: arguments[4].clone(),
            original_extent: original_extent(&function, &call, &arguments[6]),
            destination_extent: y_destination,
            applied_extent: arguments[6].clone(),
        };
        let x_clamp = exact_preceding_clamp(&function, &call, &x_axis);
        let y_clamp = exact_preceding_clamp(&function, &call, &y_axis);
        let protection = match (x_clamp, y_clamp) {
            (Some(x), Some(y)) => Some(validation_evidence(
                path,
                &x,
                &y,
                comments,
                conditional,
                literals,
            )),
            _ => None,
        };
        let source = source_evidence(path, &x_axis, &y_axis, comments, conditional, literals);
        let limit = limit_evidence(path, &x_axis, &y_axis, comments, conditional, literals);
        let sink = sink_evidence(
            path,
            &call,
            &x_axis,
            &y_axis,
            comments,
            conditional,
            literals,
        );
        if is_excluded(&sink) {
            push_unique(evidence, sink);
            continue;
        }
        paths.push(region_path(&source, &sink, protection.as_ref()));
        push_unique(evidence, source);
        push_unique(evidence, limit);
        if let Some(protection) = protection {
            push_unique(evidence, protection);
        }
        push_unique(evidence, sink);
    }
    paths
}

fn guarded_destination_extent<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    sink: &Node<'tree, StrDoc<SupportLang>>,
    offset: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let offset_text = offset.text();
    let offset = simple_identifier(offset_text.trim())?;
    function
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "if_statement" && node.range().end < sink.range().start
        })
        .find_map(|statement| {
            let condition = statement.field("condition")?;
            let comparison = condition.dfs().find(|node| {
                node.kind().as_ref() == "binary_expression"
                    && binary_operator(node).as_deref() == Some(">")
                    && node
                        .field("left")
                        .is_some_and(|left| left.text().trim() == offset)
                    && node
                        .field("right")
                        .is_some_and(|right| simple_identifier(right.text().trim()).is_some())
            })?;
            is_rejecting_consequence(&statement).then(|| comparison.field("right").unwrap())
        })
}

fn original_extent<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    sink: &Node<'tree, StrDoc<SupportLang>>,
    applied: &Node<'tree, StrDoc<SupportLang>>,
) -> Node<'tree, StrDoc<SupportLang>> {
    let applied_text = applied.text();
    let Some(name) = simple_identifier(applied_text.trim()) else {
        return applied.clone();
    };
    function
        .dfs()
        .filter(|node| node.kind().as_ref() == "init_declarator")
        .filter(|node| node.range().end < sink.range().start)
        .find_map(|declaration| {
            (declaration
                .field("declarator")
                .is_some_and(|declarator| declarator.text().trim() == name))
            .then(|| declaration.field("value"))
            .flatten()
            .filter(|value| simple_identifier(value.text().trim()).is_some())
        })
        .unwrap_or_else(|| applied.clone())
}

fn is_rejecting_consequence(statement: &Node<'_, StrDoc<SupportLang>>) -> bool {
    statement.dfs().any(|node| {
        node.kind().as_ref() == "return_statement"
            || node.kind().as_ref() == "call_expression"
                && node.field("function").is_some_and(|function| {
                    let name = function.text().to_ascii_lowercase();
                    ["error", "fatal", "abort", "panic"]
                        .iter()
                        .any(|part| name.contains(part))
                })
    })
}

fn terminal_callee(call: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let text = call.field("function")?.text();
    text.rsplit(|character: char| !(character == '_' || character.is_ascii_alphanumeric()))
        .find(|part| !part.is_empty())
        .map(str::to_string)
}

fn call_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    let Some(arguments) = call.field("arguments") else {
        return Vec::new();
    };
    arguments
        .children()
        .filter(|node| node.is_named())
        .collect()
}

fn exact_preceding_clamp<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    sink: &Node<'tree, StrDoc<SupportLang>>,
    axis: &Axis<'tree>,
) -> Option<AxisClamp<'tree>> {
    let applied_text = axis.applied_extent.text();
    let applied = simple_identifier(applied_text.trim())?;
    let original = axis.original_extent.text();
    let offset = axis.offset.text();
    let destination = axis.destination_extent.text();
    if applied == original.trim() {
        return None;
    }
    let declaration = function.dfs().find(|node| {
        node.kind().as_ref() == "declaration"
            && node.range().end < sink.range().start
            && node.dfs().any(|child| {
                child.kind().as_ref() == "init_declarator"
                    && child.field("declarator").is_some_and(|declarator| {
                        declarator.text().trim() == applied
                            && child
                                .field("value")
                                .is_some_and(|value| value.text().trim() == original.trim())
                    })
            })
    })?;
    let mut candidates = function
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| {
            node.range().start > declaration.range().end && node.range().end < sink.range().start
        })
        .filter_map(|statement| {
            let condition = statement.field("condition")?;
            condition_proves_region(
                &condition,
                offset.as_ref(),
                original.as_ref(),
                destination.as_ref(),
            )
            .then_some((statement, condition))
        })
        .collect::<Vec<_>>();
    candidates.sort_by_key(|(statement, _)| statement.range().start);
    let (statement, condition) = candidates.pop()?;
    let assignment = statement.dfs().find(|node| {
        node.kind().as_ref() == "assignment_expression"
            && node
                .field("left")
                .is_some_and(|left| left.text().trim() == applied)
            && node
                .field("right")
                .is_some_and(|right| subtraction_is(&right, destination.as_ref(), offset.as_ref()))
    })?;
    let reassigned = function.dfs().any(|node| {
        node.kind().as_ref() == "assignment_expression"
            && node.range().start > statement.range().end
            && node.range().end < sink.range().start
            && node
                .field("left")
                .is_some_and(|left| left.text().trim() == applied)
    });
    (!reassigned).then_some(AxisClamp {
        condition,
        assignment,
    })
}

fn condition_proves_region(
    condition: &Node<'_, StrDoc<SupportLang>>,
    offset: &str,
    extent: &str,
    destination: &str,
) -> bool {
    condition.dfs().any(|node| {
        if node.kind().as_ref() != "binary_expression" {
            return false;
        }
        let Some(left) = node.field("left") else {
            return false;
        };
        let Some(right) = node.field("right") else {
            return false;
        };
        binary_operator(&node).as_deref() == Some(">")
            && right.text().trim() == destination
            && contains_addition(&left, offset, extent)
    })
}

fn contains_addition(
    node: &Node<'_, StrDoc<SupportLang>>,
    left_name: &str,
    right_name: &str,
) -> bool {
    node.dfs().any(|child| {
        child.kind().as_ref() == "binary_expression"
            && binary_operator(&child).as_deref() == Some("+")
            && child
                .field("left")
                .is_some_and(|left| contains_identifier(left.text().as_ref(), left_name))
            && child
                .field("right")
                .is_some_and(|right| contains_identifier(right.text().as_ref(), right_name))
            && child.field("left").is_some_and(|left| {
                let text = left.text().to_ascii_lowercase();
                text.contains("1ull") || text.contains("uint64")
            })
    })
}

fn subtraction_is(node: &Node<'_, StrDoc<SupportLang>>, left_name: &str, right_name: &str) -> bool {
    binary_operator(node).as_deref() == Some("-")
        && node
            .field("left")
            .is_some_and(|left| left.text().trim() == left_name)
        && node
            .field("right")
            .is_some_and(|right| right.text().trim() == right_name)
}

fn binary_operator(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let left = node.field("left")?;
    let right = node.field("right")?;
    node.text()
        .get(left.range().end - node.range().start..right.range().start - node.range().start)
        .map(str::trim)
        .map(str::to_string)
}

fn source_evidence<'tree>(
    path: &str,
    x: &Axis<'tree>,
    y: &Axis<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    item(
        path,
        &x.original_extent,
        SOURCE_RULE,
        EvidenceKind::Source,
        Capability::InputQuantity,
        BTreeMap::from([
            ("copy_width".to_string(), capture(path, &x.original_extent)),
            ("copy_height".to_string(), capture(path, &y.original_extent)),
        ]),
        &[
            "native",
            "image-copy",
            "destination-region",
            "parse-recovery:locally-complete",
        ],
        comments,
        conditional,
        literals,
    )
}

fn limit_evidence<'tree>(
    path: &str,
    x: &Axis<'tree>,
    y: &Axis<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    item(
        path,
        &x.destination_extent,
        LIMIT_RULE,
        EvidenceKind::Resource,
        Capability::DomainLimitComputation,
        BTreeMap::from([
            (
                "destination_width".to_string(),
                capture(path, &x.destination_extent),
            ),
            (
                "destination_height".to_string(),
                capture(path, &y.destination_extent),
            ),
            ("x_offset".to_string(), capture(path, &x.offset)),
            ("y_offset".to_string(), capture(path, &y.offset)),
        ]),
        &[
            "native",
            "image-copy",
            "authoritative-destination-region",
            "parse-recovery:locally-complete",
        ],
        comments,
        conditional,
        literals,
    )
}

fn validation_evidence<'tree>(
    path: &str,
    x: &AxisClamp<'tree>,
    y: &AxisClamp<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    item(
        path,
        &x.condition,
        VALIDATION_RULE,
        EvidenceKind::Validation,
        Capability::DomainLimitValidation,
        BTreeMap::from([
            ("x_bound".to_string(), capture(path, &x.condition)),
            ("x_clamp".to_string(), capture(path, &x.assignment)),
            ("y_bound".to_string(), capture(path, &y.condition)),
            ("y_clamp".to_string(), capture(path, &y.assignment)),
        ]),
        &[
            "native",
            "image-copy",
            "both-axes-bounded",
            "parse-recovery:locally-complete",
        ],
        comments,
        conditional,
        literals,
    )
}

fn sink_evidence<'tree>(
    path: &str,
    sink: &Node<'tree, StrDoc<SupportLang>>,
    x: &Axis<'tree>,
    y: &Axis<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    let anchor = sink.field("function").unwrap_or_else(|| sink.clone());
    item(
        path,
        &anchor,
        SINK_RULE,
        EvidenceKind::Sink,
        Capability::CountControlledMemoryOperation,
        BTreeMap::from([
            ("operation".to_string(), capture(path, sink)),
            (
                "applied_width".to_string(),
                capture(path, &x.applied_extent),
            ),
            (
                "applied_height".to_string(),
                capture(path, &y.applied_extent),
            ),
        ]),
        &[
            "native",
            "image-copy",
            "destination-region-write",
            "parse-recovery:locally-complete",
        ],
        comments,
        conditional,
        literals,
    )
}

#[allow(clippy::too_many_arguments)]
fn item<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule_id: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    tags: &[&str],
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, rule_id, node),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: vec![
            "CWE-787".to_string(),
            "CWE-122".to_string(),
            "CWE-1284".to_string(),
        ],
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
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
            literals: BTreeMap::new(),
            secret: None,
            value_transform: None,
            http_routes: Vec::new(),
            resource_policy: None,
            runtime_environment: None,
        },
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence: Vec::new(),
    }
}

fn region_path(source: &Evidence, sink: &Evidence, protection: Option<&Evidence>) -> SecurityPath {
    let state = if protection.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![step(SecurityPathStepKind::Source, source)];
    if let Some(protection) = protection {
        steps.push(step(SecurityPathStepKind::Protection, protection));
    }
    steps.push(step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: path_id(source, sink, state, &steps),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::CountControlledMemoryOperation,
        cwe_candidates: vec![
            "CWE-787".to_string(),
            "CWE-122".to_string(),
            "CWE-1284".to_string(),
        ],
        state,
        steps,
        protection_evidence_ids: protection
            .map(|item| vec![item.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: if protection.is_some() {
            vec!["destination_storage_contract_requires_confirmation".to_string()]
        } else {
            vec![
                "copy_region_may_exceed_destination_extent".to_string(),
                "both_destination_axes_not_proven_before_write".to_string(),
            ]
        },
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family destination-region relationship 1".to_string(),
            maximum_propagation_depth: 1,
        },
    }
}

fn step(kind: SecurityPathStepKind, evidence: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: evidence.location.clone(),
        evidence_id: Some(evidence.id.clone()),
        symbol: None,
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
fn path_id(
    source: &Evidence,
    sink: &Evidence,
    state: SecurityPathState,
    steps: &[SecurityPathStep],
) -> String {
    let mut input = format!("{}\0{}\0{state:?}", source.id, sink.id);
    for step in steps {
        input.push_str(&format!(
            "\0{:?}\0{}\0{}",
            step.kind, step.location.start.byte_offset, step.location.end.byte_offset
        ));
    }
    stable_id("path", &input)
}
fn stable_id(prefix: &str, input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}
fn simple_identifier(value: &str) -> Option<&str> {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|c| c == '_' || c.is_ascii_alphabetic())
        .then_some(())?;
    chars
        .all(|c| c == '_' || c.is_ascii_alphanumeric())
        .then_some(value)
}
fn contains_identifier(text: &str, name: &str) -> bool {
    text.split(|c: char| c != '_' && !c.is_ascii_alphanumeric())
        .any(|part| part == name)
}
fn push_unique(evidence: &mut Vec<Evidence>, addition: Evidence) {
    if !evidence.iter().any(|item| item.id == addition.id) {
        evidence.push(addition);
    }
}
fn is_excluded(evidence: &Evidence) -> bool {
    evidence
        .context
        .availability
        .as_ref()
        .is_some_and(|availability| availability.state == AvailabilityState::Excluded)
}
