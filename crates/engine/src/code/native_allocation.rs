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

const INPUT_RULE_ID: &str = "c-family-architecture-sized-input";
const COMPUTATION_RULE_ID: &str = "c-family-allocation-size-computation";
const VALIDATION_RULE_ID: &str = "c-family-architecture-size-validation";
const ENGINE: &str = "tree-sitter c-family allocation-size relationship";

/// Records the two independently useful halves of the bounded relationship.
/// Linking happens after all files have been scanned because the validating
/// input boundary and allocation calculation commonly live in different
/// translation units.
#[allow(clippy::too_many_arguments)]
pub(crate) fn add_native_allocation_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    build_symbols: &BTreeMap<String, bool>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(language, Language::C | Language::Cpp) {
        return;
    }

    for statement in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        let Some(condition) = statement.field("condition") else {
            continue;
        };
        let condition_text = condition.text();
        if !condition_text.contains("SIZE_MAX") || !condition_text.contains('/') {
            continue;
        }
        let Some(input) = input_parameter_for_condition(&statement, condition_text.as_ref()) else {
            continue;
        };
        let source =
            architecture_input_evidence(path, &condition, &input, comments, conditional, literals);
        if source
            .context
            .availability
            .as_ref()
            .is_some_and(|availability| availability.state == AvailabilityState::Excluded)
        {
            continue;
        }
        evidence.push(source.clone());

        if let Some((guard, flag)) =
            effective_rejecting_guard(root, &statement, conditional, build_symbols)
        {
            evidence.push(validation_evidence(
                path,
                &guard,
                &input,
                &flag,
                &source,
                comments,
                conditional,
                literals,
            ));
        }
    }

    for declaration in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "declaration")
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        let Some(local) = size_local(&declaration) else {
            continue;
        };
        let Some(calculation) = allocation_calculation(root, &declaration, &local) else {
            continue;
        };
        evidence.push(allocation_evidence(
            path,
            &calculation,
            &local,
            comments,
            conditional,
            literals,
        ));
    }
}

struct AllocationCalculation<'tree> {
    aligned_input: Node<'tree, StrDoc<SupportLang>>,
    computation: Node<'tree, StrDoc<SupportLang>>,
    macro_call: Node<'tree, StrDoc<SupportLang>>,
    allocation: Node<'tree, StrDoc<SupportLang>>,
    input_member: String,
}

fn input_parameter_for_condition(
    statement: &Node<'_, StrDoc<SupportLang>>,
    condition: &str,
) -> Option<String> {
    let called = statement
        .field("condition")?
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter_map(|node| node.field("function"))
        .map(|node| node.text().into_owned())
        .collect::<Vec<_>>();
    let before_limit = condition.split("SIZE_MAX").next().unwrap_or(condition);
    let candidates = identifiers(before_limit)
        .filter(|name| !is_type_word(name) && !is_constant_identifier(name))
        .filter(|name| name.len() > 1)
        .filter(|name| !called.iter().any(|called| called == name))
        .collect::<Vec<_>>();
    candidates.last().copied().map(str::to_string)
}

fn effective_rejecting_guard<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    statement: &Node<'tree, StrDoc<SupportLang>>,
    conditional: &ConditionalRegions,
    build_symbols: &BTreeMap<String, bool>,
) -> Option<(Node<'tree, StrDoc<SupportLang>>, String)> {
    let consequence = statement.field("consequence")?;
    let assignment = consequence
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .find(|node| {
            selected_validation_branch(&conditional.availability_for(node.range()), build_symbols)
                && node
                    .field("left")
                    .is_some_and(|left| simple_identifier(left.text().trim()).is_some())
                && node
                    .field("right")
                    .is_some_and(|right| matches!(right.text().trim(), "1" | "true" | "TRUE"))
        })?;
    let flag = assignment.field("left")?.text().trim().to_string();
    let search_root = statement
        .ancestors()
        .find(|node| node.kind().as_ref() == "function_definition")
        .unwrap_or_else(|| root.clone());
    let symbol = enclosing_symbol(statement);
    let rejecting_use = search_root
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| node.range().start > statement.range().end)
        .filter(|node| node.range().start.saturating_sub(statement.range().end) < 32_768)
        .filter(|node| enclosing_symbol(node) == symbol)
        .find(|node| {
            node.field("condition")
                .is_some_and(|condition| contains_identifier(condition.text().as_ref(), &flag))
                && node.field("consequence").is_some_and(|body| {
                    body.dfs()
                        .filter(|child| child.kind().as_ref() == "call_expression")
                        .filter_map(|call| call.field("function"))
                        .any(|callee| is_rejecting_callee(callee.text().as_ref()))
                })
        })?;
    Some((rejecting_use, flag))
}

fn selected_validation_branch(
    availability: &mehscan_core::Availability,
    build_symbols: &BTreeMap<String, bool>,
) -> bool {
    match availability.state {
        AvailabilityState::Always => true,
        AvailabilityState::Excluded | AvailabilityState::Unknown => false,
        AvailabilityState::Conditional => {
            availability.condition.as_deref().is_some_and(|condition| {
                let mentioned = identifiers(condition)
                    .filter_map(|symbol| build_symbols.get(symbol))
                    .copied()
                    .collect::<Vec<_>>();
                mentioned.iter().any(|value| *value) && mentioned.iter().all(|value| *value)
            })
        }
    }
}

fn size_local(declaration: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let declaration_text = declaration.text();
    let prefix = declaration_text.split([';', '=']).next()?;
    if !identifiers(prefix).any(|name| name == "size_t") {
        return None;
    }
    declaration
        .dfs()
        .find(|node| node.kind().as_ref() == "identifier")
        .map(|node| node.text().into_owned())
        .filter(|name| name != "size_t")
}

fn allocation_calculation<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    declaration: &Node<'tree, StrDoc<SupportLang>>,
    local: &str,
) -> Option<AllocationCalculation<'tree>> {
    let symbol = enclosing_symbol(declaration);
    let mut assignments = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| node.range().start > declaration.range().start)
        .filter(|node| enclosing_symbol(node) == symbol)
        .filter(|node| {
            node.field("left")
                .is_some_and(|left| left.text().trim() == local)
        });
    let aligned_input = assignments.find(|node| {
        node.field("right").is_some_and(|right| {
            let text = right.text();
            text.contains('&') && text.contains('+') && member_name(text.as_ref()).is_some()
        })
    })?;
    let input_member = member_name(aligned_input.field("right")?.text().as_ref())?;
    let computation = assignments.find(|node| {
        node.range().start > aligned_input.range().end
            && node.field("right").is_some_and(|right| {
                contains_identifier(right.text().as_ref(), local)
                    && right.dfs().any(|call| macro_call_uses_local(&call, local))
            })
    })?;
    let macro_call = computation
        .field("right")?
        .dfs()
        .find(|node| macro_call_uses_local(node, local))?;
    let allocation = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| node.range().start > computation.range().end)
        .filter(|node| enclosing_symbol(node) == symbol)
        .find(|node| {
            node.field("function").is_some_and(|function| {
                let name = function.text().to_ascii_lowercase();
                name.contains("malloc") || name.contains("alloc") || name.contains("realloc")
            }) && node
                .field("arguments")
                .is_some_and(|arguments| contains_identifier(arguments.text().as_ref(), local))
        })?;
    Some(AllocationCalculation {
        aligned_input,
        computation,
        macro_call,
        allocation,
        input_member,
    })
}

fn macro_call_uses_local(node: &Node<'_, StrDoc<SupportLang>>, local: &str) -> bool {
    if node.kind().as_ref() != "call_expression" {
        return false;
    }
    let Some(function) = node.field("function") else {
        return false;
    };
    let name = function.text();
    is_constant_identifier(name.as_ref())
        && node.field("arguments").is_some_and(|arguments| {
            contains_identifier(arguments.text().as_ref(), local)
                && arguments
                    .children()
                    .filter(|child| child.is_named())
                    .count()
                    >= 2
        })
}

fn member_name(text: &str) -> Option<String> {
    for separator in ["->", "."] {
        if let Some((_, tail)) = text.rsplit_once(separator) {
            let name = identifiers(tail).next()?;
            return Some(name.to_string());
        }
    }
    None
}

fn architecture_input_evidence<'tree>(
    path: &str,
    condition: &Node<'tree, StrDoc<SupportLang>>,
    input: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, INPUT_RULE_ID, condition),
        kind: EvidenceKind::Source,
        capability: Capability::ArchitectureSizeInput,
        location: location(path, condition),
        enclosing_symbol: enclosing_symbol(condition),
        captures: BTreeMap::from([
            ("input".to_string(), text_capture(path, condition, input)),
            ("architecture_limit".to_string(), capture(path, condition)),
        ]),
        cwe_candidates: cwes(),
        tags: vec![
            "native".to_string(),
            "architecture-sized-input-boundary".to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(condition, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: INPUT_RULE_ID.to_string(),
        related_evidence: Vec::new(),
    }
}

#[allow(clippy::too_many_arguments)]
fn validation_evidence<'tree>(
    path: &str,
    rejecting_use: &Node<'tree, StrDoc<SupportLang>>,
    input: &str,
    flag: &str,
    source: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, VALIDATION_RULE_ID, rejecting_use),
        kind: EvidenceKind::Validation,
        capability: Capability::ArchitectureSizeValidation,
        location: location(path, rejecting_use),
        enclosing_symbol: enclosing_symbol(rejecting_use),
        captures: BTreeMap::from([
            (
                "input".to_string(),
                text_capture(path, rejecting_use, input),
            ),
            (
                "rejection_flag".to_string(),
                text_capture(path, rejecting_use, flag),
            ),
            ("rejection".to_string(), capture(path, rejecting_use)),
        ]),
        cwe_candidates: cwes(),
        tags: vec![
            "native".to_string(),
            "exact-architecture-limit-rejection".to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(rejecting_use, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: VALIDATION_RULE_ID.to_string(),
        related_evidence: vec![source.id.clone()],
    }
}

fn allocation_evidence<'tree>(
    path: &str,
    calculation: &AllocationCalculation<'tree>,
    local: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, COMPUTATION_RULE_ID, &calculation.computation),
        kind: EvidenceKind::Sink,
        capability: Capability::AllocationSizeComputation,
        location: location(path, &calculation.computation),
        enclosing_symbol: enclosing_symbol(&calculation.computation),
        captures: BTreeMap::from([
            (
                "allocation_size".to_string(),
                text_capture(path, &calculation.computation, local),
            ),
            (
                "input_member".to_string(),
                text_capture(path, &calculation.aligned_input, &calculation.input_member),
            ),
            (
                "aligned_input".to_string(),
                capture(path, &calculation.aligned_input),
            ),
            (
                "size_macro".to_string(),
                capture(path, &calculation.macro_call),
            ),
            (
                "size_computation".to_string(),
                capture(path, &calculation.computation),
            ),
            (
                "allocation".to_string(),
                capture(path, &calculation.allocation),
            ),
        ]),
        cwe_candidates: cwes(),
        tags: vec![
            "native".to_string(),
            "macro-derived-allocation-size".to_string(),
            "architecture-width-sensitive".to_string(),
            "value-handoff:same-size-local".to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(&calculation.computation, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: COMPUTATION_RULE_ID.to_string(),
        related_evidence: Vec::new(),
    }
}

pub(crate) fn link_native_allocation_paths(evidence: &mut Vec<Evidence>) -> Vec<SecurityPath> {
    let sources = evidence
        .iter()
        .filter(|item| item.capability == Capability::ArchitectureSizeInput)
        .cloned()
        .collect::<Vec<_>>();
    let validations = evidence
        .iter()
        .filter(|item| item.capability == Capability::ArchitectureSizeValidation)
        .cloned()
        .collect::<Vec<_>>();
    let sinks = evidence
        .iter()
        .filter(|item| item.capability == Capability::AllocationSizeComputation)
        .cloned()
        .collect::<Vec<_>>();
    let mut paths = Vec::new();
    for source in &sources {
        let Some(input) = source
            .captures
            .get("input")
            .map(|capture| capture.text.as_str())
        else {
            continue;
        };
        for sink in sinks.iter().filter(|sink| {
            same_c_family_language(&source.location.path, &sink.location.path)
                && sink
                    .captures
                    .get("input_member")
                    .is_some_and(|capture| capture.text == input)
        }) {
            let protection = validations.iter().find(|validation| {
                validation
                    .related_evidence
                    .iter()
                    .any(|id| id == &source.id)
            });
            if let Some(item) = evidence.iter_mut().find(|item| item.id == sink.id) {
                item.related_evidence.push(source.id.clone());
                if let Some(protection) = protection {
                    item.related_evidence.push(protection.id.clone());
                    item.tags.push("architecture-limit:validated".to_string());
                } else {
                    item.tags.push("architecture-limit:unproven".to_string());
                }
                item.related_evidence.sort();
                item.related_evidence.dedup();
                item.tags.sort();
                item.tags.dedup();
            }
            paths.push(allocation_path(source, sink, protection));
        }
    }
    paths.sort_by(|left, right| left.id.cmp(&right.id));
    paths.dedup_by(|left, right| left.id == right.id);
    let retained = paths
        .iter()
        .flat_map(|path| {
            std::iter::once(path.source_evidence_id.as_str())
                .chain(std::iter::once(path.sink_evidence_id.as_str()))
                .chain(path.protection_evidence_ids.iter().map(String::as_str))
        })
        .collect::<std::collections::BTreeSet<_>>();
    evidence.retain(|item| {
        !matches!(
            item.capability,
            Capability::ArchitectureSizeInput
                | Capability::AllocationSizeComputation
                | Capability::ArchitectureSizeValidation
        ) || retained.contains(item.id.as_str())
    });
    paths
}

fn same_c_family_language(left: &str, right: &str) -> bool {
    fn family(path: &str) -> Option<bool> {
        let extension = path.rsplit_once('.')?.1.to_ascii_lowercase();
        match extension.as_str() {
            "c" => Some(false),
            "cc" | "cpp" | "cxx" | "c++" | "hpp" | "hh" | "hxx" => Some(true),
            "h" => None,
            _ => None,
        }
    }
    match (family(left), family(right)) {
        (Some(left), Some(right)) => left == right,
        _ => true,
    }
}

fn allocation_path(
    source: &Evidence,
    sink: &Evidence,
    protection: Option<&Evidence>,
) -> SecurityPath {
    let state = if protection.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
    if let Some(protection) = protection {
        steps.push(evidence_step(SecurityPathStepKind::Protection, protection));
    }
    steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: path_id(source, sink, state, &steps),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::AllocationSizeComputation,
        cwe_candidates: cwes(),
        state,
        steps,
        protection_evidence_ids: protection
            .map(|item| vec![item.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: if protection.is_some() {
            Vec::new()
        } else {
            vec![
                "architecture_size_limit_rejection_not_proven".to_string(),
                "macro_expansion_and_target_size_width_require_confirmation".to_string(),
                "cross_function_input_state_handoff_requires_confirmation".to_string(),
            ]
        },
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family allocation-size relationship 1".to_string(),
            maximum_propagation_depth: 2,
        },
    }
}

fn is_rejecting_callee(name: &str) -> bool {
    let name = name.to_ascii_lowercase();
    ["error", "fatal", "abort", "panic"]
        .iter()
        .any(|part| name.contains(part))
}

fn cwes() -> Vec<String> {
    vec!["CWE-190".to_string(), "CWE-680".to_string()]
}

fn provenance() -> Provenance {
    Provenance {
        resolution: Resolution::Ast,
        engine: ENGINE.to_string(),
        rule_version: 1,
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
        literals: BTreeMap::new(),
        secret: None,
        value_transform: None,
        http_routes: Vec::new(),
        resource_policy: None,
        runtime_environment: None,
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

fn evidence_id(path: &str, rule_id: &str, node: &Node<'_, StrDoc<SupportLang>>) -> String {
    stable_id(
        "ev",
        &format!(
            "{path}\0{rule_id}\0{}\0{}",
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

fn evidence_step(kind: SecurityPathStepKind, evidence: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: evidence.location.clone(),
        evidence_id: Some(evidence.id.clone()),
        symbol: evidence.enclosing_symbol.clone(),
    }
}

fn identifiers(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|character: char| character != '_' && !character.is_ascii_alphanumeric())
        .filter(|token| simple_identifier(token).is_some())
}

fn contains_identifier(text: &str, name: &str) -> bool {
    identifiers(text).any(|candidate| candidate == name)
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

fn is_constant_identifier(value: &str) -> bool {
    value.len() > 2
        && value.chars().any(|character| character == '_')
        && value.chars().all(|character| {
            character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
        })
}

fn is_type_word(value: &str) -> bool {
    matches!(
        value,
        "char"
            | "short"
            | "int"
            | "long"
            | "signed"
            | "unsigned"
            | "size_t"
            | "uint32_t"
            | "uint64_t"
            | "const"
            | "struct"
    )
}
