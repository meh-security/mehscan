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

const INPUT_RULE_ID: &str = "c-family-domain-limited-input-quantity";
const LIMIT_RULE_ID: &str = "c-family-derived-domain-limit";
const VALIDATION_RULE_ID: &str = "c-family-derived-domain-limit-validation";
const SINK_RULE_ID: &str = "c-family-count-controlled-memory-operation";
const ENGINE: &str = "tree-sitter c-family domain-bound relationship";

pub(crate) fn add_native_domain_bound_observations<'tree>(
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
    let function_declarators = root
        .dfs()
        .filter(|node| node.kind().as_ref() == "function_declarator")
        .collect::<Vec<_>>();
    for (index, function) in function_declarators.iter().enumerate() {
        let scope_start = function.range().start;
        let scope_end = function_declarators
            .get(index + 1)
            .map(|next| next.range().start)
            .unwrap_or_else(|| root.range().end);
        let parameters = parameter_names(function);
        for limit in derived_limits(root, scope_start, scope_end) {
            for sink_node in root
                .dfs()
                .filter(|node| node.kind().as_ref() == "call_expression")
                .filter(|node| {
                    node.range().start > limit.declaration.range().end
                        && node.range().end < scope_end
                })
                .filter(|node| is_memory_operation(node))
            {
                if comments.is_in_comment(sink_node.range()) {
                    continue;
                }
                let Some(size_argument) = sink_node.field("arguments").and_then(|arguments| {
                    arguments.children().filter(|node| node.is_named()).last()
                }) else {
                    continue;
                };
                let size_text = size_argument.text();
                let Some(count) = parameters.iter().find(|name| {
                    contains_identifier(size_text.as_ref(), name) && size_text.contains('*')
                }) else {
                    continue;
                };
                let sink = memory_sink_evidence(
                    path,
                    &sink_node,
                    count,
                    &limit,
                    comments,
                    conditional,
                    literals,
                );
                push_unique(&mut additions, sink.clone());
                push_unique(
                    &mut additions,
                    limit_evidence(path, &limit, comments, conditional, literals),
                );

                for comparison in upper_bound_comparisons(root, &limit, count, &sink_node) {
                    let source = input_evidence(
                        path,
                        &comparison,
                        count,
                        &limit,
                        comments,
                        conditional,
                        literals,
                    );
                    if is_excluded(&source) {
                        push_unique(&mut additions, source);
                        continue;
                    }
                    let protection = comparison.exact.then(|| {
                        validation_evidence(
                            path,
                            &comparison,
                            count,
                            &limit,
                            comments,
                            conditional,
                            literals,
                        )
                    });
                    paths.push(domain_bound_path(&source, &sink, protection.as_ref()));
                    push_unique(&mut additions, source);
                    if let Some(protection) = protection {
                        push_unique(&mut additions, protection);
                    }
                }
            }
        }
    }
    evidence.extend(additions);
    paths
}

#[derive(Clone)]
struct DerivedLimit<'tree> {
    declaration: Node<'tree, StrDoc<SupportLang>>,
    value: Node<'tree, StrDoc<SupportLang>>,
    name: String,
}

#[derive(Clone)]
struct BoundComparison<'tree> {
    comparison: Node<'tree, StrDoc<SupportLang>>,
    left: Node<'tree, StrDoc<SupportLang>>,
    right: Node<'tree, StrDoc<SupportLang>>,
    exact: bool,
}

fn derived_limits<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    scope_start: usize,
    scope_end: usize,
) -> Vec<DerivedLimit<'tree>> {
    let mut limits = root
        .dfs()
        .filter_map(|declaration| {
            if declaration.kind().as_ref() != "declaration" {
                return None;
            }
            if declaration.range().start <= scope_start || declaration.range().end >= scope_end {
                return None;
            }
            let init = declaration
                .children()
                .find(|child| child.kind().as_ref() == "init_declarator")?;
            let declarator = init.field("declarator")?;
            let name = simple_identifier(declarator.text().trim())?.to_string();
            let value = unwrap_parentheses(init.field("value")?);
            if value.kind().as_ref() != "conditional_expression" {
                return None;
            }
            let text = value.text();
            let has_state_derived_part = value.dfs().any(|node| {
                matches!(
                    node.kind().as_ref(),
                    "field_expression" | "subscript_expression"
                )
            });
            let has_fixed_maximum = identifiers(text.as_ref()).any(is_constant_identifier);
            (has_state_derived_part && has_fixed_maximum).then_some(DerivedLimit {
                declaration,
                value,
                name,
            })
        })
        .collect::<Vec<_>>();

    limits.extend(root.dfs().filter_map(|assignment| {
        if assignment.kind().as_ref() != "assignment_expression" {
            return None;
        }
        if assignment.range().start <= scope_start || assignment.range().end >= scope_end {
            return None;
        }
        let left = unwrap_parentheses(assignment.field("left")?);
        let name = simple_identifier(left.text().trim())?.to_string();
        let value = unwrap_parentheses(assignment.field("right")?);
        if value.kind().as_ref() != "conditional_expression"
            || !has_preceding_declaration(root, &assignment, &name, scope_start)
        {
            return None;
        }
        let text = value.text();
        let has_state_derived_part = value.dfs().any(|node| {
            matches!(
                node.kind().as_ref(),
                "field_expression" | "subscript_expression"
            )
        });
        let has_fixed_maximum = identifiers(text.as_ref()).any(is_constant_identifier);
        (has_state_derived_part && has_fixed_maximum).then_some(DerivedLimit {
            declaration: assignment,
            value,
            name,
        })
    }));
    limits.sort_by_key(|limit| limit.declaration.range().start);
    limits
}

fn has_preceding_declaration(
    function: &Node<'_, StrDoc<SupportLang>>,
    assignment: &Node<'_, StrDoc<SupportLang>>,
    name: &str,
    scope_start: usize,
) -> bool {
    function
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "declaration"
                && node.range().start > scope_start
                && node.range().end < assignment.range().start
        })
        .any(|declaration| {
            declaration
                .dfs()
                .any(|node| node.kind().as_ref() == "identifier" && node.text().trim() == name)
        })
}

fn parameter_names(function: &Node<'_, StrDoc<SupportLang>>) -> Vec<String> {
    function
        .dfs()
        .filter(|node| node.kind().as_ref() == "parameter_declaration")
        .filter_map(|parameter| parameter.field("declarator"))
        .filter_map(|parameter_declarator| {
            parameter_declarator
                .dfs()
                .filter(|node| node.kind().as_ref() == "identifier")
                .last()
                .map(|identifier| identifier.text().into_owned())
        })
        .collect()
}

fn is_memory_operation(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let Some(function) = node.field("function") else {
        return false;
    };
    matches!(
        function.text().trim(),
        "memcpy" | "memmove" | "memset" | "bcopy"
    )
}

fn upper_bound_comparisons<'tree>(
    function: &Node<'tree, StrDoc<SupportLang>>,
    limit: &DerivedLimit<'tree>,
    count: &str,
    sink: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<BoundComparison<'tree>> {
    function
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| {
            node.range().start > limit.declaration.range().end
                && node.range().end < sink.range().start
        })
        .filter_map(|statement| {
            let rejecting = statement
                .field("consequence")
                .is_some_and(|consequence| is_rejecting_consequence(&consequence))
                || has_rejection_between(function, &statement, sink);
            if !rejecting {
                return None;
            }
            let condition = statement.field("condition")?;
            condition.dfs().find_map(|comparison| {
                if comparison.kind().as_ref() != "binary_expression"
                    || binary_operator(&comparison).as_deref() != Some(">")
                {
                    return None;
                }
                let left = unwrap_parentheses(comparison.field("left")?);
                let right = unwrap_parentheses(comparison.field("right")?);
                let exact = expression_references_only_limit(&right, &limit.name);
                let right_text = right.text();
                let is_named_maximum = identifiers(right_text.as_ref()).any(is_constant_identifier);
                (left.text().trim() == count && (exact || is_named_maximum)).then_some(
                    BoundComparison {
                        exact,
                        comparison,
                        left,
                        right,
                    },
                )
            })
        })
        .collect()
}

fn has_rejection_between(
    root: &Node<'_, StrDoc<SupportLang>>,
    comparison_statement: &Node<'_, StrDoc<SupportLang>>,
    sink: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    root.dfs()
        .filter(|node| {
            node.range().start > comparison_statement.range().end
                && node.range().end < sink.range().start
        })
        .any(|node| {
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

fn is_rejecting_consequence(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if node.kind().as_ref() == "return_statement" {
        return true;
    }
    node.dfs().any(|child| {
        if child.kind().as_ref() == "return_statement" {
            return true;
        }
        if child.kind().as_ref() != "call_expression" {
            return false;
        }
        child.field("function").is_some_and(|function| {
            let name = function.text().to_ascii_lowercase();
            ["error", "fatal", "abort", "panic"]
                .iter()
                .any(|part| name.contains(part))
        })
    })
}

fn expression_references_only_limit(node: &Node<'_, StrDoc<SupportLang>>, limit: &str) -> bool {
    let text = node.text();
    let names = identifiers(text.as_ref())
        .filter(|name| !is_type_word(name))
        .collect::<Vec<_>>();
    names.len() == 1 && names[0] == limit
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
    )
}

fn binary_operator(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let left = node.field("left")?;
    let right = node.field("right")?;
    node.text()
        .get(left.range().end - node.range().start..right.range().start - node.range().start)
        .map(str::trim)
        .map(str::to_string)
}

fn input_evidence<'tree>(
    path: &str,
    comparison: &BoundComparison<'tree>,
    count: &str,
    limit: &DerivedLimit<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, INPUT_RULE_ID, &comparison.comparison),
        kind: EvidenceKind::Source,
        capability: Capability::InputQuantity,
        location: location(path, &comparison.left),
        enclosing_symbol: enclosing_symbol(&comparison.comparison),
        captures: BTreeMap::from([
            ("quantity".to_string(), capture(path, &comparison.left)),
            (
                "applied_upper_bound".to_string(),
                capture(path, &comparison.right),
            ),
            (
                "derived_upper_bound".to_string(),
                Capture {
                    text: limit.name.clone(),
                    location: location(path, &limit.declaration),
                },
            ),
        ]),
        cwe_candidates: vec!["CWE-1284".to_string(), "CWE-805".to_string()],
        tags: vec![
            "native".to_string(),
            "domain-limited-quantity".to_string(),
            if comparison.exact {
                "upper-bound:derived-limit"
            } else {
                "upper-bound:differs-from-derived-limit"
            }
            .to_string(),
            "parse-recovery:locally-complete".to_string(),
            format!("quantity:{count}"),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(&comparison.comparison, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: INPUT_RULE_ID.to_string(),
        related_evidence: vec![evidence_id(path, LIMIT_RULE_ID, &limit.declaration)],
    }
}

fn limit_evidence<'tree>(
    path: &str,
    limit: &DerivedLimit<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, LIMIT_RULE_ID, &limit.declaration),
        kind: EvidenceKind::Resource,
        capability: Capability::DomainLimitComputation,
        location: location(path, &limit.value),
        enclosing_symbol: enclosing_symbol(&limit.declaration),
        captures: BTreeMap::from([
            (
                "limit".to_string(),
                Capture {
                    text: limit.name.clone(),
                    location: location(path, &limit.declaration),
                },
            ),
            ("expression".to_string(), capture(path, &limit.value)),
        ]),
        cwe_candidates: vec!["CWE-1284".to_string()],
        tags: vec![
            "native".to_string(),
            "state-derived-domain-limit".to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(&limit.declaration, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: LIMIT_RULE_ID.to_string(),
        related_evidence: Vec::new(),
    }
}

fn validation_evidence<'tree>(
    path: &str,
    comparison: &BoundComparison<'tree>,
    count: &str,
    limit: &DerivedLimit<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, VALIDATION_RULE_ID, &comparison.comparison),
        kind: EvidenceKind::Validation,
        capability: Capability::DomainLimitValidation,
        location: location(path, &comparison.comparison),
        enclosing_symbol: enclosing_symbol(&comparison.comparison),
        captures: BTreeMap::from([
            (
                "quantity".to_string(),
                Capture {
                    text: count.to_string(),
                    location: location(path, &comparison.left),
                },
            ),
            ("limit".to_string(), capture(path, &comparison.right)),
        ]),
        cwe_candidates: vec!["CWE-1284".to_string(), "CWE-805".to_string()],
        tags: vec![
            "native".to_string(),
            "exact-derived-upper-bound-rejection".to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(&comparison.comparison, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: VALIDATION_RULE_ID.to_string(),
        related_evidence: vec![evidence_id(path, LIMIT_RULE_ID, &limit.declaration)],
    }
}

fn memory_sink_evidence<'tree>(
    path: &str,
    sink: &Node<'tree, StrDoc<SupportLang>>,
    count: &str,
    limit: &DerivedLimit<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, SINK_RULE_ID, sink),
        kind: EvidenceKind::Sink,
        capability: Capability::CountControlledMemoryOperation,
        location: location(path, sink),
        enclosing_symbol: enclosing_symbol(sink),
        captures: BTreeMap::from([
            ("operation".to_string(), capture(path, sink)),
            (
                "quantity".to_string(),
                Capture {
                    text: count.to_string(),
                    location: location(path, sink),
                },
            ),
        ]),
        cwe_candidates: vec!["CWE-805".to_string(), "CWE-1284".to_string()],
        tags: vec![
            "native".to_string(),
            "count-controls-memory-extent".to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(sink, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: SINK_RULE_ID.to_string(),
        related_evidence: vec![evidence_id(path, LIMIT_RULE_ID, &limit.declaration)],
    }
}

fn domain_bound_path(
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
        capability: Capability::CountControlledMemoryOperation,
        cwe_candidates: vec!["CWE-1284".to_string(), "CWE-805".to_string()],
        state,
        steps,
        protection_evidence_ids: protection
            .map(|item| vec![item.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: if protection.is_some() {
            vec!["derived_limit_expression_semantics_require_confirmation".to_string()]
        } else {
            vec![
                "applied_upper_bound_differs_from_derived_domain_limit".to_string(),
                "runtime_quantity_may_exceed_domain_limit".to_string(),
            ]
        },
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family domain-bound relationship 1".to_string(),
            maximum_propagation_depth: 1,
        },
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

fn unwrap_parentheses(mut node: Node<'_, StrDoc<SupportLang>>) -> Node<'_, StrDoc<SupportLang>> {
    while node.kind().as_ref() == "parenthesized_expression" {
        let Some(child) = node.children().find(|child| child.is_named()) else {
            break;
        };
        node = child;
    }
    node
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

fn identifiers(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|character: char| character != '_' && !character.is_ascii_alphanumeric())
        .filter(|token| simple_identifier(token).is_some())
}

fn is_constant_identifier(value: &str) -> bool {
    value.len() > 2
        && value.chars().any(|character| character == '_')
        && value.chars().all(|character| {
            character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
        })
}

fn contains_identifier(text: &str, name: &str) -> bool {
    identifiers(text).any(|candidate| candidate == name)
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
        symbol: None,
    }
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
