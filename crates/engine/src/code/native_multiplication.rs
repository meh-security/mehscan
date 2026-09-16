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

const WIDTH_RULE_ID: &str = "c-family-fixed-width-arithmetic-accumulator";
const MULTIPLICATION_RULE_ID: &str = "c-family-memory-relevant-multiplication";
const VALIDATION_RULE_ID: &str = "c-family-multiplication-overflow-validation";
const ENGINE: &str = "tree-sitter c-family multiplication relationship";

pub(crate) fn add_native_multiplication_observations<'tree>(
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
    for declaration in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "declaration")
    {
        if comments.is_in_comment(declaration.range()) {
            continue;
        }
        let Some(accumulator) = fixed_width_accumulator(&declaration) else {
            continue;
        };
        let Some(multiplication) = linked_multiplication(root, &accumulator, comments) else {
            continue;
        };
        let Some(memory_use) = downstream_memory_use(root, &accumulator, &multiplication) else {
            continue;
        };

        let source = width_evidence(path, &accumulator, comments, conditional, literals);
        if is_excluded(&source) {
            additions.push(source);
            continue;
        }
        let mut sink = multiplication_evidence(
            path,
            &multiplication,
            &memory_use,
            &source,
            comments,
            conditional,
            literals,
        );
        let protection_node = overflow_guard(root, &accumulator, &multiplication);
        let protection = protection_node.as_ref().map(|guard| {
            overflow_validation_evidence(
                path,
                guard,
                &accumulator,
                &multiplication,
                comments,
                conditional,
                literals,
            )
        });
        if let Some(protection) = &protection {
            sink.tags.push("multiplication:range-guarded".to_string());
            sink.related_evidence.push(protection.id.clone());
        } else {
            sink.tags.push("multiplication:range-unproven".to_string());
        }

        paths.push(multiplication_path(
            &source,
            &sink,
            protection.as_ref(),
            &accumulator,
        ));
        additions.push(source);
        if let Some(protection) = protection {
            additions.push(protection);
        }
        additions.push(sink);
    }
    evidence.extend(additions);
    paths
}

struct Accumulator<'tree> {
    declaration: Node<'tree, StrDoc<SupportLang>>,
    initializer: Node<'tree, StrDoc<SupportLang>>,
    name: String,
    type_name: String,
    nominal_width: bool,
}

struct Multiplication<'tree> {
    expression: Node<'tree, StrDoc<SupportLang>>,
    multiplier: Node<'tree, StrDoc<SupportLang>>,
}

struct MemoryUse<'tree> {
    assignment: Node<'tree, StrDoc<SupportLang>>,
    intermediate: String,
    operation: Node<'tree, StrDoc<SupportLang>>,
}

fn fixed_width_accumulator<'tree>(
    declaration: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Accumulator<'tree>> {
    let init = declaration
        .children()
        .find(|child| child.kind().as_ref() == "init_declarator")?;
    let declarator = init.field("declarator")?;
    let name = simple_identifier(declarator.text().trim())?.to_string();
    let initializer = init.field("value")?;
    let type_name = declaration
        .field("type")
        .map(|node| normalize_type(node.text().as_ref()))
        .unwrap_or_else(|| declaration_prefix_type(declaration, &declarator));
    let nominal_width = is_unsigned_32_type(&type_name)?;
    Some(Accumulator {
        declaration: declaration.clone(),
        initializer,
        name,
        type_name,
        nominal_width,
    })
}

fn is_unsigned_32_type(value: &str) -> Option<bool> {
    if matches!(value, "uint32_t" | "uint_least32_t" | "uint_fast32_t") {
        Some(false)
    } else if value.contains("uint32") || value.contains("uint_32") {
        Some(true)
    } else {
        None
    }
}

fn linked_multiplication<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    accumulator: &Accumulator<'tree>,
    comments: &CommentRanges,
) -> Option<Multiplication<'tree>> {
    let symbol = enclosing_symbol(&accumulator.declaration);
    root.dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| node.range().start > accumulator.declaration.range().end)
        .filter(|node| enclosing_symbol(node) == symbol)
        .filter(|node| !comments.is_in_comment(node.range()))
        .find_map(|expression| {
            let left = expression.field("left")?;
            let right = expression.field("right")?;
            if left.text().trim() != accumulator.name
                || assignment_operator(&expression).as_deref() != Some("*=")
            {
                return None;
            }
            Some(Multiplication {
                expression,
                multiplier: right,
            })
        })
}

fn downstream_memory_use<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    accumulator: &Accumulator<'tree>,
    multiplication: &Multiplication<'tree>,
) -> Option<MemoryUse<'tree>> {
    let symbol = enclosing_symbol(&accumulator.declaration);
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| node.range().start > multiplication.expression.range().end)
        .filter(|node| enclosing_symbol(node) == symbol)
    {
        let Some(left) = assignment.field("left") else {
            continue;
        };
        let Some(right) = assignment.field("right") else {
            continue;
        };
        let left_text = left.text();
        let Some(intermediate) = simple_identifier(left_text.trim()) else {
            continue;
        };
        if intermediate == accumulator.name
            || !expression_is_cast_or_identifier(&right, &accumulator.name)
        {
            continue;
        }
        let Some(operation) = root
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
            .filter(|node| node.range().start > assignment.range().end)
            .filter(|node| enclosing_symbol(node) == symbol)
            .filter(|node| is_memory_operation(node))
            .find(|node| {
                memory_size_argument(node).is_some_and(|argument| {
                    contains_identifier(argument.text().as_ref(), intermediate)
                })
            })
        else {
            continue;
        };
        return Some(MemoryUse {
            assignment,
            intermediate: intermediate.to_string(),
            operation,
        });
    }
    None
}

fn expression_is_cast_or_identifier(node: &Node<'_, StrDoc<SupportLang>>, expected: &str) -> bool {
    let text = node.text();
    let names = identifiers(text.as_ref())
        .filter(|name| !is_type_word(name))
        .collect::<Vec<_>>();
    names.len() == 1 && names[0] == expected
}

fn overflow_guard<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    accumulator: &Accumulator<'tree>,
    multiplication: &Multiplication<'tree>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let symbol = enclosing_symbol(&accumulator.declaration);
    root.dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| {
            node.range().start > accumulator.declaration.range().end
                && node.range().end < multiplication.expression.range().start
        })
        .filter(|node| enclosing_symbol(node) == symbol)
        .find_map(|statement| {
            let condition = statement.field("condition")?;
            let consequence = statement.field("consequence")?;
            (is_rejecting_consequence(&consequence)
                && condition_rejects_zero(
                    condition.text().as_ref(),
                    multiplication.multiplier.text().trim(),
                )
                && condition.dfs().any(|comparison| {
                    multiplication_limit_comparison(
                        &comparison,
                        &accumulator.name,
                        multiplication.multiplier.text().trim(),
                    )
                }))
            .then_some(condition)
        })
}

fn condition_rejects_zero(condition: &str, multiplier: &str) -> bool {
    let compact = condition
        .chars()
        .filter(|character| !character.is_whitespace() && !matches!(*character, '(' | ')'))
        .collect::<String>();
    compact.contains(&format!("{multiplier}==0"))
        || compact.contains(&format!("0=={multiplier}"))
        || compact.starts_with(&format!("!{multiplier}||"))
        || compact.contains(&format!("||!{multiplier}||"))
}

fn multiplication_limit_comparison(
    comparison: &Node<'_, StrDoc<SupportLang>>,
    accumulator: &str,
    multiplier: &str,
) -> bool {
    if comparison.kind().as_ref() != "binary_expression"
        || binary_operator(comparison).as_deref() != Some(">")
    {
        return false;
    }
    let Some(left) = comparison.field("left") else {
        return false;
    };
    let Some(right) = comparison.field("right") else {
        return false;
    };
    if left.text().trim() != accumulator || binary_operator(&right).as_deref() != Some("/") {
        return false;
    }
    let Some(limit) = right.field("left") else {
        return false;
    };
    let Some(divisor) = right.field("right") else {
        return false;
    };
    identifiers(limit.text().as_ref()).any(is_constant_identifier)
        && divisor.text().trim() == multiplier
}

fn width_evidence<'tree>(
    path: &str,
    accumulator: &Accumulator<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, WIDTH_RULE_ID, &accumulator.declaration),
        kind: EvidenceKind::Source,
        capability: Capability::IntegerWidthConstraint,
        location: location(path, &accumulator.declaration),
        enclosing_symbol: enclosing_symbol(&accumulator.declaration),
        captures: BTreeMap::from([
            (
                "accumulator".to_string(),
                Capture {
                    text: accumulator.name.clone(),
                    location: location(path, &accumulator.declaration),
                },
            ),
            (
                "type".to_string(),
                Capture {
                    text: accumulator.type_name.clone(),
                    location: location(path, &accumulator.declaration),
                },
            ),
            (
                "initial_value".to_string(),
                capture(path, &accumulator.initializer),
            ),
        ]),
        cwe_candidates: vec!["CWE-190".to_string(), "CWE-680".to_string()],
        tags: vec![
            "native".to_string(),
            "fixed-width-arithmetic-accumulator".to_string(),
            if accumulator.nominal_width {
                "accumulator-width:nominal-32"
            } else {
                "accumulator-width:exact-32"
            }
            .to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: if accumulator.nominal_width {
            Confidence::Medium
        } else {
            Confidence::High
        },
        provenance: provenance(),
        context: evidence_context(&accumulator.declaration, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: WIDTH_RULE_ID.to_string(),
        related_evidence: Vec::new(),
    }
}

fn multiplication_evidence<'tree>(
    path: &str,
    multiplication: &Multiplication<'tree>,
    memory_use: &MemoryUse<'tree>,
    source: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, MULTIPLICATION_RULE_ID, &multiplication.expression),
        kind: EvidenceKind::Sink,
        capability: Capability::ArithmeticMultiplication,
        location: location(path, &multiplication.expression),
        enclosing_symbol: enclosing_symbol(&multiplication.expression),
        captures: BTreeMap::from([
            (
                "multiplication".to_string(),
                capture(path, &multiplication.expression),
            ),
            (
                "multiplier".to_string(),
                capture(path, &multiplication.multiplier),
            ),
            (
                "memory_extent_value".to_string(),
                Capture {
                    text: memory_use.intermediate.clone(),
                    location: location(path, &memory_use.assignment),
                },
            ),
            (
                "downstream_memory_operation".to_string(),
                capture(path, &memory_use.operation),
            ),
        ]),
        cwe_candidates: vec!["CWE-190".to_string(), "CWE-680".to_string()],
        tags: vec![
            "native".to_string(),
            "multiplication-controls-memory-extent".to_string(),
            "value-handoff:one-local-assignment".to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(&multiplication.expression, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: MULTIPLICATION_RULE_ID.to_string(),
        related_evidence: vec![source.id.clone()],
    }
}

fn overflow_validation_evidence<'tree>(
    path: &str,
    guard: &Node<'tree, StrDoc<SupportLang>>,
    accumulator: &Accumulator<'tree>,
    multiplication: &Multiplication<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, VALIDATION_RULE_ID, guard),
        kind: EvidenceKind::Validation,
        capability: Capability::MultiplicationOverflowValidation,
        location: location(path, guard),
        enclosing_symbol: enclosing_symbol(guard),
        captures: BTreeMap::from([
            (
                "accumulator".to_string(),
                Capture {
                    text: accumulator.name.clone(),
                    location: location(path, guard),
                },
            ),
            (
                "multiplier".to_string(),
                capture(path, &multiplication.multiplier),
            ),
            ("guard".to_string(), capture(path, guard)),
        ]),
        cwe_candidates: vec!["CWE-190".to_string(), "CWE-680".to_string()],
        tags: vec![
            "native".to_string(),
            "exact-pre-multiplication-range-check".to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(guard, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: VALIDATION_RULE_ID.to_string(),
        related_evidence: Vec::new(),
    }
}

fn multiplication_path(
    source: &Evidence,
    sink: &Evidence,
    protection: Option<&Evidence>,
    accumulator: &Accumulator<'_>,
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
        capability: Capability::ArithmeticMultiplication,
        cwe_candidates: vec!["CWE-190".to_string(), "CWE-680".to_string()],
        state,
        steps,
        protection_evidence_ids: protection
            .map(|item| vec![item.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: if protection.is_some() {
            accumulator
                .nominal_width
                .then(|| "accumulator_width_typedef_requires_confirmation".to_string())
                .into_iter()
                .collect()
        } else {
            let mut reasons = vec!["multiplication_range_not_proven".to_string()];
            if accumulator.nominal_width {
                reasons.push("accumulator_width_typedef_requires_confirmation".to_string());
            }
            reasons
        },
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family multiplication relationship 1".to_string(),
            maximum_propagation_depth: 1,
        },
    }
}

fn is_memory_operation(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.field("function").is_some_and(|function| {
        matches!(
            function.text().trim(),
            "memcpy" | "memmove" | "memset" | "bcopy"
        )
    })
}

fn memory_size_argument<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    node.field("arguments")?
        .children()
        .filter(|child| child.is_named())
        .last()
}

fn assignment_operator(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    binary_operator(node)
}

fn binary_operator(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let left = node.field("left")?;
    let right = node.field("right")?;
    node.text()
        .get(left.range().end - node.range().start..right.range().start - node.range().start)
        .map(str::trim)
        .map(str::to_string)
}

fn is_rejecting_consequence(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if node.kind().as_ref() == "return_statement" {
        return true;
    }
    node.dfs().any(|child| {
        child.kind().as_ref() == "return_statement"
            || child.kind().as_ref() == "call_expression"
                && child.field("function").is_some_and(|function| {
                    let name = function.text().to_ascii_lowercase();
                    ["error", "fatal", "abort", "panic"]
                        .iter()
                        .any(|part| name.contains(part))
                })
    })
}

fn declaration_prefix_type(
    declaration: &Node<'_, StrDoc<SupportLang>>,
    declarator: &Node<'_, StrDoc<SupportLang>>,
) -> String {
    let length = declarator
        .range()
        .start
        .saturating_sub(declaration.range().start);
    normalize_type(declaration.text().get(..length).unwrap_or_default())
}

fn normalize_type(value: &str) -> String {
    value
        .split_whitespace()
        .filter(|token| !matches!(*token, "const" | "volatile" | "register" | "static"))
        .collect::<Vec<_>>()
        .join(" ")
        .trim_matches(['(', ')'])
        .to_string()
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

fn contains_identifier(text: &str, name: &str) -> bool {
    identifiers(text).any(|candidate| candidate == name)
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

fn is_constant_identifier(value: &str) -> bool {
    value.len() > 2
        && value.chars().any(|character| character == '_')
        && value.chars().all(|character| {
            character == '_' || character.is_ascii_uppercase() || character.is_ascii_digit()
        })
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

fn is_excluded(evidence: &Evidence) -> bool {
    evidence
        .context
        .availability
        .as_ref()
        .is_some_and(|availability| availability.state == AvailabilityState::Excluded)
}
