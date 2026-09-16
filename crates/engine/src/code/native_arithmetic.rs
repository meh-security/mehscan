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

const NARROWING_RULE_ID: &str = "c-family-wide-to-u32-narrowing";
const DIVISION_RULE_ID: &str = "c-family-narrowed-divisor";
const VALIDATION_RULE_ID: &str = "c-family-narrowed-divisor-nonzero-validation";

pub(crate) fn add_native_arithmetic_observations<'tree>(
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
        let Some(narrowing) = narrowing_declaration(root, &declaration) else {
            continue;
        };
        let Some(division) = first_linked_division(root, &narrowing, comments) else {
            continue;
        };

        let source = narrowing_evidence(path, &narrowing, comments, conditional, literals);
        if is_excluded(&source) {
            additions.push(source);
            continue;
        }
        let mut sink = division_evidence(
            path,
            &division,
            &narrowing.result,
            &source,
            comments,
            conditional,
            literals,
        );
        let protection_node = nonzero_guard(root, &narrowing, &division);
        let protection = protection_node.as_ref().map(|guard| {
            nonzero_validation_evidence(
                path,
                guard,
                &narrowing.result,
                &sink,
                comments,
                conditional,
                literals,
            )
        });
        if let Some(protection) = &protection {
            sink.tags.push("divisor:nonzero-guarded".to_string());
            sink.related_evidence.push(protection.id.clone());
        } else {
            sink.tags.push("divisor:nonzero-unproven".to_string());
        }

        paths.push(arithmetic_path(&source, &sink, protection.as_ref()));
        additions.push(source);
        if let Some(protection) = protection {
            additions.push(protection);
        }
        additions.push(sink);
    }
    evidence.extend(additions);
    paths
}

struct Narrowing<'tree> {
    declaration: Node<'tree, StrDoc<SupportLang>>,
    cast: Node<'tree, StrDoc<SupportLang>>,
    operand: Node<'tree, StrDoc<SupportLang>>,
    target_type: Node<'tree, StrDoc<SupportLang>>,
    result: String,
    source_type: String,
    nominal_target_width: bool,
}

fn narrowing_declaration<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    declaration: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Narrowing<'tree>> {
    let init = declaration
        .children()
        .find(|child| child.kind().as_ref() == "init_declarator")?;
    let result_node = init.field("declarator")?;
    let result = simple_identifier(result_node.text().trim())?.to_string();
    let cast = unwrap_parentheses(init.field("value")?);
    if cast.kind().as_ref() != "cast_expression" {
        return None;
    }
    let target_type = cast.field("type")?;
    let target_type_text = normalize_type(target_type.text().as_ref());
    let nominal_target_width = is_nominal_unsigned_32(&target_type_text)?;
    let operand = unwrap_parentheses(cast.field("value")?);
    let operand_text = operand.text();
    let operand_name = simple_identifier(operand_text.trim())?;
    let source_type = preceding_local_type(root, declaration, operand_name)?;
    if !is_wide_unsigned_source(&source_type) {
        return None;
    }
    Some(Narrowing {
        declaration: declaration.clone(),
        cast,
        operand,
        target_type,
        result,
        source_type,
        nominal_target_width,
    })
}

fn preceding_local_type(
    root: &Node<'_, StrDoc<SupportLang>>,
    use_declaration: &Node<'_, StrDoc<SupportLang>>,
    name: &str,
) -> Option<String> {
    let symbol = enclosing_symbol(use_declaration);
    root.dfs()
        .filter(|node| node.kind().as_ref() == "declaration")
        .filter(|node| node.range().end <= use_declaration.range().start)
        .filter(|node| enclosing_symbol(node) == symbol)
        .filter_map(|node| {
            let declared = node
                .children()
                .find_map(|child| match child.kind().as_ref() {
                    "init_declarator" => child.field("declarator"),
                    "identifier" => Some(child),
                    _ => None,
                })?;
            (declared.text().trim() == name).then(|| {
                node.field("type")
                    .map(|value| normalize_type(value.text().as_ref()))
                    .unwrap_or_else(|| declaration_prefix_type(&node, &declared))
            })
        })
        .last()
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

fn first_linked_division<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    narrowing: &Narrowing<'tree>,
    comments: &CommentRanges,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let symbol = enclosing_symbol(&narrowing.declaration);
    root.dfs()
        .filter(|node| node.kind().as_ref() == "binary_expression")
        .filter(|node| node.range().start > narrowing.declaration.range().end)
        .filter(|node| enclosing_symbol(node) == symbol)
        .filter(|node| !comments.is_in_comment(node.range()))
        .filter(|node| binary_operator(node).as_deref() == Some("/"))
        .filter(|node| {
            node.field("right")
                .and_then(|right| simple_identifier(right.text().trim()).map(str::to_string))
                .as_deref()
                == Some(narrowing.result.as_str())
        })
        .find(|division| {
            !is_reassigned_between(
                root,
                &narrowing.result,
                narrowing.declaration.range().end,
                division.range().start,
                symbol.as_deref(),
            )
        })
}

fn binary_operator(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let left = node.field("left")?;
    let right = node.field("right")?;
    node.text()
        .get(left.range().end - node.range().start..right.range().start - node.range().start)
        .map(str::trim)
        .map(str::to_string)
}

fn is_reassigned_between(
    root: &Node<'_, StrDoc<SupportLang>>,
    name: &str,
    start: usize,
    end: usize,
    symbol: Option<&str>,
) -> bool {
    root.dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| start < node.range().start && node.range().end < end)
        .filter(|node| enclosing_symbol(node).as_deref() == symbol)
        .filter_map(|node| node.field("left"))
        .any(|left| left.text().trim() == name)
}

fn nonzero_guard<'tree>(
    root: &Node<'tree, StrDoc<SupportLang>>,
    narrowing: &Narrowing<'tree>,
    division: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    for ancestor in division.ancestors() {
        if ancestor.kind().as_ref() != "if_statement" {
            continue;
        }
        let condition = ancestor.field("condition")?;
        if is_positive_nonzero_condition(condition.text().as_ref(), &narrowing.result) {
            return Some(condition);
        }
    }

    let symbol = enclosing_symbol(&narrowing.declaration);
    root.dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| {
            node.range().start > narrowing.declaration.range().end
                && node.range().end < division.range().start
        })
        .filter(|node| enclosing_symbol(node) == symbol)
        .find_map(|node| {
            let condition = node.field("condition")?;
            let consequence = node.field("consequence")?;
            (is_zero_condition(condition.text().as_ref(), &narrowing.result)
                && consequence
                    .dfs()
                    .any(|child| child.kind().as_ref() == "return_statement"))
            .then_some(condition)
        })
}

fn is_positive_nonzero_condition(text: &str, name: &str) -> bool {
    let value = compact_parentheses(text);
    matches!(
        value.as_str(),
        candidate if candidate == name
            || candidate == format!("{name}!=0")
            || candidate == format!("0!={name}")
            || candidate == format!("{name}>0")
    )
}

fn is_zero_condition(text: &str, name: &str) -> bool {
    let value = compact_parentheses(text);
    value == format!("{name}==0") || value == format!("0=={name}") || value == format!("!{name}")
}

fn compact_parentheses(value: &str) -> String {
    let mut value = value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect::<String>();
    while value.starts_with('(') && value.ends_with(')') && value.len() >= 2 {
        value = value[1..value.len() - 1].to_string();
    }
    value
}

fn is_nominal_unsigned_32(value: &str) -> Option<bool> {
    if matches!(value, "uint32_t" | "uint_least32_t" | "uint_fast32_t") {
        Some(false)
    } else if value.contains("uint32") || value.contains("uint_32") {
        Some(true)
    } else {
        None
    }
}

fn is_wide_unsigned_source(value: &str) -> bool {
    matches!(
        value,
        "size_t" | "uint64_t" | "uint_least64_t" | "uint_fast64_t" | "unsigned long long"
    )
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

fn unwrap_parentheses(mut node: Node<'_, StrDoc<SupportLang>>) -> Node<'_, StrDoc<SupportLang>> {
    while node.kind().as_ref() == "parenthesized_expression" {
        let Some(child) = node.children().find(|child| child.is_named()) else {
            break;
        };
        node = child;
    }
    node
}

fn narrowing_evidence<'tree>(
    path: &str,
    narrowing: &Narrowing<'tree>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    let mut captures = BTreeMap::new();
    captures.insert("value".to_string(), capture(path, &narrowing.operand));
    captures.insert(
        "target_type".to_string(),
        capture(path, &narrowing.target_type),
    );
    captures.insert(
        "result".to_string(),
        Capture {
            text: narrowing.result.clone(),
            location: location(path, &narrowing.declaration),
        },
    );
    captures.insert(
        "source_type".to_string(),
        Capture {
            text: narrowing.source_type.clone(),
            location: location(path, &narrowing.operand),
        },
    );
    Evidence {
        id: evidence_id(path, NARROWING_RULE_ID, &narrowing.cast),
        kind: EvidenceKind::Source,
        capability: Capability::IntegerNarrowing,
        location: location(path, &narrowing.cast),
        enclosing_symbol: enclosing_symbol(&narrowing.cast),
        captures,
        cwe_candidates: vec!["CWE-681".to_string(), "CWE-369".to_string()],
        tags: vec![
            "native".to_string(),
            "integer-conversion".to_string(),
            "parse-recovery:locally-complete".to_string(),
            if narrowing.nominal_target_width {
                "target-width:nominal-32"
            } else {
                "target-width:exact-32"
            }
            .to_string(),
        ],
        confidence: if narrowing.nominal_target_width {
            Confidence::Medium
        } else {
            Confidence::High
        },
        provenance: provenance(),
        context: evidence_context(&narrowing.cast, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: NARROWING_RULE_ID.to_string(),
        related_evidence: Vec::new(),
    }
}

fn division_evidence<'tree>(
    path: &str,
    division: &Node<'tree, StrDoc<SupportLang>>,
    result: &str,
    source: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    let divisor = division
        .field("right")
        .expect("linked division has a divisor");
    Evidence {
        id: evidence_id(path, DIVISION_RULE_ID, division),
        kind: EvidenceKind::Sink,
        capability: Capability::ArithmeticDivision,
        location: location(path, division),
        enclosing_symbol: enclosing_symbol(division),
        captures: BTreeMap::from([
            ("divisor".to_string(), capture(path, &divisor)),
            (
                "narrowed_result".to_string(),
                Capture {
                    text: result.to_string(),
                    location: capture(path, &divisor).location,
                },
            ),
        ]),
        cwe_candidates: vec!["CWE-369".to_string()],
        tags: vec![
            "native".to_string(),
            "arithmetic".to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(division, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: DIVISION_RULE_ID.to_string(),
        related_evidence: vec![source.id.clone()],
    }
}

fn nonzero_validation_evidence<'tree>(
    path: &str,
    guard: &Node<'tree, StrDoc<SupportLang>>,
    result: &str,
    sink: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    Evidence {
        id: evidence_id(path, VALIDATION_RULE_ID, guard),
        kind: EvidenceKind::Validation,
        capability: Capability::NonzeroValidation,
        location: location(path, guard),
        enclosing_symbol: enclosing_symbol(guard),
        captures: BTreeMap::from([(
            "divisor".to_string(),
            Capture {
                text: result.to_string(),
                location: location(path, guard),
            },
        )]),
        cwe_candidates: vec!["CWE-369".to_string()],
        tags: vec![
            "native".to_string(),
            "exact-local-nonzero-guard".to_string(),
            "parse-recovery:locally-complete".to_string(),
        ],
        confidence: Confidence::High,
        provenance: provenance(),
        context: evidence_context(guard, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: VALIDATION_RULE_ID.to_string(),
        related_evidence: vec![sink.id.clone()],
    }
}

fn arithmetic_path(
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
    let id = path_id(source, sink, state, &steps);
    SecurityPath {
        id,
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::ArithmeticDivision,
        cwe_candidates: vec!["CWE-369".to_string(), "CWE-681".to_string()],
        state,
        steps,
        protection_evidence_ids: protection
            .map(|item| vec![item.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: if protection.is_some() {
            vec!["integer_range_before_conversion_not_proven".to_string()]
        } else {
            vec![
                "integer_range_before_conversion_not_proven".to_string(),
                "converted_divisor_nonzero_invariant_unproven".to_string(),
            ]
        },
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family arithmetic relationship 1".to_string(),
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
        engine: "tree-sitter c-family arithmetic relationship".to_string(),
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
