use std::collections::{BTreeMap, BTreeSet};

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

const SOURCE_RULE_ID: &str = "c-family-serialized-scalar-load";
const SINK_RULE_ID: &str = "c-family-loaded-memory-extent";
const VALIDATION_RULE_ID: &str = "c-family-loaded-memory-extent-overflow-validation";
const ENGINE: &str = "tree-sitter c-family loaded-memory-extent relationship";
const PATH_ENGINE: &str = "mehscan c-family loaded-memory-extent relationship 1";

struct Extent<'tree> {
    declaration: Node<'tree, StrDoc<SupportLang>>,
    expression: Node<'tree, StrDoc<SupportLang>>,
    name: String,
    operands: Vec<String>,
}

struct ScalarLoad<'tree> {
    binding: Node<'tree, StrDoc<SupportLang>>,
    call: Node<'tree, StrDoc<SupportLang>>,
    name: String,
}

struct MemoryUses<'tree> {
    allocation: Node<'tree, StrDoc<SupportLang>>,
    operation: Node<'tree, StrDoc<SupportLang>>,
}

pub(crate) fn add_native_loaded_extent_observations<'tree>(
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
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        let Some(extent) = extent_declaration(&declaration) else {
            continue;
        };
        let Some(scope) = declaration
            .ancestors()
            .find(|node| node.kind().as_ref() == "function_definition")
        else {
            continue;
        };
        let Some(load) = extent.operands.iter().find_map(|operand| {
            scalar_load(&scope, operand, extent.declaration.range().start, comments)
        }) else {
            continue;
        };
        let Some(uses) = memory_uses(&scope, &extent) else {
            continue;
        };
        if extent.operands.iter().any(|operand| {
            reassigned_between(
                &scope,
                operand,
                load.binding.range().end,
                extent.declaration.range().start,
            )
        }) {
            continue;
        }
        let validation = overflow_validation(&scope, &extent, &load);

        let source = make_evidence(
            path,
            &load.call,
            SOURCE_RULE_ID,
            EvidenceKind::Source,
            Capability::SerializedScalarLoad,
            BTreeMap::from([
                (
                    "loaded_scalar".to_string(),
                    text_capture(path, &load.binding, &load.name),
                ),
                ("loader".to_string(), capture(path, &load.call)),
            ]),
            vec![
                "native",
                "serialized-scalar-loader",
                "parse-recovery:locally-complete",
            ],
            comments,
            conditional,
            literals,
            Vec::new(),
        );
        let protection = validation.as_ref().map(|guard| {
            make_evidence(
                path,
                guard,
                VALIDATION_RULE_ID,
                EvidenceKind::Validation,
                Capability::MemoryExtentOverflowValidation,
                BTreeMap::from([
                    (
                        "loaded_scalar".to_string(),
                        text_capture(path, guard, &load.name),
                    ),
                    (
                        "extent_operands".to_string(),
                        text_capture(path, guard, &extent.operands.join(", ")),
                    ),
                    ("rejecting_checks".to_string(), capture(path, guard)),
                ]),
                vec![
                    "native",
                    "zero-safe-size-max-rejection",
                    "pre-computation-validation",
                    "parse-recovery:locally-complete",
                ],
                comments,
                conditional,
                literals,
                vec![source.id.clone()],
            )
        });
        let mut related = vec![source.id.clone()];
        if let Some(protection) = &protection {
            related.push(protection.id.clone());
        }
        let sink = make_evidence(
            path,
            &extent.declaration,
            SINK_RULE_ID,
            EvidenceKind::Sink,
            Capability::LoadedMemoryExtent,
            BTreeMap::from([
                (
                    "extent".to_string(),
                    text_capture(path, &extent.declaration, &extent.name),
                ),
                (
                    "extent_computation".to_string(),
                    capture(path, &extent.expression),
                ),
                ("allocation".to_string(), capture(path, &uses.allocation)),
                (
                    "memory_operation".to_string(),
                    capture(path, &uses.operation),
                ),
            ]),
            vec![
                "native",
                "loaded-scalar-controls-memory-extent",
                if protection.is_some() {
                    "extent-overflow:validated"
                } else {
                    "extent-overflow:unproven"
                },
                "parse-recovery:locally-complete",
            ],
            comments,
            conditional,
            literals,
            related,
        );
        paths.push(extent_path(&source, &sink, protection.as_ref()));
        additions.push(source);
        additions.extend(protection);
        additions.push(sink);
    }
    evidence.extend(additions);
    paths
}

fn extent_declaration<'tree>(
    declaration: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<Extent<'tree>> {
    let init = declaration
        .children()
        .find(|node| node.kind().as_ref() == "init_declarator")?;
    let name = simple_identifier(init.field("declarator")?.text().trim())?.to_string();
    let expression = init.field("value")?;
    let compact_expression = compact(expression.text().as_ref());
    if !compact_expression.contains("sizeof")
        || compact_expression
            .chars()
            .filter(|character| *character == '*')
            .count()
            < 2
    {
        return None;
    }
    let operands = identifiers(expression.text().as_ref())
        .filter(|identifier| {
            !matches!(
                *identifier,
                "sizeof"
                    | "size_t"
                    | "float"
                    | "double"
                    | "char"
                    | "short"
                    | "int"
                    | "long"
                    | "signed"
                    | "unsigned"
            ) && !identifier.chars().all(|character| {
                character.is_ascii_uppercase() || character == '_' || character.is_ascii_digit()
            })
        })
        .map(str::to_string)
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    (operands.len() >= 2).then_some(Extent {
        declaration: declaration.clone(),
        expression,
        name,
        operands,
    })
}

fn scalar_load<'tree>(
    scope: &Node<'tree, StrDoc<SupportLang>>,
    expected: &str,
    before: usize,
    comments: &CommentRanges,
) -> Option<ScalarLoad<'tree>> {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "init_declarator")
        .filter(|node| node.range().start < before && !comments.is_in_comment(node.range()))
        .find_map(|binding| {
            let name = simple_identifier(binding.field("declarator")?.text().trim())?.to_string();
            (name == expected).then_some(())?;
            let value = binding.field("value")?;
            let call = value
                .dfs()
                .find(|node| node.kind().as_ref() == "call_expression")?;
            let callee = call.field("function")?.text().into_owned();
            is_scalar_loader(&callee).then_some(ScalarLoad {
                binding,
                call,
                name,
            })
        })
}

fn is_scalar_loader(callee: &str) -> bool {
    let name = callee.to_ascii_lowercase();
    ["load", "read", "decode", "parse"]
        .iter()
        .any(|part| name.contains(part))
        && [
            "unsigned",
            "integer",
            "uint",
            "count",
            "dimension",
            "dim",
            "size",
            "length",
            "len",
            "scalar",
            "number",
            "u32",
            "u64",
        ]
        .iter()
        .any(|part| name.contains(part))
        && !["buffer", "blob", "string", "bytes"]
            .iter()
            .any(|part| name.contains(part))
}

fn memory_uses<'tree>(
    scope: &Node<'tree, StrDoc<SupportLang>>,
    extent: &Extent<'tree>,
) -> Option<MemoryUses<'tree>> {
    let after = extent.declaration.range().end;
    let allocation = scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression" && node.range().start > after)
        .find(|call| {
            is_allocator(call)
                && named_arguments(call)
                    .iter()
                    .any(|arg| arg.text().trim() == extent.name)
        })?;
    let operation = scope
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "call_expression" && node.range().start > allocation.range().end
        })
        .find(|call| {
            is_memory_operation(call)
                && named_arguments(call)
                    .iter()
                    .any(|arg| arg.text().trim() == extent.name)
        })?;
    Some(MemoryUses {
        allocation,
        operation,
    })
}

fn overflow_validation<'tree>(
    scope: &Node<'tree, StrDoc<SupportLang>>,
    extent: &Extent<'tree>,
    load: &ScalarLoad<'tree>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let candidates = scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| {
            node.range().start > load.binding.range().end
                && node.range().end < extent.declaration.range().start
        })
        .filter(|node| {
            node.field("consequence")
                .is_some_and(|branch| branch_terminates(&branch))
        })
        .collect::<Vec<_>>();
    let zero_safe = extent.operands.iter().all(|operand| {
        candidates.iter().any(|statement| {
            let text = compact(
                statement
                    .field("condition")
                    .expect("condition")
                    .text()
                    .as_ref(),
            );
            text.contains(&format!("{operand}==0"))
                || text.contains(&format!("0=={operand}"))
                || text.contains(&format!("!{operand}"))
        })
    });
    if !zero_safe {
        return None;
    }
    candidates.into_iter().find(|statement| {
        let condition = statement.field("condition").expect("condition");
        let text = compact(condition.text().as_ref());
        if !text.contains(&load.name) || !text.contains('>') {
            return false;
        }
        if text.contains("SIZE_MAX/") {
            return true;
        }
        identifiers(condition.text().as_ref()).any(|bound| {
            bound != load.name
                && bound_local(scope, bound, statement.range().start, &extent.operands)
        })
    })
}

fn bound_local(
    scope: &Node<'_, StrDoc<SupportLang>>,
    bound: &str,
    before: usize,
    operands: &[String],
) -> bool {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "init_declarator" && node.range().start < before)
        .any(|node| {
            node.field("declarator")
                .is_some_and(|decl| decl.text().trim() == bound)
                && node.field("value").is_some_and(|value| {
                    let text = compact(value.text().as_ref());
                    text.contains("SIZE_MAX/")
                        && operands.iter().any(|operand| text.contains(operand))
                })
        })
}

fn reassigned_between(
    scope: &Node<'_, StrDoc<SupportLang>>,
    name: &str,
    after: usize,
    before: usize,
) -> bool {
    scope
        .dfs()
        .filter(|node| {
            node.kind().as_ref() == "assignment_expression"
                && node.range().start > after
                && node.range().end < before
        })
        .any(|node| {
            node.field("left")
                .is_some_and(|left| left.text().trim() == name)
        })
}

fn branch_terminates(branch: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if branch.dfs().any(|node| {
        matches!(
            node.kind().as_ref(),
            "return_statement" | "goto_statement" | "continue_statement" | "break_statement"
        )
    }) {
        let terminal = if branch.kind().as_ref() == "compound_statement" {
            branch.children().filter(|node| node.is_named()).last()
        } else {
            Some(branch.clone())
        };
        return terminal.is_some_and(|node| {
            matches!(
                node.kind().as_ref(),
                "return_statement" | "goto_statement" | "continue_statement" | "break_statement"
            )
        });
    }
    false
}

fn is_allocator(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    call.field("function").is_some_and(|function| {
        let name = function.text().to_ascii_lowercase();
        name.contains("alloc") || name.contains("malloc") || name.contains("realloc")
    })
}

fn is_memory_operation(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    call.field("function").is_some_and(|function| {
        matches!(
            function.text().trim(),
            "memcpy" | "memmove" | "memset" | "bcopy" | "fread"
        )
    })
}

fn named_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.field("arguments")
        .map(|args| args.children().filter(|node| node.is_named()).collect())
        .unwrap_or_default()
}

fn identifiers(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|character: char| !(character == '_' || character.is_ascii_alphanumeric()))
        .filter(|part| {
            part.chars()
                .next()
                .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        })
}

fn simple_identifier(value: &str) -> Option<&str> {
    let mut chars = value.chars();
    chars
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        .then_some(())?;
    chars
        .all(|character| character == '_' || character.is_ascii_alphanumeric())
        .then_some(value)
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace() && !matches!(*character, '(' | ')'))
        .collect()
}

fn extent_path(source: &Evidence, sink: &Evidence, protection: Option<&Evidence>) -> SecurityPath {
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
        id: stable_id(
            "path",
            &format!("{}\0{}\0{state:?}\0CWE-680", source.id, sink.id),
        ),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::LoadedMemoryExtent,
        cwe_candidates: cwes(),
        state,
        steps,
        protection_evidence_ids: protection
            .map(|item| vec![item.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: protection
            .is_none()
            .then(|| "loaded_memory_extent_overflow_not_proven_absent".to_string())
            .into_iter()
            .chain(["effective_operand_types_and_input_control_require_confirmation".to_string()])
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
    vec![
        "CWE-190".to_string(),
        "CWE-680".to_string(),
        "CWE-122".to_string(),
    ]
}
fn stable_id(prefix: &str, value: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}_{hash:016x}")
}
