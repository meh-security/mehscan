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

const ALLOCATION_RULE_ID: &str = "c-family-local-heap-allocation";
const RELEASE_RULE_ID: &str = "c-family-local-heap-deallocation";
const EARLY_RELEASE_RULE_ID: &str = "c-family-early-exit-deallocation";
const ENGINE: &str = "tree-sitter c-family local-heap-lifetime relationship";

pub(crate) fn add_native_heap_lifetime_observations<'tree>(
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
    for allocation_call in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| !comments.is_in_comment(node.range()))
        .filter(|node| is_allocator(node))
    {
        let Some((binding, local)) = allocation_binding(&allocation_call) else {
            continue;
        };
        let Some(scope) = allocation_call
            .ancestors()
            .find(|node| node.kind().as_ref() == "function_definition")
        else {
            continue;
        };
        let releases = scope
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
            .filter(|node| node.range().start > allocation_call.range().end)
            .filter(|node| exact_free(node, &local))
            .collect::<Vec<_>>();
        let Some(contract_release) = releases
            .iter()
            .rev()
            .find(|release| {
                is_unconditional_function_statement(release)
                    && availability_compatible(&allocation_call, release, conditional)
            })
            .cloned()
        else {
            continue;
        };
        if reassigned_between(
            &scope,
            &local,
            binding.range().end,
            contract_release.range().start,
        ) {
            continue;
        }
        let exits = scope
            .dfs()
            .filter(|node| node.kind().as_ref() == "return_statement")
            .filter(|node| node.range().start > binding.range().end)
            .filter(|node| node.range().end < contract_release.range().start)
            .filter(|node| is_controlled_exit(node))
            .filter(|node| !return_transfers_local(node, &local))
            .filter(|node| !null_allocation_exit(node, &local, &allocation_call))
            .filter(|node| !ownership_escaped_before(&scope, node, &local, binding.range().end))
            .filter(|node| availability_compatible(&allocation_call, node, conditional))
            .collect::<Vec<_>>();
        if exits.is_empty() {
            continue;
        }

        let source = allocation_evidence(
            path,
            &binding,
            &allocation_call,
            &local,
            comments,
            conditional,
            literals,
        );
        if excluded(&source) {
            continue;
        }
        let sink = release_evidence(
            path,
            &contract_release,
            &local,
            &source,
            comments,
            conditional,
            literals,
        );
        for exit in exits {
            let protection_call = releases.iter().find(|release| {
                release.range().start < exit.range().start
                    && same_immediate_block(release, &exit)
                    && availability_compatible(&exit, release, conditional)
            });
            let protection = protection_call.map(|release| {
                early_release_evidence(
                    path,
                    release,
                    &exit,
                    &local,
                    &sink,
                    comments,
                    conditional,
                    literals,
                )
            });
            paths.push(lifetime_path(&source, &sink, &exit, protection.as_ref()));
            if let Some(protection) = protection {
                additions.push(protection);
            }
        }
        additions.push(source);
        additions.push(sink);
    }
    evidence.extend(additions);
    paths
}

fn is_allocator(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    call.field("function").is_some_and(|function| {
        matches!(
            function.text().trim(),
            "malloc" | "calloc" | "realloc" | "aligned_alloc" | "strdup" | "strndup"
        )
    })
}

fn allocation_binding<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(Node<'tree, StrDoc<SupportLang>>, String)> {
    for ancestor in call.ancestors() {
        match ancestor.kind().as_ref() {
            "init_declarator" => {
                let value = ancestor.field("value")?;
                if contains(&value, call) {
                    let declarator = ancestor.field("declarator")?;
                    return simple_declarator_identifier(&declarator)
                        .map(|local| (ancestor, local));
                }
            }
            "assignment_expression" => {
                let right = ancestor.field("right")?;
                if contains(&right, call) {
                    let left = ancestor.field("left")?;
                    return simple_identifier(left.text().trim())
                        .map(|local| (ancestor, local.to_string()));
                }
            }
            "function_definition" => break,
            _ => {}
        }
    }
    None
}

fn simple_declarator_identifier(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    if node.kind().as_ref() == "identifier" {
        return Some(node.text().trim().to_string());
    }
    let identifiers = node
        .dfs()
        .filter(|child| child.kind().as_ref() == "identifier")
        .collect::<Vec<_>>();
    (identifiers.len() == 1).then(|| identifiers[0].text().trim().to_string())
}

fn exact_free(call: &Node<'_, StrDoc<SupportLang>>, local: &str) -> bool {
    if call
        .field("function")
        .is_none_or(|function| function.text().trim() != "free")
    {
        return false;
    }
    call.field("arguments").is_some_and(|arguments| {
        let named = arguments
            .children()
            .filter(|child| child.is_named())
            .collect::<Vec<_>>();
        named.len() == 1 && named[0].text().trim() == local
    })
}

fn is_unconditional_function_statement(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    !node
        .ancestors()
        .take_while(|ancestor| ancestor.kind().as_ref() != "function_definition")
        .any(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "if_statement"
                    | "for_statement"
                    | "while_statement"
                    | "do_statement"
                    | "switch_statement"
                    | "conditional_expression"
            )
        })
}

fn is_controlled_exit(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    node.ancestors()
        .take_while(|ancestor| ancestor.kind().as_ref() != "function_definition")
        .any(|ancestor| {
            matches!(
                ancestor.kind().as_ref(),
                "if_statement" | "switch_statement"
            )
        })
}

fn same_immediate_block(
    release: &Node<'_, StrDoc<SupportLang>>,
    exit: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let release_block = release
        .ancestors()
        .find(|node| node.kind().as_ref() == "compound_statement");
    let exit_block = exit
        .ancestors()
        .find(|node| node.kind().as_ref() == "compound_statement");
    release_block.zip(exit_block).is_some_and(|(left, right)| {
        left.range() == right.range()
            && !release
                .ancestors()
                .take_while(|node| node.range() != left.range())
                .any(|node| matches!(node.kind().as_ref(), "if_statement" | "switch_statement"))
    })
}

fn reassigned_between(
    scope: &Node<'_, StrDoc<SupportLang>>,
    local: &str,
    start: usize,
    end: usize,
) -> bool {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| start < node.range().start && node.range().end < end)
        .any(|node| {
            node.field("left")
                .is_some_and(|left| left.text().trim() == local)
        })
}

fn return_transfers_local(exit: &Node<'_, StrDoc<SupportLang>>, local: &str) -> bool {
    exit.dfs()
        .any(|node| node.kind().as_ref() == "identifier" && node.text().trim() == local)
}

fn null_allocation_exit(
    exit: &Node<'_, StrDoc<SupportLang>>,
    local: &str,
    allocation_call: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    let allocation_results = allocation_result_names(allocation_call, local);
    exit.ancestors()
        .take_while(|ancestor| ancestor.kind().as_ref() != "function_definition")
        .filter(|ancestor| ancestor.kind().as_ref() == "if_statement")
        .any(|statement| {
            let Some(consequence) = statement.field("consequence") else {
                return false;
            };
            if !contains(&consequence, exit) {
                return false;
            }
            statement.field("condition").is_some_and(|condition| {
                let value = compact(condition.text().as_ref());
                let direct_null_check = allocation_results.iter().any(|result| {
                    value == format!("!{result}")
                        || ["NULL", "nullptr", "0"].iter().any(|null| {
                            value == format!("{result}=={null}")
                                || value == format!("{null}=={result}")
                        })
                });
                let allocation_failure_check = condition
                    .dfs()
                    .filter(|node| node.kind().as_ref() == "assignment_expression")
                    .find(|assignment| {
                        assignment
                            .field("left")
                            .is_some_and(|left| left.text().trim() == local)
                            && assignment.field("right").is_some_and(|right| {
                                right.dfs().any(|candidate| is_allocator(&candidate))
                            })
                    })
                    .is_some_and(|assignment| {
                        let assignment = compact(assignment.text().as_ref());
                        value == format!("!{assignment}")
                            || ["NULL", "nullptr", "0"].iter().any(|null| {
                                value == format!("{assignment}=={null}")
                                    || value == format!("{null}=={assignment}")
                            })
                    });
                direct_null_check || allocation_failure_check
            })
        })
}

fn allocation_result_names(
    allocation_call: &Node<'_, StrDoc<SupportLang>>,
    local: &str,
) -> Vec<String> {
    let mut names = vec![local.to_string()];
    for ancestor in allocation_call.ancestors() {
        match ancestor.kind().as_ref() {
            "assignment_expression" => {
                if let Some(left) = ancestor
                    .field("left")
                    .and_then(|left| simple_identifier(left.text().trim()).map(str::to_string))
                {
                    names.push(left);
                }
            }
            "init_declarator" => {
                if let Some(declarator) = ancestor.field("declarator")
                    && let Some(name) = simple_declarator_identifier(&declarator)
                {
                    names.push(name);
                }
            }
            "declaration" | "expression_statement" => break,
            _ => {}
        }
    }
    names.sort();
    names.dedup();
    names
}

fn ownership_escaped_before(
    scope: &Node<'_, StrDoc<SupportLang>>,
    exit: &Node<'_, StrDoc<SupportLang>>,
    local: &str,
    allocation_end: usize,
) -> bool {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| allocation_end < node.range().start && node.range().end < exit.range().start)
        .any(|assignment| {
            assignment.field("left").is_some_and(|left| {
                matches!(
                    left.kind().as_ref(),
                    "field_expression" | "subscript_expression"
                )
            }) && assignment
                .field("right")
                .is_some_and(|right| right.text().trim() == local)
        })
}

fn availability_compatible(
    source: &Node<'_, StrDoc<SupportLang>>,
    other: &Node<'_, StrDoc<SupportLang>>,
    conditional: &ConditionalRegions,
) -> bool {
    let source = conditional.availability_for(source.range());
    let other = conditional.availability_for(other.range());
    match other.state {
        AvailabilityState::Always => true,
        AvailabilityState::Conditional | AvailabilityState::Unknown => other == source,
        AvailabilityState::Excluded => false,
    }
}

fn contains(parent: &Node<'_, StrDoc<SupportLang>>, child: &Node<'_, StrDoc<SupportLang>>) -> bool {
    parent.range().start <= child.range().start && child.range().end <= parent.range().end
}

#[allow(clippy::too_many_arguments)]
fn allocation_evidence<'tree>(
    path: &str,
    binding: &Node<'tree, StrDoc<SupportLang>>,
    call: &Node<'tree, StrDoc<SupportLang>>,
    local: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    make_evidence(
        path,
        binding,
        ALLOCATION_RULE_ID,
        EvidenceKind::Source,
        Capability::LocalHeapAllocation,
        BTreeMap::from([
            ("local".to_string(), text_capture(path, binding, local)),
            ("allocation".to_string(), capture(path, call)),
        ]),
        vec!["native", "local-heap-allocation"],
        comments,
        conditional,
        literals,
        Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn release_evidence<'tree>(
    path: &str,
    release: &Node<'tree, StrDoc<SupportLang>>,
    local: &str,
    source: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    make_evidence(
        path,
        release,
        RELEASE_RULE_ID,
        EvidenceKind::Sink,
        Capability::LocalHeapDeallocation,
        BTreeMap::from([
            ("local".to_string(), text_capture(path, release, local)),
            ("contract_release".to_string(), capture(path, release)),
        ]),
        vec!["native", "same-function-release-contract"],
        comments,
        conditional,
        literals,
        vec![source.id.clone()],
    )
}

#[allow(clippy::too_many_arguments)]
fn early_release_evidence<'tree>(
    path: &str,
    release: &Node<'tree, StrDoc<SupportLang>>,
    exit: &Node<'tree, StrDoc<SupportLang>>,
    local: &str,
    sink: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    make_evidence(
        path,
        release,
        EARLY_RELEASE_RULE_ID,
        EvidenceKind::Validation,
        Capability::EarlyExitDeallocation,
        BTreeMap::from([
            ("local".to_string(), text_capture(path, release, local)),
            ("early_release".to_string(), capture(path, release)),
            ("early_exit".to_string(), capture(path, exit)),
        ]),
        vec!["native", "same-block-release-before-return"],
        comments,
        conditional,
        literals,
        vec![sink.id.clone()],
    )
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
        id: evidence_id(path, rule_id, node),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: vec!["CWE-401".to_string()],
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

fn lifetime_path(
    source: &Evidence,
    sink: &Evidence,
    exit: &Node<'_, StrDoc<SupportLang>>,
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
    } else {
        steps.push(SecurityPathStep {
            kind: SecurityPathStepKind::IneffectiveProtection,
            location: location(&source.location.path, exit),
            evidence_id: None,
            symbol: Some("early return bypasses contract release".to_string()),
        });
    }
    steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: path_id(source, sink, exit, state),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::LocalHeapDeallocation,
        cwe_candidates: vec!["CWE-401".to_string()],
        state,
        steps,
        protection_evidence_ids: protection
            .map(|item| vec![item.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: protection
            .is_none()
            .then(|| "early_exit_bypasses_same_scope_heap_release".to_string())
            .into_iter()
            .collect(),
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family local-heap-lifetime relationship 1".to_string(),
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
    exit: &Node<'_, StrDoc<SupportLang>>,
    state: SecurityPathState,
) -> String {
    stable_id(
        "path",
        &format!(
            "{}\0{}\0{}\0{state:?}",
            source.id,
            sink.id,
            exit.range().start
        ),
    )
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

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '(' && *character != ')')
        .collect()
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

fn excluded(evidence: &Evidence) -> bool {
    evidence
        .context
        .availability
        .as_ref()
        .is_some_and(|availability| availability.state == AvailabilityState::Excluded)
}
