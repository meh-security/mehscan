use std::collections::BTreeMap;

use ast_grep_core::tree_sitter::StrDoc;
use ast_grep_core::{AstGrep, Node};
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

const CALL_RULE_ID: &str = "c-family-invalidating-return-call";
const USE_RULE_ID: &str = "c-family-post-invalidation-use";
const GUARD_RULE_ID: &str = "c-family-invalidation-status-guard";
const ENGINE: &str = "tree-sitter c-family documented-invalidation relationship";
const PATH_ENGINE: &str = "mehscan c-family documented-invalidation relationship 1";

#[derive(Clone, Debug, Eq, PartialEq)]
struct InvalidationContract {
    function: String,
    pointer_parameter: usize,
    invalid_status: String,
    definition: Capture,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct NativeInvalidationProjectContext {
    contracts: BTreeMap<String, InvalidationContract>,
}

impl NativeInvalidationProjectContext {
    pub(crate) fn from_sources<'a>(
        sources: impl Iterator<Item = (&'a str, Language, &'a str)>,
    ) -> Self {
        let mut candidates = BTreeMap::<String, Vec<InvalidationContract>>::new();
        for (path, language, source) in sources {
            let parser = match language {
                Language::C => SupportLang::C,
                Language::Cpp => SupportLang::Cpp,
                _ => continue,
            };
            let Ok(document) = StrDoc::try_new(source, parser) else {
                continue;
            };
            let ast = AstGrep::doc(document);
            for function in ast
                .root()
                .dfs()
                .filter(|node| node.kind().as_ref() == "function_definition")
            {
                if let Some(contract) = documented_contract(path, source, &function) {
                    candidates
                        .entry(contract.function.clone())
                        .or_default()
                        .push(contract);
                }
            }
        }

        let contracts = candidates
            .into_iter()
            .filter_map(|(name, contracts)| {
                contracts
                    .iter()
                    .all(|contract| contract == &contracts[0])
                    .then(|| (name, contracts[0].clone()))
            })
            .collect();
        Self { contracts }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn add_observations<'tree>(
        &self,
        path: &str,
        root: &Node<'tree, StrDoc<SupportLang>>,
        language: Language,
        comments: &CommentRanges,
        conditional: &ConditionalRegions,
        literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
        evidence: &mut Vec<Evidence>,
    ) -> Vec<SecurityPath> {
        if !matches!(language, Language::C | Language::Cpp) || self.contracts.is_empty() {
            return Vec::new();
        }

        let mut additions = Vec::new();
        let mut paths = Vec::new();
        for call in root
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
            .filter(|node| !comments.is_in_comment(node.range()))
        {
            let Some(function) = call.field("function") else {
                continue;
            };
            let function_text = function.text();
            let Some(callee) = simple_identifier(function_text.trim()) else {
                continue;
            };
            let Some(contract) = self.contracts.get(callee) else {
                continue;
            };
            let arguments = named_arguments(&call);
            let Some(argument) = arguments.get(contract.pointer_parameter) else {
                continue;
            };
            let argument_text = argument.text();
            let Some(pointer) = simple_identifier(argument_text.trim()) else {
                continue;
            };
            let Some(scope) = call
                .ancestors()
                .find(|node| node.kind().as_ref() == "function_definition")
            else {
                continue;
            };
            let Some(post_use) = first_post_call_use(&scope, &call, pointer) else {
                continue;
            };
            let guard = invalidation_guard(&scope, &call, &post_use, contract);

            let call_evidence = make_evidence(
                path,
                &call,
                CALL_RULE_ID,
                EvidenceKind::Source,
                Capability::InvalidatingReturnContract,
                BTreeMap::from([
                    ("callee".to_string(), capture(path, &function)),
                    ("pointer".to_string(), capture(path, argument)),
                    (
                        "invalid_status".to_string(),
                        text_capture(path, &call, &contract.invalid_status),
                    ),
                    (
                        "contract_definition".to_string(),
                        contract.definition.clone(),
                    ),
                ]),
                vec![
                    "native",
                    "documented-lifetime-contract",
                    "status-result-controls-pointer-validity",
                    "parse-recovery:locally-complete",
                ],
                comments,
                conditional,
                literals,
                Vec::new(),
            );
            let use_evidence = make_evidence(
                path,
                &post_use,
                USE_RULE_ID,
                EvidenceKind::Sink,
                Capability::PostInvalidationUse,
                BTreeMap::from([
                    (
                        "pointer".to_string(),
                        text_capture(path, &post_use, pointer),
                    ),
                    ("post_call_use".to_string(), capture(path, &post_use)),
                ]),
                vec![
                    "native",
                    "same-function-post-call-use",
                    "parse-recovery:locally-complete",
                ],
                comments,
                conditional,
                literals,
                vec![call_evidence.id.clone()],
            );
            let guard_evidence = guard.as_ref().map(|guard| {
                make_evidence(
                    path,
                    guard,
                    GUARD_RULE_ID,
                    EvidenceKind::Validation,
                    Capability::InvalidationStatusValidation,
                    BTreeMap::from([
                        (
                            "invalid_status".to_string(),
                            text_capture(path, guard, &contract.invalid_status),
                        ),
                        ("terminating_guard".to_string(), capture(path, guard)),
                    ]),
                    vec![
                        "native",
                        "exact-invalid-status",
                        "terminates-before-pointer-reuse",
                        "parse-recovery:locally-complete",
                    ],
                    comments,
                    conditional,
                    literals,
                    vec![call_evidence.id.clone()],
                )
            });
            paths.push(invalidation_path(
                &call_evidence,
                &use_evidence,
                guard_evidence.as_ref(),
            ));
            additions.push(call_evidence);
            additions.push(use_evidence);
            additions.extend(guard_evidence);
        }
        evidence.extend(additions);
        paths
    }
}

fn documented_contract(
    path: &str,
    source: &str,
    function: &Node<'_, StrDoc<SupportLang>>,
) -> Option<InvalidationContract> {
    let declarator = function.field("declarator")?;
    let function_name = declarator
        .dfs()
        .find(|node| node.kind().as_ref() == "identifier")?
        .text()
        .into_owned();
    let parameter_list = declarator
        .dfs()
        .find(|node| node.kind().as_ref() == "parameter_list")?;
    let pointer_parameters = parameter_list
        .children()
        .filter(|node| node.is_named())
        .enumerate()
        .filter_map(|(index, parameter)| parameter.text().contains('*').then_some(index))
        .collect::<Vec<_>>();
    if pointer_parameters.len() != 1 {
        return None;
    }

    let (comment_start, comment_end, comment) =
        adjacent_block_comment(source, function.range().start)?;
    let lower = comment.to_ascii_lowercase();
    let returns = lower.find("returns ")? + "returns ".len();
    let contract_clause_end = lower[returns..]
        .find('.')
        .map_or(lower.len(), |offset| returns + offset);
    let contract_clause = &lower[returns..contract_clause_end];
    if ![
        "was freed",
        "is freed",
        "no longer valid",
        "becomes invalid",
        "became invalid",
        "was invalidated",
    ]
    .iter()
    .any(|phrase| contract_clause.contains(phrase))
    {
        return None;
    }
    let status = comment[returns..]
        .trim_start()
        .chars()
        .take_while(|character| character.is_ascii_alphanumeric() || *character == '_')
        .collect::<String>();
    simple_identifier(&status)?;

    Some(InvalidationContract {
        function: function_name,
        pointer_parameter: pointer_parameters[0],
        invalid_status: status,
        definition: Capture {
            text: comment.to_string(),
            location: location_from_offsets(path, source, comment_start, comment_end),
        },
    })
}

fn adjacent_block_comment(source: &str, function_start: usize) -> Option<(usize, usize, &str)> {
    let prefix = source.get(..function_start)?;
    let trimmed = prefix.trim_end();
    if !trimmed.ends_with("*/") {
        return None;
    }
    let start = trimmed.rfind("/*")?;
    Some((start, trimmed.len(), &trimmed[start..]))
}

fn first_post_call_use<'tree>(
    scope: &Node<'tree, StrDoc<SupportLang>>,
    call: &Node<'tree, StrDoc<SupportLang>>,
    pointer: &str,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    let reassignment = scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| node.range().start > call.range().end)
        .filter(|node| {
            node.field("left")
                .is_some_and(|left| left.text().trim() == pointer)
        })
        .map(|node| node.range().start)
        .min();

    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "identifier")
        .filter(|node| node.range().start >= call.range().end)
        .filter(|node| node.text().trim() == pointer)
        .filter(|node| reassignment.is_none_or(|offset| node.range().start < offset))
        .filter_map(pointer_use_expression)
        .min_by_key(|node| node.range().start)
}

fn pointer_use_expression<'tree>(
    identifier: Node<'tree, StrDoc<SupportLang>>,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    for ancestor in identifier.ancestors().take(5) {
        match ancestor.kind().as_ref() {
            "field_expression" | "subscript_expression" | "pointer_expression" => {
                return Some(ancestor);
            }
            "argument_list" => return ancestor.parent(),
            "assignment_expression" => {
                if ancestor
                    .field("left")
                    .is_some_and(|left| contains(&left, &identifier))
                {
                    return None;
                }
                return Some(ancestor);
            }
            "return_statement" => return Some(ancestor),
            "function_definition" | "compound_statement" => return None,
            _ => {}
        }
    }
    None
}

fn invalidation_guard<'tree>(
    scope: &Node<'tree, StrDoc<SupportLang>>,
    call: &Node<'tree, StrDoc<SupportLang>>,
    post_use: &Node<'tree, StrDoc<SupportLang>>,
    contract: &InvalidationContract,
) -> Option<Node<'tree, StrDoc<SupportLang>>> {
    if let Some(statement) = call
        .ancestors()
        .take_while(|node| node.kind().as_ref() != "function_definition")
        .find(|node| node.kind().as_ref() == "if_statement")
        && statement.field("condition").is_some_and(|condition| {
            exact_status_comparison(
                condition.text().as_ref(),
                call.text().as_ref(),
                &contract.invalid_status,
            )
        })
        && statement
            .field("consequence")
            .is_some_and(|branch| branch_terminates(&branch))
    {
        return Some(statement);
    }

    let result = assigned_result(call)?;
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| {
            call.range().end < node.range().start && node.range().end <= post_use.range().start
        })
        .filter(|node| {
            same_immediate_compound(call, node) && same_immediate_compound(node, post_use)
        })
        .find(|statement| {
            statement.field("condition").is_some_and(|condition| {
                exact_status_comparison(
                    condition.text().as_ref(),
                    &result,
                    &contract.invalid_status,
                )
            }) && statement
                .field("consequence")
                .is_some_and(|branch| branch_terminates(&branch))
        })
}

fn same_immediate_compound(
    left: &Node<'_, StrDoc<SupportLang>>,
    right: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    left.ancestors()
        .find(|node| node.kind().as_ref() == "compound_statement")
        .zip(
            right
                .ancestors()
                .find(|node| node.kind().as_ref() == "compound_statement"),
        )
        .is_some_and(|(left, right)| left.range() == right.range())
}

fn assigned_result(call: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    for ancestor in call.ancestors() {
        match ancestor.kind().as_ref() {
            "init_declarator" => {
                if ancestor
                    .field("value")
                    .is_some_and(|value| contains(&value, call))
                {
                    return ancestor
                        .field("declarator")?
                        .dfs()
                        .find(|node| node.kind().as_ref() == "identifier")
                        .map(|node| node.text().into_owned());
                }
            }
            "assignment_expression" => {
                if ancestor
                    .field("right")
                    .is_some_and(|right| contains(&right, call))
                {
                    return simple_identifier(ancestor.field("left")?.text().trim())
                        .map(str::to_string);
                }
            }
            "function_definition" | "expression_statement" => break,
            _ => {}
        }
    }
    None
}

fn exact_status_comparison(condition: &str, value: &str, status: &str) -> bool {
    let mut condition = compact(condition);
    while condition.starts_with('(') && condition.ends_with(')') {
        condition = condition[1..condition.len() - 1].to_string();
    }
    let value = compact(value);
    condition == format!("{value}=={status}") || condition == format!("{status}=={value}")
}

fn branch_terminates(branch: &Node<'_, StrDoc<SupportLang>>) -> bool {
    if matches!(
        branch.kind().as_ref(),
        "return_statement" | "continue_statement"
    ) {
        return true;
    }
    branch.kind().as_ref() == "compound_statement"
        && branch
            .children()
            .filter(|node| node.is_named())
            .last()
            .is_some_and(|node| {
                matches!(
                    node.kind().as_ref(),
                    "return_statement" | "continue_statement"
                )
            })
}

fn invalidation_path(source: &Evidence, sink: &Evidence, guard: Option<&Evidence>) -> SecurityPath {
    let state = if guard.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![evidence_step(SecurityPathStepKind::Source, source)];
    if let Some(guard) = guard {
        steps.push(evidence_step(SecurityPathStepKind::Protection, guard));
    } else {
        steps.push(SecurityPathStep {
            kind: SecurityPathStepKind::IneffectiveProtection,
            location: source.location.clone(),
            evidence_id: None,
            symbol: Some("invalidating status is not handled before pointer reuse".to_string()),
        });
    }
    steps.push(evidence_step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: stable_id(
            "path",
            &format!("{}\0{}\0{state:?}\0CWE-416", source.id, sink.id),
        ),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::PostInvalidationUse,
        cwe_candidates: cwes(),
        state,
        steps,
        protection_evidence_ids: guard.map(|item| vec![item.id.clone()]).unwrap_or_default(),
        uncertainty_reasons: guard
            .is_none()
            .then(|| "documented_invalidating_status_not_handled_before_pointer_reuse".to_string())
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

fn contains(parent: &Node<'_, StrDoc<SupportLang>>, child: &Node<'_, StrDoc<SupportLang>>) -> bool {
    parent.range().start <= child.range().start && child.range().end <= parent.range().end
}

fn simple_identifier(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()
        && value.chars().enumerate().all(|(index, character)| {
            character == '_'
                || character.is_ascii_alphanumeric() && (index > 0 || !character.is_ascii_digit())
        }))
    .then_some(value)
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace())
        .collect()
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

fn location_from_offsets(path: &str, source: &str, start: usize, end: usize) -> Location {
    Location {
        path: path.to_string(),
        start: position(source, start),
        end: position(source, end),
    }
}

fn position(source: &str, offset: usize) -> Position {
    let prefix = &source[..offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count() + 1;
    let column = prefix
        .rsplit_once('\n')
        .map_or(prefix.len(), |(_, tail)| tail.len())
        + 1;
    Position {
        line,
        column,
        byte_offset: offset,
    }
}

fn cwes() -> Vec<String> {
    vec!["CWE-416".to_string()]
}

fn stable_id(prefix: &str, value: &str) -> String {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in value.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}_{hash:016x}")
}
