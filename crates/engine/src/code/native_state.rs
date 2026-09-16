use std::collections::{BTreeMap, BTreeSet};

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

const INITIALIZATION_RULE_ID: &str = "c-family-required-state-initialization-failure";
const HANDOFF_RULE_ID: &str = "c-family-required-state-pointer-handoff";
const DEREFERENCE_RULE_ID: &str = "c-family-handed-off-state-indexed-dereference";
const VALIDATION_RULE_ID: &str = "c-family-fatal-state-invariant-validation";
const ENGINE: &str = "tree-sitter c-family exceptional-state relationship";

pub(crate) fn add_native_state_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    if !matches!(language, Language::C | Language::Cpp) {
        return;
    }

    for function in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "function_definition")
    {
        add_dereference_observation(path, &function, comments, conditional, literals, evidence);
    }
    add_initialization_observations(path, root, comments, conditional, literals, evidence);

    for call in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        let Some(callee) = call
            .field("function")
            .map(|node| node.text().trim().to_string())
        else {
            continue;
        };
        if simple_identifier(&callee).is_none() {
            continue;
        }
        for (argument_index, argument) in named_arguments(&call).into_iter().enumerate() {
            let Some((owner, member)) = direct_member(argument.text().as_ref()) else {
                continue;
            };
            evidence.push(make_evidence(
                path,
                &argument,
                HANDOFF_RULE_ID,
                EvidenceKind::Guard,
                Capability::StatePointerHandoff,
                BTreeMap::from([
                    ("callee".to_string(), capture_text(path, &call, &callee)),
                    (
                        "argument_index".to_string(),
                        capture_text(path, &argument, &argument_index.to_string()),
                    ),
                    ("owner".to_string(), capture_text(path, &argument, &owner)),
                    ("member".to_string(), capture_text(path, &argument, &member)),
                    ("handoff".to_string(), capture(path, &argument)),
                ]),
                vec![
                    "native",
                    "required-state-pointer-handoff",
                    "parse-recovery:locally-complete",
                ],
                comments,
                conditional,
                literals,
                Vec::new(),
            ));
        }
    }

    for condition in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        let Some(condition_node) = condition.field("condition") else {
            continue;
        };
        let Some((owner, member)) = null_member_comparison(condition_node.text().as_ref()) else {
            continue;
        };
        let Some(consequence) = condition.field("consequence") else {
            continue;
        };
        for reporter in consequence
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
            .filter(|node| is_fatal_reporter(node))
        {
            let validation = validation_evidence(
                path,
                &reporter,
                &condition_node,
                &owner,
                &member,
                comments,
                conditional,
                literals,
                Vec::new(),
            );
            if !evidence.iter().any(|item| item.id == validation.id) {
                evidence.push(validation);
            }
        }
    }
}

fn add_initialization_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    for function in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "function_definition")
    {
        let Some(initializer_name) = function_name(&function) else {
            continue;
        };
        let parameters = parameter_names(&function);
        for assignment in function
            .dfs()
            .filter(|node| node.kind().as_ref() == "assignment_expression")
        {
            let Some(left) = assignment.field("left") else {
                continue;
            };
            let Some(right) = assignment.field("right") else {
                continue;
            };
            if !right
                .dfs()
                .any(|node| node.kind().as_ref() == "call_expression")
            {
                continue;
            }
            let Some((owner, member)) = direct_member(left.text().as_ref()) else {
                continue;
            };
            if !parameters.iter().any(|parameter| parameter == &member) {
                continue;
            }
            for failure in function
                .dfs()
                .filter(|node| node.kind().as_ref() == "if_statement")
                .filter(|node| node.range().end < assignment.range().start)
            {
                let Some(condition) = failure.field("condition") else {
                    continue;
                };
                if !is_null_identifier_comparison(condition.text().as_ref(), &member) {
                    continue;
                }
                let Some(consequence) = failure.field("consequence") else {
                    continue;
                };
                if !consequence
                    .dfs()
                    .any(|node| node.kind().as_ref() == "return_statement")
                {
                    continue;
                }
                for reporter in consequence
                    .dfs()
                    .filter(|node| node.kind().as_ref() == "call_expression")
                    .filter(|node| is_error_reporter(node))
                {
                    let source = make_evidence(
                        path,
                        &reporter,
                        INITIALIZATION_RULE_ID,
                        EvidenceKind::Source,
                        Capability::RequiredStateInitialization,
                        BTreeMap::from([
                            (
                                "initializer_function".to_string(),
                                capture_text(path, &reporter, &initializer_name),
                            ),
                            ("input".to_string(), capture_text(path, &condition, &member)),
                            ("owner".to_string(), capture_text(path, &left, &owner)),
                            ("member".to_string(), capture_text(path, &left, &member)),
                            ("failure_check".to_string(), capture(path, &condition)),
                            ("failure_reporter".to_string(), capture(path, &reporter)),
                            ("initializer".to_string(), capture(path, &assignment)),
                            (
                                "error_policy".to_string(),
                                capture_text(
                                    path,
                                    &reporter,
                                    if is_fatal_reporter(&reporter) {
                                        "fatal"
                                    } else {
                                        "recoverable"
                                    },
                                ),
                            ),
                        ]),
                        vec![
                            "native",
                            "exception-can-skip-required-state",
                            "parse-recovery:locally-complete",
                        ],
                        comments,
                        conditional,
                        literals,
                        Vec::new(),
                    );
                    if is_excluded(&source) {
                        evidence.push(source);
                        continue;
                    }
                    if !evidence.iter().any(|item| item.id == source.id) {
                        evidence.push(source.clone());
                    }
                    if is_fatal_reporter(&reporter) {
                        let validation = validation_evidence(
                            path,
                            &reporter,
                            &condition,
                            &owner,
                            &member,
                            comments,
                            conditional,
                            literals,
                            vec![source.id],
                        );
                        if !evidence.iter().any(|item| item.id == validation.id) {
                            evidence.push(validation);
                        }
                    }
                }
            }
        }
    }
}

fn add_dereference_observation<'tree>(
    path: &str,
    function: &Node<'tree, StrDoc<SupportLang>>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) {
    let Some(callee) = function_name(function) else {
        return;
    };
    let parameters = parameter_names(function);
    for (parameter_index, parameter) in parameters.iter().enumerate() {
        let Some(dereference) = function.dfs().find(|node| {
            node.kind().as_ref() == "subscript_expression"
                && subscript_base(node.text().as_ref()) == Some(parameter.as_str())
                && !comments.is_in_comment(node.range())
        }) else {
            continue;
        };
        evidence.push(make_evidence(
            path,
            &dereference,
            DEREFERENCE_RULE_ID,
            EvidenceKind::Sink,
            Capability::StateDependentDereference,
            BTreeMap::from([
                (
                    "callee".to_string(),
                    capture_text(path, &dereference, &callee),
                ),
                (
                    "parameter_index".to_string(),
                    capture_text(path, &dereference, &parameter_index.to_string()),
                ),
                (
                    "state_parameter".to_string(),
                    capture_text(path, &dereference, parameter),
                ),
                (
                    "indexed_dereference".to_string(),
                    capture(path, &dereference),
                ),
            ]),
            vec![
                "native",
                "handed-off-state-indexed-dereference",
                "parse-recovery:locally-complete",
            ],
            comments,
            conditional,
            literals,
            Vec::new(),
        ));
    }
}

#[allow(clippy::too_many_arguments)]
fn validation_evidence<'tree>(
    path: &str,
    reporter: &Node<'tree, StrDoc<SupportLang>>,
    condition: &Node<'tree, StrDoc<SupportLang>>,
    owner: &str,
    member: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    related_evidence: Vec<String>,
) -> Evidence {
    make_evidence(
        path,
        reporter,
        VALIDATION_RULE_ID,
        EvidenceKind::Validation,
        Capability::FatalStateInvariantValidation,
        BTreeMap::from([
            ("owner".to_string(), capture_text(path, condition, owner)),
            ("member".to_string(), capture_text(path, condition, member)),
            ("invariant_check".to_string(), capture(path, condition)),
            ("fatal_reporter".to_string(), capture(path, reporter)),
        ]),
        vec![
            "native",
            "fatal-required-state-rejection",
            "parse-recovery:locally-complete",
        ],
        comments,
        conditional,
        literals,
        related_evidence,
    )
}

pub(crate) fn link_native_state_paths(evidence: &mut Vec<Evidence>) -> Vec<SecurityPath> {
    let sources = by_capability(evidence, Capability::RequiredStateInitialization);
    let handoffs = by_capability(evidence, Capability::StatePointerHandoff);
    let sinks = by_capability(evidence, Capability::StateDependentDereference);
    let validations = by_capability(evidence, Capability::FatalStateInvariantValidation);
    let mut retained = BTreeSet::new();
    let mut paths = Vec::new();
    for source in sources.iter().filter(|item| !is_excluded(item)) {
        let Some(owner) = capture_value(source, "owner") else {
            continue;
        };
        let Some(member) = capture_value(source, "member") else {
            continue;
        };
        for handoff in handoffs.iter().filter(|item| {
            !is_excluded(item)
                && capture_value(item, "owner") == Some(owner)
                && capture_value(item, "member") == Some(member)
                && same_c_family_language(&source.location.path, &item.location.path)
                && source.location.path == item.location.path
        }) {
            let Some(callee) = capture_value(handoff, "callee") else {
                continue;
            };
            let Some(index) = capture_value(handoff, "argument_index") else {
                continue;
            };
            for sink in sinks.iter().filter(|item| {
                !is_excluded(item)
                    && capture_value(item, "callee") == Some(callee)
                    && capture_value(item, "parameter_index") == Some(index)
                    && capture_value(item, "state_parameter") == Some(member)
                    && same_c_family_language(&source.location.path, &item.location.path)
            }) {
                let protections = validations
                    .iter()
                    .filter(|item| {
                        is_always_available(item)
                            && capture_value(item, "owner") == Some(owner)
                            && capture_value(item, "member") == Some(member)
                            && same_c_family_language(&source.location.path, &item.location.path)
                            && source.location.path == item.location.path
                    })
                    .collect::<Vec<_>>();
                retained.extend([source.id.clone(), handoff.id.clone(), sink.id.clone()]);
                retained.extend(protections.iter().map(|item| item.id.clone()));
                paths.push(state_path(source, handoff, sink, &protections));
            }
        }
    }
    evidence.retain(|item| {
        !matches!(
            item.capability,
            Capability::RequiredStateInitialization
                | Capability::StatePointerHandoff
                | Capability::StateDependentDereference
                | Capability::FatalStateInvariantValidation
        ) || retained.contains(&item.id)
    });
    paths.sort_by(|a, b| a.id.cmp(&b.id));
    paths.dedup_by(|a, b| a.id == b.id);
    paths
}

fn state_path(
    source: &Evidence,
    handoff: &Evidence,
    sink: &Evidence,
    protections: &[&Evidence],
) -> SecurityPath {
    let state = if protections.is_empty() {
        SecurityPathState::Unknown
    } else {
        SecurityPathState::Protected
    };
    let mut steps = vec![step(SecurityPathStepKind::Source, source)];
    steps.extend(
        protections
            .iter()
            .map(|item| step(SecurityPathStepKind::Protection, item)),
    );
    steps.push(step(SecurityPathStepKind::Alias, handoff));
    steps.push(step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: path_id(source, sink, state, &steps),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::StateDependentDereference,
        cwe_candidates: cwes(),
        state,
        steps,
        protection_evidence_ids: protections.iter().map(|item| item.id.clone()).collect(),
        uncertainty_reasons: if protections.is_empty() {
            vec![
                "recoverable_exception_can_leave_required_state_absent".to_string(),
                "member_to_parameter_handoff_reaches_indexed_dereference".to_string(),
            ]
        } else {
            Vec::new()
        },
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family exceptional-state relationship 1".to_string(),
            maximum_propagation_depth: 2,
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
        id: evidence_id(path, rule_id, node),
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
        context: evidence_context(node, comments, conditional, literals),
        symbol_resolution: None,
        rule_id: rule_id.to_string(),
        related_evidence,
    }
}

fn parameter_names(function: &Node<'_, StrDoc<SupportLang>>) -> Vec<String> {
    let Some(list) = function
        .dfs()
        .find(|node| node.kind().as_ref() == "parameter_list")
    else {
        return Vec::new();
    };
    list.children()
        .filter(|node| node.is_named())
        .filter_map(|parameter| {
            parameter
                .dfs()
                .filter(|node| node.kind().as_ref() == "identifier")
                .last()
                .map(|node| node.text().into_owned())
        })
        .collect()
}

fn function_name(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    node.field("declarator")?
        .dfs()
        .find(|child| child.kind().as_ref() == "identifier")
        .map(|child| child.text().into_owned())
}

fn named_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.field("arguments")
        .map(|args| args.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
}

fn direct_member(text: &str) -> Option<(String, String)> {
    let compact = text
        .chars()
        .filter(|c| !c.is_whitespace() && !matches!(c, '(' | ')'))
        .collect::<String>();
    let (owner, member) = compact
        .split_once("->")
        .or_else(|| compact.split_once('.'))?;
    (simple_identifier(owner).is_some() && simple_identifier(member).is_some())
        .then(|| (owner.to_string(), member.to_string()))
}

fn null_member_comparison(text: &str) -> Option<(String, String)> {
    for operator in ["==", "!="] {
        let Some((left, right)) = text.split_once(operator) else {
            continue;
        };
        let left = left.trim().trim_matches(|c| matches!(c, '(' | ')' | ' '));
        let right = right.trim().trim_matches(|c| matches!(c, '(' | ')' | ' '));
        if matches!(right, "NULL" | "nullptr" | "null")
            && let Some(member) = direct_member(left)
        {
            return Some(member);
        }
        if matches!(left, "NULL" | "nullptr" | "null")
            && let Some(member) = direct_member(right)
        {
            return Some(member);
        }
    }
    None
}

fn is_null_identifier_comparison(text: &str, identifier: &str) -> bool {
    contains_null(text)
        && (text.contains("==") || text.contains("!="))
        && identifiers(text).any(|candidate| candidate == identifier)
}

fn contains_null(text: &str) -> bool {
    identifiers(text).any(|value| matches!(value, "NULL" | "nullptr" | "null"))
}

fn subscript_base(text: &str) -> Option<&str> {
    simple_identifier(text.trim().split_once('[')?.0.trim())
}

fn is_error_reporter(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    call.field("function").is_some_and(|callee| {
        let name = callee.text().to_ascii_lowercase();
        ["error", "report", "warn", "fatal", "abort", "panic"]
            .iter()
            .any(|part| name.contains(part))
    })
}

fn is_fatal_reporter(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    call.field("function").is_some_and(|callee| {
        let name = callee.text().to_ascii_lowercase();
        name.contains("fatal")
            || name.contains("abort")
            || name.contains("panic")
            || name == "png_error"
            || name.ends_with("_error")
    })
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

fn identifiers(value: &str) -> impl Iterator<Item = &str> {
    value
        .split(|c: char| c != '_' && !c.is_ascii_alphanumeric())
        .filter(|token| simple_identifier(token).is_some())
}

fn capture_text(path: &str, node: &Node<'_, StrDoc<SupportLang>>, text: &str) -> Capture {
    Capture {
        text: text.to_string(),
        location: location(path, node),
    }
}
fn capture(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Capture {
    capture_text(path, node, node.text().as_ref())
}
fn capture_value<'a>(evidence: &'a Evidence, name: &str) -> Option<&'a str> {
    evidence.captures.get(name).map(|item| item.text.as_str())
}
fn by_capability(evidence: &[Evidence], capability: Capability) -> Vec<Evidence> {
    evidence
        .iter()
        .filter(|item| item.capability == capability)
        .cloned()
        .collect()
}
fn cwes() -> Vec<String> {
    vec![
        "CWE-476".to_string(),
        "CWE-754".to_string(),
        "CWE-755".to_string(),
    ]
}
fn is_excluded(evidence: &Evidence) -> bool {
    evidence
        .context
        .availability
        .as_ref()
        .is_some_and(|item| item.state == AvailabilityState::Excluded)
}
fn is_always_available(evidence: &Evidence) -> bool {
    evidence
        .context
        .availability
        .as_ref()
        .is_some_and(|item| item.state == AvailabilityState::Always)
}
fn same_c_family_language(left: &str, right: &str) -> bool {
    fn family(path: &str) -> Option<bool> {
        match path.rsplit_once('.')?.1.to_ascii_lowercase().as_str() {
            "c" => Some(false),
            "cc" | "cpp" | "cxx" | "c++" | "hpp" | "hh" | "hxx" => Some(true),
            _ => None,
        }
    }
    match (family(left), family(right)) {
        (Some(a), Some(b)) => a == b,
        _ => true,
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
fn evidence_id(path: &str, rule_id: &str, node: &Node<'_, StrDoc<SupportLang>>) -> String {
    format!(
        "{rule_id}:{path}:{}:{}",
        node.range().start,
        node.range().end
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
fn location(path: &str, node: &Node<'_, StrDoc<SupportLang>>) -> Location {
    Location {
        path: path.to_string(),
        start: Position {
            line: node.start_pos().line() + 1,
            column: node.start_pos().column(node) + 1,
            byte_offset: node.range().start,
        },
        end: Position {
            line: node.end_pos().line() + 1,
            column: node.end_pos().column(node) + 1,
            byte_offset: node.range().end,
        },
    }
}
fn step(kind: SecurityPathStepKind, evidence: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        evidence_id: Some(evidence.id.clone()),
        location: evidence.location.clone(),
        symbol: evidence.enclosing_symbol.clone(),
    }
}

fn stable_id(prefix: &str, input: &str) -> String {
    let mut hash = 0xcbf29ce484222325_u64;
    for byte in input.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    format!("{prefix}-{hash:016x}")
}
