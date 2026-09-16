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

const CHECK_RULE: &str = "native-same-path-metadata-check";
const USE_RULE: &str = "native-same-path-filesystem-use";
const ATOMIC_RULE: &str = "native-atomic-exclusive-create";
const NOFOLLOW_RULE: &str = "native-open-nofollow-control";
const ENGINE: &str = "tree-sitter c-family same-path check-use relationship";

pub(crate) fn add_native_toctou_observations<'tree>(
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
    for function in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "function_definition")
    {
        let calls = function
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
            .filter(|node| !comments.is_in_comment(node.range()))
            .collect::<Vec<_>>();
        for check in calls.iter().filter(|call| is_check(call)) {
            let check_arguments = arguments(check);
            let Some(path_argument) = check_arguments.first() else {
                continue;
            };
            let path_text = path_argument.text();
            let local = path_text.trim();
            if !is_identifier(local) {
                continue;
            }
            let Some(operation) = calls
                .iter()
                .filter(|call| call.range().start > check.range().end)
                .find(|call| operation_path(call).as_deref() == Some(local))
            else {
                continue;
            };
            if reassigned_between(&function, local, check.range().end, operation.range().start)
                || !availability_compatible(check, operation, conditional)
            {
                continue;
            }
            let check_item = item(
                path,
                check,
                CHECK_RULE,
                EvidenceKind::Source,
                Capability::FilesystemRead,
                BTreeMap::from([
                    ("checked_path".to_string(), capture(path, path_argument)),
                    ("check".to_string(), capture(path, check)),
                ]),
                vec!["native", "filesystem", "metadata-precheck"],
                comments,
                conditional,
                literals,
                Vec::new(),
                &["CWE-367"],
            );
            let use_item = item(
                path,
                operation,
                USE_RULE,
                EvidenceKind::Sink,
                operation_capability(operation),
                BTreeMap::from([
                    (
                        "used_path".to_string(),
                        capture(path, &arguments(operation)[0]),
                    ),
                    ("operation".to_string(), capture(path, operation)),
                ]),
                vec!["native", "filesystem", "post-check-use"],
                comments,
                conditional,
                literals,
                vec![check_item.id.clone()],
                &["CWE-367"],
            );
            let atomic = is_nonexistence_access_check(check, operation)
                && atomic_exclusive_create(operation);
            let atomic_item = atomic.then(|| {
                item(
                    path,
                    operation,
                    ATOMIC_RULE,
                    EvidenceKind::Guard,
                    Capability::FilesystemWrite,
                    BTreeMap::from([("atomic_operation".to_string(), capture(path, operation))]),
                    vec!["native", "filesystem", "atomic-exclusive-create"],
                    comments,
                    conditional,
                    literals,
                    vec![use_item.id.clone()],
                    &["CWE-367"],
                )
            });
            paths.push(relationship_path(
                &check_item,
                &use_item,
                atomic_item.as_ref(),
                "CWE-367",
                "same_path_metadata_check_and_filesystem_use_are_not_atomic",
            ));
            additions.extend([check_item.clone(), use_item.clone()]);
            if let Some(value) = atomic_item {
                additions.push(value);
            }

            if global_function(check).as_deref() == Some("lstat")
                && global_function(operation).as_deref() == Some("open")
            {
                let nofollow =
                    open_flags(operation).is_some_and(|flags| has_identifier(&flags, "O_NOFOLLOW"));
                let nofollow_item = nofollow.then(|| {
                    item(
                        path,
                        operation,
                        NOFOLLOW_RULE,
                        EvidenceKind::Guard,
                        Capability::PathContainmentCheck,
                        BTreeMap::from([("open_flags".to_string(), capture(path, operation))]),
                        vec!["native", "filesystem", "final-component-nofollow"],
                        comments,
                        conditional,
                        literals,
                        vec![use_item.id.clone()],
                        &["CWE-59"],
                    )
                });
                paths.push(relationship_path(
                    &check_item,
                    &use_item,
                    nofollow_item.as_ref(),
                    "CWE-59",
                    "lstat_then_open_final_component_symlink_restriction_unproven",
                ));
                if let Some(value) = nofollow_item {
                    additions.push(value);
                }
            }
        }
    }
    let mut unique_additions = BTreeMap::<String, Evidence>::new();
    for mut addition in additions {
        match unique_additions.entry(addition.id.clone()) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(addition);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                let existing = entry.get_mut();
                existing
                    .related_evidence
                    .append(&mut addition.related_evidence);
                existing.related_evidence.sort();
                existing.related_evidence.dedup();
                existing.tags.append(&mut addition.tags);
                existing.tags.sort();
                existing.tags.dedup();
                existing.cwe_candidates.append(&mut addition.cwe_candidates);
                existing.cwe_candidates.sort();
                existing.cwe_candidates.dedup();
            }
        }
    }
    evidence.extend(unique_additions.into_values());
    paths.sort_by(|left, right| left.id.cmp(&right.id));
    paths.dedup_by(|left, right| left.id == right.id);
    paths
}

fn is_check(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    matches!(
        global_function(call).as_deref(),
        Some("access" | "stat" | "lstat")
    )
}

fn operation_path(call: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    matches!(
        global_function(call).as_deref(),
        Some("open" | "fopen" | "unlink" | "remove" | "chmod" | "chown")
    )
    .then(|| {
        arguments(call)
            .first()
            .map(|argument| argument.text().trim().to_string())
    })?
}

fn operation_capability(call: &Node<'_, StrDoc<SupportLang>>) -> Capability {
    match global_function(call).as_deref() {
        Some("open")
            if open_flags(call).is_some_and(|flags| {
                ["O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"]
                    .iter()
                    .any(|flag| has_identifier(&flags, flag))
            }) =>
        {
            Capability::FilesystemWrite
        }
        Some("fopen")
            if arguments(call).get(1).is_some_and(|mode| {
                mode.text().contains('w') || mode.text().contains('a') || mode.text().contains('+')
            }) =>
        {
            Capability::FilesystemWrite
        }
        Some("open" | "fopen") => Capability::FilesystemRead,
        _ => Capability::FilesystemWrite,
    }
}

fn open_flags(call: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    arguments(call)
        .get(1)
        .map(|value| value.text().into_owned())
}

fn atomic_exclusive_create(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    global_function(call).as_deref() == Some("open")
        && open_flags(call).is_some_and(|flags| {
            has_identifier(&flags, "O_CREAT") && has_identifier(&flags, "O_EXCL")
        })
}

fn is_nonexistence_access_check(
    call: &Node<'_, StrDoc<SupportLang>>,
    operation: &Node<'_, StrDoc<SupportLang>>,
) -> bool {
    if global_function(call).as_deref() != Some("access") {
        return false;
    }
    let call_arguments = arguments(call);
    if !call_arguments
        .get(1)
        .is_some_and(|mode| matches!(mode.text().trim(), "F_OK" | "0"))
    {
        return false;
    }
    let Some(statement) = call
        .ancestors()
        .take_while(|node| node.kind().as_ref() != "function_definition")
        .find(|node| node.kind().as_ref() == "if_statement")
    else {
        return false;
    };
    let Some(condition) = statement.field("condition") else {
        return false;
    };
    if !statement
        .field("consequence")
        .is_some_and(|consequence| contains(&consequence, operation))
    {
        return false;
    }
    let condition = compact(condition.text().as_ref());
    let checked = compact(call.text().as_ref());
    condition.contains(&format!("{checked}!=0")) || condition.contains(&format!("{checked}==-1"))
}

fn contains(outer: &Node<'_, StrDoc<SupportLang>>, inner: &Node<'_, StrDoc<SupportLang>>) -> bool {
    outer.range().start <= inner.range().start && inner.range().end <= outer.range().end
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

fn global_function(call: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let function = call.field("function")?;
    let text = function.text();
    let value = text.trim();
    let value = value.strip_prefix("::").unwrap_or(value);
    is_identifier(value).then(|| value.to_string())
}

fn arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.field("arguments")
        .map(|args| args.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
}

fn has_identifier(text: &str, expected: &str) -> bool {
    text.split(|character: char| character != '_' && !character.is_ascii_alphanumeric())
        .any(|token| token == expected)
}

fn is_identifier(value: &str) -> bool {
    let mut characters = value.chars();
    characters
        .next()
        .is_some_and(|character| character == '_' || character.is_ascii_alphabetic())
        && characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn compact(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_whitespace() && *character != '(' && *character != ')')
        .collect()
}

fn availability_compatible(
    source: &Node<'_, StrDoc<SupportLang>>,
    sink: &Node<'_, StrDoc<SupportLang>>,
    conditional: &ConditionalRegions,
) -> bool {
    let source = conditional.availability_for(source.range());
    let sink = conditional.availability_for(sink.range());
    match sink.state {
        AvailabilityState::Always => source.state == AvailabilityState::Always,
        AvailabilityState::Conditional | AvailabilityState::Unknown => source == sink,
        AvailabilityState::Excluded => false,
    }
}

#[allow(clippy::too_many_arguments)]
fn item<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    rule: &str,
    kind: EvidenceKind,
    capability: Capability,
    captures: BTreeMap<String, Capture>,
    tags: Vec<&str>,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    related_evidence: Vec<String>,
    cwes: &[&str],
) -> Evidence {
    Evidence {
        id: evidence_id(path, rule, node),
        kind,
        capability,
        location: location(path, node),
        enclosing_symbol: enclosing_symbol(node),
        captures,
        cwe_candidates: cwes.iter().map(|value| (*value).to_string()).collect(),
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
        rule_id: rule.to_string(),
        related_evidence,
    }
}

fn relationship_path(
    source: &Evidence,
    sink: &Evidence,
    protection: Option<&Evidence>,
    cwe: &str,
    reason: &str,
) -> SecurityPath {
    let state = if protection.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![step(SecurityPathStepKind::Source, source)];
    if let Some(value) = protection {
        steps.push(step(SecurityPathStepKind::Protection, value));
    }
    steps.push(step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: path_id(source, sink, state, cwe),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: sink.capability,
        cwe_candidates: vec![cwe.to_string()],
        state,
        steps,
        protection_evidence_ids: protection
            .map(|value| vec![value.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: protection
            .is_none()
            .then_some(reason.to_string())
            .into_iter()
            .collect(),
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family same-path check-use relationship 1".to_string(),
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
fn path_id(source: &Evidence, sink: &Evidence, state: SecurityPathState, cwe: &str) -> String {
    stable_id(
        "path",
        &format!("{}\0{}\0{state:?}\0{cwe}", source.id, sink.id),
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
fn step(kind: SecurityPathStepKind, item: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: item.location.clone(),
        evidence_id: Some(item.id.clone()),
        symbol: None,
    }
}
