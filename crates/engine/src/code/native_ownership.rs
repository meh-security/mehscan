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

const ALLOCATION_RULE_ID: &str = "c-family-owned-state-allocation";
const REGISTRATION_RULE_ID: &str = "c-family-ownership-flag-registration";
const RELEASE_RULE_ID: &str = "c-family-ownership-gated-release";
const ENGINE: &str = "tree-sitter c-family ownership-contract relationship";

#[allow(clippy::too_many_arguments)]
pub(crate) fn add_native_ownership_observations<'tree>(
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
    for assignment in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "assignment_expression")
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        let Some(left) = assignment.field("left") else {
            continue;
        };
        let Some(right) = assignment.field("right") else {
            continue;
        };
        let Some((owner, member)) = direct_member(left.text().as_ref()) else {
            continue;
        };
        if let Some(allocator) = right
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
            .find(|node| is_allocator(node))
        {
            evidence.push(allocation_evidence(
                path,
                &assignment,
                &allocator,
                &owner,
                &member,
                comments,
                conditional,
                literals,
            ));
        }
        if assignment.text().contains("|=") {
            let flag = right.text().trim().to_string();
            if is_ownership_flag(&flag) {
                evidence.push(registration_evidence(
                    path,
                    &assignment,
                    &owner,
                    &member,
                    &flag,
                    comments,
                    conditional,
                    literals,
                    selected_registration(
                        &conditional.availability_for(assignment.range()),
                        build_symbols,
                    ),
                ));
            }
        }
    }

    for branch in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "if_statement")
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        let Some(condition) = branch.field("condition") else {
            continue;
        };
        if !condition.text().contains('&') {
            continue;
        }
        let Some((flag_owner, flag_member)) = condition
            .dfs()
            .filter(|node| node.kind().as_ref() == "field_expression")
            .find_map(|node| direct_member(node.text().as_ref()))
        else {
            continue;
        };
        let Some(flag) = identifiers(condition.text().as_ref())
            .find(|identifier| is_ownership_flag(identifier))
            .map(str::to_string)
        else {
            continue;
        };
        let Some(body) = branch.field("consequence") else {
            continue;
        };
        for release in body
            .dfs()
            .filter(|node| node.kind().as_ref() == "call_expression")
            .filter(|node| is_releaser(node))
        {
            for argument in named_arguments(&release) {
                let Some((owner, member)) = direct_member(argument.text().as_ref()) else {
                    continue;
                };
                if owner != flag_owner || !semantic_match(&member, &flag) {
                    continue;
                }
                evidence.push(release_evidence(
                    path,
                    &release,
                    &condition,
                    &owner,
                    &member,
                    &flag_member,
                    &flag,
                    comments,
                    conditional,
                    literals,
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn allocation_evidence<'tree>(
    path: &str,
    assignment: &Node<'tree, StrDoc<SupportLang>>,
    allocator: &Node<'tree, StrDoc<SupportLang>>,
    owner: &str,
    member: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    make_evidence(
        path,
        assignment,
        ALLOCATION_RULE_ID,
        EvidenceKind::Source,
        Capability::OwnedResourceAllocation,
        BTreeMap::from([
            ("owner".to_string(), text_capture(path, assignment, owner)),
            ("member".to_string(), text_capture(path, assignment, member)),
            ("allocation".to_string(), capture(path, assignment)),
            ("allocator".to_string(), capture(path, allocator)),
            (
                "scope".to_string(),
                text_capture(path, assignment, &scope_key(assignment)),
            ),
        ]),
        vec![
            "native",
            "allocation-stored-in-owned-state",
            "parse-recovery:locally-complete",
        ],
        comments,
        conditional,
        literals,
        Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn registration_evidence<'tree>(
    path: &str,
    assignment: &Node<'tree, StrDoc<SupportLang>>,
    owner: &str,
    flag_member: &str,
    flag: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    profile_selected: bool,
) -> Evidence {
    make_evidence(
        path,
        assignment,
        REGISTRATION_RULE_ID,
        EvidenceKind::Validation,
        Capability::OwnershipFlagRegistration,
        BTreeMap::from([
            ("owner".to_string(), text_capture(path, assignment, owner)),
            (
                "flag_member".to_string(),
                text_capture(path, assignment, flag_member),
            ),
            (
                "ownership_flag".to_string(),
                text_capture(path, assignment, flag),
            ),
            ("registration".to_string(), capture(path, assignment)),
            (
                "profile_selected".to_string(),
                text_capture(
                    path,
                    assignment,
                    if profile_selected { "true" } else { "false" },
                ),
            ),
            (
                "scope".to_string(),
                text_capture(path, assignment, &scope_key(assignment)),
            ),
        ]),
        vec![
            "native",
            "owned-state-registered",
            "parse-recovery:locally-complete",
        ],
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
    condition: &Node<'tree, StrDoc<SupportLang>>,
    owner: &str,
    member: &str,
    flag_member: &str,
    flag: &str,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    make_evidence(
        path,
        release,
        RELEASE_RULE_ID,
        EvidenceKind::Sink,
        Capability::OwnershipGatedRelease,
        BTreeMap::from([
            ("owner".to_string(), text_capture(path, release, owner)),
            ("member".to_string(), text_capture(path, release, member)),
            (
                "flag_member".to_string(),
                text_capture(path, condition, flag_member),
            ),
            (
                "ownership_flag".to_string(),
                text_capture(path, condition, flag),
            ),
            ("release_gate".to_string(), capture(path, condition)),
            ("release".to_string(), capture(path, release)),
        ]),
        vec![
            "native",
            "release-requires-ownership-flag",
            "parse-recovery:locally-complete",
        ],
        comments,
        conditional,
        literals,
        Vec::new(),
    )
}

pub(crate) fn link_native_ownership_paths(evidence: &mut Vec<Evidence>) -> Vec<SecurityPath> {
    let allocations = by_capability(evidence, Capability::OwnedResourceAllocation);
    let registrations = by_capability(evidence, Capability::OwnershipFlagRegistration);
    let releases = by_capability(evidence, Capability::OwnershipGatedRelease);
    let mut retained = BTreeSet::new();
    let mut paths = Vec::new();
    for source in allocations.iter().filter(|item| !is_excluded(item)) {
        let Some(member) = capture_text(source, "member") else {
            continue;
        };
        for sink in releases.iter().filter(|item| {
            !is_excluded(item)
                && capture_text(item, "member") == Some(member)
                && same_c_family_language(&source.location.path, &item.location.path)
        }) {
            let Some(flag) = capture_text(sink, "ownership_flag") else {
                continue;
            };
            let Some(flag_member) = capture_text(sink, "flag_member") else {
                continue;
            };
            let protection = registrations.iter().find(|item| {
                protection_available_for(source, item)
                    && capture_text(item, "flag_member") == Some(flag_member)
                    && capture_text(item, "ownership_flag") == Some(flag)
                    && semantic_match(member, flag)
                    && item.location.path == source.location.path
                    && same_scope(source, item)
                    && item
                        .location
                        .start
                        .byte_offset
                        .abs_diff(source.location.start.byte_offset)
                        <= 8192
            });
            retained.extend([source.id.clone(), sink.id.clone()]);
            if let Some(item) = protection {
                retained.insert(item.id.clone());
            }
            paths.push(ownership_path(source, sink, protection));
        }
    }
    let unknown_flags = paths
        .iter()
        .filter(|path| path.state == SecurityPathState::Unknown)
        .filter_map(|path| {
            releases
                .iter()
                .find(|item| item.id == path.sink_evidence_id)
                .and_then(|item| capture_text(item, "ownership_flag"))
                .map(str::to_string)
        })
        .collect::<BTreeSet<_>>();
    paths.retain(|path| {
        if path.state == SecurityPathState::Unknown {
            return true;
        }
        let explicitly_selected = path.protection_evidence_ids.iter().any(|id| {
            registrations.iter().any(|item| {
                &item.id == id && capture_text(item, "profile_selected") == Some("true")
            })
        });
        let comparative_flag = releases
            .iter()
            .find(|item| item.id == path.sink_evidence_id)
            .and_then(|item| capture_text(item, "ownership_flag"))
            .is_some_and(|flag| unknown_flags.contains(flag));
        explicitly_selected || comparative_flag
    });
    retained.clear();
    for path in &paths {
        retained.extend([
            path.source_evidence_id.clone(),
            path.sink_evidence_id.clone(),
        ]);
        retained.extend(path.protection_evidence_ids.iter().cloned());
    }
    evidence.retain(|item| {
        !matches!(
            item.capability,
            Capability::OwnedResourceAllocation
                | Capability::OwnershipFlagRegistration
                | Capability::OwnershipGatedRelease
        ) || retained.contains(&item.id)
    });
    paths.sort_by(|a, b| a.id.cmp(&b.id));
    paths.dedup_by(|a, b| a.id == b.id);
    paths
}

fn ownership_path(
    source: &Evidence,
    sink: &Evidence,
    protection: Option<&Evidence>,
) -> SecurityPath {
    let state = if protection.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![step(SecurityPathStepKind::Source, source)];
    if let Some(item) = protection {
        steps.push(step(SecurityPathStepKind::Protection, item));
    }
    steps.push(step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: path_id(source, sink, state, &steps),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: Capability::OwnershipGatedRelease,
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
                "persistent_allocation_ownership_registration_not_found".to_string(),
                "exceptional_exit_before_manual_release_requires_confirmation".to_string(),
            ]
        },
        provenance: SecurityPathProvenance {
            engine: "mehscan c-family ownership-contract relationship 1".to_string(),
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

fn is_allocator(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    call.field("function").is_some_and(|node| {
        let name = node.text().to_ascii_lowercase();
        name.contains("malloc")
            || name.contains("calloc")
            || name.contains("allocate")
            || name == "new"
    })
}
fn is_releaser(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    call.field("function").is_some_and(|node| {
        let name = node.text().to_ascii_lowercase();
        name.contains("free")
            || name.contains("release")
            || name.contains("destroy")
            || name == "delete"
    })
}
fn is_ownership_flag(value: &str) -> bool {
    simple_identifier(value).is_some()
        && value.chars().any(|c| c.is_ascii_uppercase())
        && value
            .to_ascii_uppercase()
            .split('_')
            .any(|part| matches!(part, "FREE" | "OWN" | "OWNED"))
}
fn semantic_match(member: &str, flag: &str) -> bool {
    let member = semantic_key(member);
    let flag = flag
        .split('_')
        .filter(|part| !matches!(*part, "PNG" | "FREE" | "OWN" | "OWNED" | "FLAG"))
        .collect::<String>()
        .to_ascii_lowercase();
    member.len() >= 3 && flag.len() >= 3 && (member.contains(&flag) || flag.contains(&member))
}
fn semantic_key(value: &str) -> String {
    let mut value = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    for suffix in ["pointer", "buffer", "data", "ptr", "buf"] {
        if value.ends_with(suffix) {
            value.truncate(value.len() - suffix.len());
            break;
        }
    }
    value
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
fn named_arguments<'tree>(
    call: &Node<'tree, StrDoc<SupportLang>>,
) -> Vec<Node<'tree, StrDoc<SupportLang>>> {
    call.field("arguments")
        .map(|node| node.children().filter(|child| child.is_named()).collect())
        .unwrap_or_default()
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
fn capture_text<'a>(evidence: &'a Evidence, name: &str) -> Option<&'a str> {
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
        "CWE-401".to_string(),
        "CWE-404".to_string(),
        "CWE-772".to_string(),
    ]
}
fn is_excluded(evidence: &Evidence) -> bool {
    evidence
        .context
        .availability
        .as_ref()
        .is_some_and(|item| item.state == AvailabilityState::Excluded)
}
fn protection_available_for(source: &Evidence, protection: &Evidence) -> bool {
    if capture_text(protection, "profile_selected") == Some("true") {
        return true;
    }
    let Some(protection) = protection.context.availability.as_ref() else {
        return false;
    };
    if protection.state == AvailabilityState::Always {
        return true;
    }
    let Some(source) = source.context.availability.as_ref() else {
        return false;
    };
    protection.state == AvailabilityState::Conditional
        && source.state == AvailabilityState::Conditional
        && protection.condition.is_some()
        && protection.condition == source.condition
}
fn selected_registration(
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
fn same_scope(left: &Evidence, right: &Evidence) -> bool {
    match (capture_text(left, "scope"), capture_text(right, "scope")) {
        (Some(left), Some(right)) if left != "unknown" && right != "unknown" => left == right,
        (Some("unknown"), Some("unknown")) => true,
        _ => false,
    }
}
fn scope_key(node: &Node<'_, StrDoc<SupportLang>>) -> String {
    node.ancestors()
        .find(|ancestor| ancestor.kind().as_ref() == "function_definition")
        .map(|function| format!("{}:{}", function.range().start, function.range().end))
        .unwrap_or_else(|| "unknown".to_string())
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
    text_capture(path, node, node.text().as_ref())
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
fn step(kind: SecurityPathStepKind, evidence: &Evidence) -> SecurityPathStep {
    SecurityPathStep {
        kind,
        location: evidence.location.clone(),
        evidence_id: Some(evidence.id.clone()),
        symbol: evidence.enclosing_symbol.clone(),
    }
}
