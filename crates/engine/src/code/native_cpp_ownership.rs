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

const ALLOCATION_RULE_ID: &str = "cpp-local-new-allocation";
const DELETE_RULE_ID: &str = "cpp-local-delete-release";
const FAMILY_RULE_ID: &str = "cpp-allocation-family-validation";
const RAII_RULE_ID: &str = "cpp-standard-unique-owner";
const TRANSFER_RULE_ID: &str = "cpp-raw-to-unique-ownership-transfer";
const ENGINE: &str = "tree-sitter c++ allocation-ownership relationship";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Family {
    Scalar,
    Array,
}

impl Family {
    fn label(self) -> &'static str {
        match self {
            Self::Scalar => "scalar",
            Self::Array => "array",
        }
    }
}

pub(crate) fn add_native_cpp_ownership_observations<'tree>(
    path: &str,
    root: &Node<'tree, StrDoc<SupportLang>>,
    language: Language,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
    evidence: &mut Vec<Evidence>,
) -> Vec<SecurityPath> {
    if language != Language::Cpp {
        return Vec::new();
    }

    let mut additions = Vec::new();
    let mut paths = Vec::new();

    for allocation in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "new_expression")
        .filter(|node| !comments.is_in_comment(node.range()))
        .filter(|node| ordinary_new(node))
    {
        let family = new_family(&allocation);
        if let Some(owner) = enclosing_unique_owner(&allocation) {
            let owner_family = owner.family;
            let source = allocation_evidence(
                path,
                &allocation,
                owner.local.as_str(),
                family,
                comments,
                conditional,
                literals,
            );
            if excluded(&source) {
                continue;
            }
            let sink = raii_evidence(
                path,
                &owner.node,
                owner.local.as_str(),
                owner_family,
                &source,
                comments,
                conditional,
                literals,
            );
            let validation = (family == owner_family).then(|| {
                family_evidence(
                    path,
                    &owner.node,
                    family,
                    &sink,
                    comments,
                    conditional,
                    literals,
                )
            });
            paths.push(ownership_path(
                &source,
                &sink,
                validation.as_ref(),
                "unique owner family differs from allocated new form",
            ));
            additions.push(source);
            if let Some(validation) = validation {
                additions.push(validation);
            }
            additions.push(sink);
            continue;
        }

        let Some((binding, local)) = allocation_binding(&allocation) else {
            continue;
        };
        let Some(scope) = allocation
            .ancestors()
            .find(|node| node.kind().as_ref() == "function_definition")
        else {
            continue;
        };
        if let Some(owner) = raw_unique_transfer(&scope, &local, binding.range().end) {
            if reassigned_between(
                &scope,
                &local,
                binding.range().end,
                owner.node.range().start,
            ) || !availability_compatible(&allocation, &owner.node, conditional)
            {
                continue;
            }
            let source = allocation_evidence(
                path,
                &allocation,
                &local,
                family,
                comments,
                conditional,
                literals,
            );
            if excluded(&source) {
                continue;
            }
            let transfer = transfer_evidence(
                path,
                &owner.node,
                &local,
                &source,
                comments,
                conditional,
                literals,
            );
            let sink = raii_evidence(
                path,
                &owner.node,
                &owner.local,
                owner.family,
                &source,
                comments,
                conditional,
                literals,
            );
            let validation = (family == owner.family).then(|| {
                family_evidence(
                    path,
                    &owner.node,
                    family,
                    &sink,
                    comments,
                    conditional,
                    literals,
                )
            });
            paths.push(ownership_transfer_path(
                &source,
                &transfer,
                &sink,
                validation.as_ref(),
            ));
            additions.extend([source, transfer]);
            if let Some(validation) = validation {
                additions.push(validation);
            }
            additions.push(sink);
            continue;
        }

        let Some(release) = scope
            .dfs()
            .filter(|node| node.kind().as_ref() == "delete_expression")
            .filter(|node| node.range().start > binding.range().end)
            .find(|node| delete_target(node).as_deref() == Some(local.as_str()))
        else {
            continue;
        };
        if reassigned_between(&scope, &local, binding.range().end, release.range().start) {
            continue;
        }
        let source = allocation_evidence(
            path,
            &allocation,
            &local,
            family,
            comments,
            conditional,
            literals,
        );
        if excluded(&source) || !availability_compatible(&allocation, &release, conditional) {
            continue;
        }
        let release_family = delete_family(&release);
        let sink = delete_evidence(
            path,
            &release,
            &local,
            release_family,
            &source,
            comments,
            conditional,
            literals,
        );
        let validation = (family == release_family).then(|| {
            family_evidence(
                path,
                &release,
                family,
                &sink,
                comments,
                conditional,
                literals,
            )
        });
        paths.push(ownership_path(
            &source,
            &sink,
            validation.as_ref(),
            "new and delete scalar-array forms differ",
        ));
        additions.push(source);
        if let Some(validation) = validation {
            additions.push(validation);
        }
        additions.push(sink);
    }

    for call in root
        .dfs()
        .filter(|node| node.kind().as_ref() == "call_expression")
        .filter(|node| is_make_unique(node))
        .filter(|node| !comments.is_in_comment(node.range()))
    {
        let Some((binding, local)) = call_binding(&call) else {
            continue;
        };
        let family = make_unique_family(&call);
        let source =
            allocation_evidence(path, &call, &local, family, comments, conditional, literals);
        if excluded(&source) {
            continue;
        }
        let sink = raii_evidence(
            path,
            &binding,
            &local,
            family,
            &source,
            comments,
            conditional,
            literals,
        );
        let validation = family_evidence(
            path,
            &binding,
            family,
            &sink,
            comments,
            conditional,
            literals,
        );
        paths.push(ownership_path(
            &source,
            &sink,
            Some(&validation),
            "standard make_unique owner family unproven",
        ));
        additions.extend([source, validation, sink]);
    }

    evidence.extend(additions);
    paths
}

struct UniqueOwner<'tree> {
    node: Node<'tree, StrDoc<SupportLang>>,
    local: String,
    family: Family,
}

fn ordinary_new(node: &Node<'_, StrDoc<SupportLang>>) -> bool {
    let compact = compact(node.text().as_ref());
    !compact.starts_with("new(") || compact.starts_with("new(std::nothrow)")
}

fn new_family(node: &Node<'_, StrDoc<SupportLang>>) -> Family {
    if node
        .dfs()
        .any(|child| child.kind().as_ref() == "new_declarator" && child.text().contains('['))
    {
        Family::Array
    } else {
        Family::Scalar
    }
}

fn allocation_binding<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(Node<'tree, StrDoc<SupportLang>>, String)> {
    for ancestor in node.ancestors() {
        match ancestor.kind().as_ref() {
            "init_declarator" => {
                let declarator = ancestor.field("declarator")?;
                return declarator_identifier(&declarator).map(|local| (ancestor, local));
            }
            "assignment_expression" => {
                let left = ancestor.field("left")?;
                return simple_identifier(left.text().trim())
                    .map(|local| (ancestor, local.to_string()));
            }
            "function_definition" => break,
            _ => {}
        }
    }
    None
}

fn call_binding<'tree>(
    node: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<(Node<'tree, StrDoc<SupportLang>>, String)> {
    allocation_binding(node)
}

fn enclosing_unique_owner<'tree>(
    allocation: &Node<'tree, StrDoc<SupportLang>>,
) -> Option<UniqueOwner<'tree>> {
    allocation
        .ancestors()
        .take_while(|node| node.kind().as_ref() != "function_definition")
        .find_map(|node| {
            (node.kind().as_ref() == "declaration" && default_unique_owner(node.text().as_ref()))
                .then(|| {
                    let local = declaration_local(&node)?;
                    Some(UniqueOwner {
                        family: unique_owner_family(node.text().as_ref()),
                        node,
                        local,
                    })
                })
                .flatten()
        })
}

fn raw_unique_transfer<'tree>(
    scope: &Node<'tree, StrDoc<SupportLang>>,
    raw: &str,
    after: usize,
) -> Option<UniqueOwner<'tree>> {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "declaration")
        .filter(|node| node.range().start > after)
        .filter(|node| default_unique_owner(node.text().as_ref()))
        .find_map(|node| {
            let text = compact(node.text().as_ref());
            ((text.contains(&format!("({raw})")) || text.contains(&format!("{{{raw}}}")))
                && !released_between(scope, raw, after, node.range().start))
            .then(|| {
                let local = declaration_local(&node)?;
                Some(UniqueOwner {
                    family: unique_owner_family(node.text().as_ref()),
                    node,
                    local,
                })
            })
            .flatten()
        })
}

fn declaration_local(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    node.children()
        .find_map(|child| {
            (child.kind().as_ref() == "init_declarator")
                .then(|| child.field("declarator"))
                .flatten()
        })
        .and_then(|declarator| declarator_identifier(&declarator))
        .or_else(|| {
            let value = compact(node.text().as_ref());
            let after_type = value.rsplit_once('>')?.1;
            let local = after_type.split(['(', '{']).next()?;
            simple_identifier(local).map(str::to_string)
        })
}

fn declarator_identifier(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let ids = node
        .dfs()
        .filter(|child| child.kind().as_ref() == "identifier")
        .collect::<Vec<_>>();
    ids.last().map(|id| id.text().trim().to_string())
}

fn unique_owner_family(text: &str) -> Family {
    let value = compact(text);
    if value
        .find("std::unique_ptr<")
        .and_then(|start| {
            value[start..]
                .find('>')
                .map(|end| &value[start..start + end])
        })
        .is_some_and(|kind| kind.contains("[]"))
    {
        Family::Array
    } else {
        Family::Scalar
    }
}

fn default_unique_owner(text: &str) -> bool {
    let value = compact(text);
    let Some(start) = value.find("std::unique_ptr<") else {
        return false;
    };
    let mut depth = 0_u32;
    for character in value[start + "std::unique_ptr".len()..].chars() {
        match character {
            '<' => depth += 1,
            '>' if depth == 1 => return true,
            '>' => depth = depth.saturating_sub(1),
            ',' if depth == 1 => return false,
            _ => {}
        }
    }
    false
}

fn is_make_unique(call: &Node<'_, StrDoc<SupportLang>>) -> bool {
    compact(call.text().as_ref()).starts_with("std::make_unique<")
}

fn make_unique_family(call: &Node<'_, StrDoc<SupportLang>>) -> Family {
    if compact(call.text().as_ref())
        .split('(')
        .next()
        .unwrap_or_default()
        .contains("[]>")
    {
        Family::Array
    } else {
        Family::Scalar
    }
}

fn delete_target(node: &Node<'_, StrDoc<SupportLang>>) -> Option<String> {
    let mut value = compact(node.text().as_ref());
    value = value.strip_prefix("delete")?.to_string();
    if let Some(rest) = value.strip_prefix("[]") {
        value = rest.to_string();
    }
    value = value.trim_end_matches(';').to_string();
    simple_identifier(&value).map(str::to_string)
}

fn delete_family(node: &Node<'_, StrDoc<SupportLang>>) -> Family {
    if compact(node.text().as_ref()).starts_with("delete[]") {
        Family::Array
    } else {
        Family::Scalar
    }
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

fn released_between(
    scope: &Node<'_, StrDoc<SupportLang>>,
    local: &str,
    start: usize,
    end: usize,
) -> bool {
    scope
        .dfs()
        .filter(|node| node.kind().as_ref() == "delete_expression")
        .filter(|node| start < node.range().start && node.range().end < end)
        .any(|node| delete_target(&node).as_deref() == Some(local))
}

#[allow(clippy::too_many_arguments)]
fn allocation_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    local: &str,
    family: Family,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    evidence_item(
        path,
        node,
        ALLOCATION_RULE_ID,
        EvidenceKind::Source,
        Capability::CppHeapAllocation,
        BTreeMap::from([
            ("local".to_string(), text_capture(path, node, local)),
            ("allocation".to_string(), capture(path, node)),
            (
                "allocation_family".to_string(),
                text_capture(path, node, family.label()),
            ),
        ]),
        vec!["native", "cpp-new-allocation"],
        comments,
        conditional,
        literals,
        Vec::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn delete_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    local: &str,
    family: Family,
    source: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    evidence_item(
        path,
        node,
        DELETE_RULE_ID,
        EvidenceKind::Sink,
        Capability::CppHeapDeallocation,
        BTreeMap::from([
            ("local".to_string(), text_capture(path, node, local)),
            ("release".to_string(), capture(path, node)),
            (
                "deallocation_family".to_string(),
                text_capture(path, node, family.label()),
            ),
        ]),
        vec!["native", "cpp-delete-release"],
        comments,
        conditional,
        literals,
        vec![source.id.clone()],
    )
}

#[allow(clippy::too_many_arguments)]
fn raii_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    local: &str,
    family: Family,
    source: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    evidence_item(
        path,
        node,
        RAII_RULE_ID,
        EvidenceKind::Sink,
        Capability::CppRaiiOwner,
        BTreeMap::from([
            ("owner".to_string(), text_capture(path, node, local)),
            ("owner_declaration".to_string(), capture(path, node)),
            (
                "owner_family".to_string(),
                text_capture(path, node, family.label()),
            ),
        ]),
        vec!["native", "standard-unique-owner"],
        comments,
        conditional,
        literals,
        vec![source.id.clone()],
    )
}

#[allow(clippy::too_many_arguments)]
fn transfer_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    local: &str,
    source: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    evidence_item(
        path,
        node,
        TRANSFER_RULE_ID,
        EvidenceKind::Validation,
        Capability::CppOwnershipTransfer,
        BTreeMap::from([
            ("raw_local".to_string(), text_capture(path, node, local)),
            ("transfer".to_string(), capture(path, node)),
        ]),
        vec!["native", "raw-to-unique-owner-transfer"],
        comments,
        conditional,
        literals,
        vec![source.id.clone()],
    )
}

#[allow(clippy::too_many_arguments)]
fn family_evidence<'tree>(
    path: &str,
    node: &Node<'tree, StrDoc<SupportLang>>,
    family: Family,
    sink: &Evidence,
    comments: &CommentRanges,
    conditional: &ConditionalRegions,
    literals: &LiteralEnvironment<'tree, StrDoc<SupportLang>>,
) -> Evidence {
    evidence_item(
        path,
        node,
        FAMILY_RULE_ID,
        EvidenceKind::Validation,
        Capability::CppAllocationFamilyValidation,
        BTreeMap::from([(
            "matched_family".to_string(),
            text_capture(path, node, family.label()),
        )]),
        vec!["native", "exact-scalar-array-family-match"],
        comments,
        conditional,
        literals,
        vec![sink.id.clone()],
    )
}

#[allow(clippy::too_many_arguments)]
fn evidence_item<'tree>(
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
        cwe_candidates: vec!["CWE-762".to_string()],
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

fn ownership_path(
    source: &Evidence,
    sink: &Evidence,
    validation: Option<&Evidence>,
    reason: &str,
) -> SecurityPath {
    let state = if validation.is_some() {
        SecurityPathState::Protected
    } else {
        SecurityPathState::Unknown
    };
    let mut steps = vec![step(SecurityPathStepKind::Source, source)];
    if let Some(item) = validation {
        steps.push(step(SecurityPathStepKind::Protection, item));
    }
    steps.push(step(SecurityPathStepKind::Sink, sink));
    SecurityPath {
        id: path_id(source, sink, state),
        source_evidence_id: source.id.clone(),
        sink_evidence_id: sink.id.clone(),
        capability: sink.capability,
        cwe_candidates: vec!["CWE-762".to_string()],
        state,
        steps,
        protection_evidence_ids: validation
            .map(|item| vec![item.id.clone()])
            .unwrap_or_default(),
        uncertainty_reasons: validation
            .is_none()
            .then(|| reason.replace(' ', "_"))
            .into_iter()
            .collect(),
        provenance: SecurityPathProvenance {
            engine: "mehscan c++ allocation-ownership relationship 1".to_string(),
            maximum_propagation_depth: 0,
        },
    }
}

fn ownership_transfer_path(
    source: &Evidence,
    transfer: &Evidence,
    sink: &Evidence,
    validation: Option<&Evidence>,
) -> SecurityPath {
    let mut path = ownership_path(
        source,
        sink,
        validation,
        "unique owner family differs from allocated new form",
    );
    path.steps
        .insert(1, step(SecurityPathStepKind::Assignment, transfer));
    path.id = path_id(source, sink, path.state);
    path
}

fn availability_compatible(
    source: &Node<'_, StrDoc<SupportLang>>,
    sink: &Node<'_, StrDoc<SupportLang>>,
    conditional: &ConditionalRegions,
) -> bool {
    let source = conditional.availability_for(source.range());
    let sink = conditional.availability_for(sink.range());
    match sink.state {
        AvailabilityState::Always => true,
        AvailabilityState::Conditional | AvailabilityState::Unknown => source == sink,
        AvailabilityState::Excluded => false,
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
fn path_id(source: &Evidence, sink: &Evidence, state: SecurityPathState) -> String {
    stable_id("path", &format!("{}\0{}\0{state:?}", source.id, sink.id))
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
fn compact(value: &str) -> String {
    value.chars().filter(|c| !c.is_whitespace()).collect()
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
fn excluded(item: &Evidence) -> bool {
    item.context
        .availability
        .as_ref()
        .is_some_and(|value| value.state == AvailabilityState::Excluded)
}
